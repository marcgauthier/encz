package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
	sqlite3 "github.com/mattn/go-sqlite3"
)

type runner struct {
	cfg       config
	log       *liveLogger
	ctx       context.Context
	cancel    context.CancelCauseFunc
	gate      sync.RWMutex
	db        *sqliteseal.DB
	oracle    *oracle
	stats     counters
	started   time.Time
	key       string
	keyIndex  int
	sequence  atomic.Int64
	workerWG  sync.WaitGroup
	failOnce  sync.Once
	maintDone chan struct{}
}

func newRunner(ctx context.Context, cancel context.CancelCauseFunc, cfg config, logger *liveLogger) *runner {
	return &runner{
		cfg:       cfg,
		log:       logger,
		ctx:       ctx,
		cancel:    cancel,
		oracle:    newOracle(),
		started:   time.Now(),
		key:       cfg.MasterKey,
		maintDone: make(chan struct{}),
	}
}

func (r *runner) openOptions(key string, cipher sqliteseal.Cipher) sqliteseal.Options {
	busy := int(r.cfg.BusyTimeoutValue / time.Millisecond)
	return sqliteseal.Options{
		Key:                        key,
		Cipher:                     cipher,
		JournalMode:                strings.ToUpper(r.cfg.JournalMode),
		BusyTimeoutMillis:          &busy,
		URIParameters:              map[string]string{"_foreign_keys": "on"},
		DecryptedPageCacheBytes:    r.cfg.CacheBytes,
		EnableReadPerformanceStats: true,
	}
}

func (r *runner) initialize() error {
	db, err := sqliteseal.OpenWithOptions(r.cfg.DBPath, r.openOptions(r.key, r.cfg.CipherValue))
	if err != nil {
		return fmt.Errorf("open main database: %w", err)
	}
	db.SetMaxOpenConns(r.cfg.Workers + 2)
	db.SetMaxIdleConns(r.cfg.Workers + 2)
	r.db = db

	for _, statement := range schemaDDL() {
		if _, err := r.db.ExecContext(r.ctx, statement); err != nil {
			return fmt.Errorf("schema statement failed: %w; sql=%s", err, statement)
		}
	}
	policy := sqliteseal.RotationPolicy{
		KEKRotationDays:  30,
		DEKRotationHours: 24,
		AutoRewrap:       true,
		KeepPreviousKey:  true,
	}
	if err := r.db.SetRotationPolicy(policy); err != nil {
		return fmt.Errorf("SetRotationPolicy: %w", err)
	}
	info, err := r.db.RotationStatus()
	if err != nil {
		return fmt.Errorf("RotationStatus: %w", err)
	}
	if !info.Exists || info.KEKRotationDays != policy.KEKRotationDays {
		return fmt.Errorf("RotationStatus returned unexpected policy: %+v", info)
	}
	if r.db.SQLDB() == nil {
		return errors.New("SQLDB returned nil")
	}
	return r.seed()
}

func (r *runner) seed() error {
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	base := time.Now().UTC()
	for generation := 1; generation <= r.cfg.InitialRowsPerTable; generation++ {
		for _, spec := range schema {
			id := r.oracle.allocateID(spec.Name)
			var parentID int64
			if spec.Parent != "" {
				parentIDs := r.oracle.ids(spec.Parent)
				parentID = parentIDs[(generation-1)%len(parentIDs)]
			}
			row := makeRecord(spec.Name, id, parentID, int64(generation), base.Add(time.Duration(id)*time.Nanosecond))
			if err := insertRecord(r.ctx, tx, spec.Name, row); err != nil {
				return fmt.Errorf("seed %s id=%d: %w", spec.Name, id, err)
			}
			r.oracle.add(spec.Name, row)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.stats.lastOracleRows.Store(int64(r.oracle.count()))
	return r.fullAudit(r.ctx, r.db.SQLDB())
}

func (r *runner) run() error {
	r.log.Info("workload start seed=%d workers=%d ops_per_second=%d rows_per_table=%d", r.cfg.Seed, r.cfg.Workers, r.cfg.OperationsPerSecond, r.cfg.RowsPerTable)
	tokens := make(chan struct{}, r.cfg.Workers*2)
	go r.rateLimiter(tokens)
	for id := 0; id < r.cfg.Workers; id++ {
		r.workerWG.Add(1)
		go r.worker(id, tokens)
	}
	go r.maintenance()

	progress := time.NewTicker(r.cfg.ProgressEvery)
	defer progress.Stop()
	for {
		select {
		case <-r.ctx.Done():
			r.workerWG.Wait()
			<-r.maintDone
			if cause := context.Cause(r.ctx); cause != nil && !errors.Is(cause, context.Canceled) {
				return cause
			}
			return nil
		case <-progress.C:
			r.refreshReadStats()
			r.log.Progress(r.stats.progress(r.started, r.cfg.DBPath))
		}
	}
}

func (r *runner) rateLimiter(tokens chan<- struct{}) {
	interval := time.Second / time.Duration(r.cfg.OperationsPerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(tokens)
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			select {
			case tokens <- struct{}{}:
			default:
			}
		}
	}
}

func (r *runner) worker(id int, tokens <-chan struct{}) {
	defer r.workerWG.Done()
	rnd := rand.New(rand.NewSource(r.cfg.Seed + int64(id+1)*1_000_003))
	for {
		select {
		case <-r.ctx.Done():
			return
		case _, ok := <-tokens:
			if !ok {
				return
			}
			if err := r.operation(id, rnd); err != nil {
				r.fail(fmt.Errorf("worker=%d seed=%d: %w", id, r.cfg.Seed, err))
				return
			}
		}
	}
}

func (r *runner) operation(workerID int, rnd *rand.Rand) error {
	choice := rnd.Intn(100)
	var err error
	switch {
	case choice < r.cfg.Workload.InsertPct:
		err = r.insertOne(workerID, rnd)
	case choice < r.cfg.Workload.InsertPct+r.cfg.Workload.UpdatePct:
		err = r.updateOne(workerID, rnd)
	case choice < r.cfg.Workload.InsertPct+r.cfg.Workload.UpdatePct+r.cfg.Workload.SelectPct:
		err = r.selectOne(workerID, rnd)
	default:
		err = r.joinOne(workerID, rnd)
	}
	return err
}

func (r *runner) fail(err error) {
	r.failOnce.Do(func() {
		r.stats.errors.Add(1)
		r.log.Error("%v", err)
		r.log.DumpHistory()
		r.cancel(err)
	})
}

func (r *runner) refreshReadStats() {
	r.gate.RLock()
	defer r.gate.RUnlock()
	if r.db == nil {
		return
	}
	stats := r.db.ReadPerformanceStats()
	r.stats.lastCacheHits.Store(stats.CacheHits)
	r.stats.lastCacheMiss.Store(stats.CacheMisses)
	r.stats.lastAEAD.Store(stats.AEADOpenCalls)
	r.stats.lastPhysical.Store(stats.PhysicalReads)
}

func (r *runner) close() error {
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.db == nil {
		return nil
	}
	err := r.db.Close()
	if second := r.db.Close(); second != nil && err == nil {
		err = fmt.Errorf("second Close: %w", second)
	}
	r.db = nil
	return err
}

func isBusy(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
}

func retryBusy(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isBusy(err) {
			return err
		}
		delay := time.Duration(attempt+1) * 10 * time.Millisecond
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("SQLITE_BUSY retry limit: %w", err)
}

func insertRecord(ctx context.Context, tx *sql.Tx, table string, row record) error {
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", quoteIdent(table), rowColumns, rowMarkers)
	_, err := tx.ExecContext(ctx, query, row.values()...)
	return err
}

func removeDBArtifacts(path string) error {
	for _, suffix := range []string{"", ".encz", ".encz.lock", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}
