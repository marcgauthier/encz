package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/marcgauthier/encz"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath = "test-encz-vs-sqlite/config.yaml"
	plainDriverName   = "sqlite3"
)

type config struct {
	EnczDBPath           string               `yaml:"encz_db_path"`
	SQLiteDBPath         string               `yaml:"sqlite_db_path"`
	EnczPassword         string               `yaml:"encz_password"`
	JournalMode          string               `yaml:"journal_mode"`
	MaxRunTime           string               `yaml:"max_run_time"`
	ActionInterval       string               `yaml:"action_interval"`
	CompareInterval      string               `yaml:"compare_interval"`
	ReopenInterval       string               `yaml:"reopen_interval"`
	SchemaChangeInterval string               `yaml:"schema_change_interval"`
	BackupInterval       string               `yaml:"backup_interval"`
	RekeyInterval        string               `yaml:"rekey_interval"`
	ComplexQueryInterval string               `yaml:"complex_query_interval"`
	LargeTxInterval      string               `yaml:"large_tx_interval"`
	MaxDBSize            string               `yaml:"max_db_size"`
	WorkerCount          int                  `yaml:"worker_count"`
	LogFile              string               `yaml:"log_file"`
	Seed                 int64                `yaml:"seed"`
	InvalidWritePct      int                  `yaml:"invalid_write_pct"`
	RotationPolicy       rotationPolicyConfig `yaml:"rotation_policy"`
	WorkloadMix          workloadMixConfig    `yaml:"workload_mix"`
}

type rotationPolicyConfig struct {
	KEKRotationDays int    `yaml:"kek_rotation_days"`
	DEKRotation     string `yaml:"dek_rotation"`
	AutoRewrap      bool   `yaml:"auto_rewrap"`
	KeepPreviousKey bool   `yaml:"keep_previous_key"`
}

type workloadMixConfig struct {
	SelectPct int `yaml:"select_pct"`
	InsertPct int `yaml:"insert_pct"`
	UpdatePct int `yaml:"update_pct"`
	DeletePct int `yaml:"delete_pct"`
}

type parsedConfig struct {
	config
	MaxRunDuration     time.Duration
	ActionEvery        time.Duration
	CompareEvery       time.Duration
	ReopenEvery        time.Duration
	SchemaChangeEvery  time.Duration
	BackupEvery        time.Duration
	RekeyEvery         time.Duration
	ComplexQueryEvery  time.Duration
	LargeTxEvery       time.Duration
	DEKRotationEvery   time.Duration
	RotationPolicy     encz.RotationPolicy
	PlainDSN           string
	DefaultConfigPath  string
	PhaseResumeMessage string
	MaxDBSizeBytes     int64
}

type dualLogger struct {
	mu           sync.Mutex
	out          io.Writer
	file         *os.File
	progress     bool
	history      []string
	historyIdx   int
	historyLimit int
}

func newDualLogger(logPath string) (*dualLogger, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &dualLogger{
		out:          os.Stdout,
		file:         f,
		history:      make([]string, 200),
		historyLimit: 200,
	}, nil
}

func (l *dualLogger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *dualLogger) Record(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [RECORD] %s\n", time.Now().Format(time.RFC3339), msg)
	l.history[l.historyIdx] = line
	l.historyIdx = (l.historyIdx + 1) % l.historyLimit
}

func (l *dualLogger) Progress(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.out, "\r"+msg)
	l.progress = true

	line := fmt.Sprintf("%s [PROGRESS] %s\n", time.Now().Format(time.RFC3339), msg)
	l.history[l.historyIdx] = line
	l.historyIdx = (l.historyIdx + 1) % l.historyLimit
}

func (l *dualLogger) clearProgressLocked() {
	if !l.progress {
		return
	}
	fmt.Fprint(l.out, "\r\033[2K")
	l.progress = false
}

func (l *dualLogger) log(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearProgressLocked()
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format(time.RFC3339), level, msg)
	_, _ = io.WriteString(l.out, line)
	_, _ = io.WriteString(l.file, line)

	l.history[l.historyIdx] = line
	l.historyIdx = (l.historyIdx + 1) % l.historyLimit
}

func (l *dualLogger) Info(format string, args ...any) {
	l.log("INFO", format, args...)
}

func (l *dualLogger) Error(format string, args ...any) {
	l.log("ERROR", format, args...)
}

func (l *dualLogger) Fatal(format string, args ...any) {
	l.log("FATAL", format, args...)

	l.mu.Lock()
	defer l.mu.Unlock()

	dumpHeader := fmt.Sprintf("\n=================== FATAL FAILURE: DUMPING LAST %d ACTIONS/LOGS ===================\n", l.historyLimit)
	_, _ = io.WriteString(l.out, dumpHeader)
	_, _ = io.WriteString(l.file, dumpHeader)

	start := l.historyIdx
	for i := 0; i < l.historyLimit; i++ {
		idx := (start + i) % l.historyLimit
		line := l.history[idx]
		if line != "" {
			if !strings.HasSuffix(line, "\n") {
				line += "\n"
			}
			_, _ = io.WriteString(l.out, line)
			_, _ = io.WriteString(l.file, line)
		}
	}

	dumpFooter := "===================================================================================\n"
	_, _ = io.WriteString(l.out, dumpFooter)
	_, _ = io.WriteString(l.file, dumpFooter)

	if l.file != nil {
		_ = l.file.Sync()
		_ = l.file.Close()
	}

	os.Exit(1)
}

type kind string

const (
	kindText      kind = "text"
	kindEmail     kind = "email"
	kindURL       kind = "url"
	kindIP        kind = "ip"
	kindUUID      kind = "uuid"
	kindDate      kind = "date"
	kindTimestamp kind = "timestamp"
	kindBool      kind = "bool"
	kindInt       kind = "int"
	kindReal      kind = "real"
	kindBlob      kind = "blob"
	kindEnum      kind = "enum"
	kindFK        kind = "fk"
)

type columnSpec struct {
	Name       string
	Kind       kind
	Nullable   bool
	Unique     bool
	RefTable   string
	Enum       []string
	MinLen     int
	MaxLen     int
	MinInt     int64
	MaxInt     int64
	MinFloat   float64
	MaxFloat   float64
	BlobBytes  int
	Indexed    bool
	Updatable  bool
	InvalidCap bool
}

type tableSpec struct {
	Name             string
	Columns          []columnSpec
	CompositeUniques [][]string
	Indexes          [][]string
	SeedRows         int
	AllowDelete      bool
	InsertSQL        string
	SelectByIDSQL    string
	UpdateableCols   []columnSpec
	AllColumnNames   []string
}

type dbState struct {
	mu     sync.RWMutex
	tables map[string]*tableRows
	specs  []*tableSpec
}

type tableRows struct {
	IDs  []int64
	Rows map[int64]map[string]any
}

func newDBState(tables []*tableSpec) *dbState {
	out := &dbState{
		tables: make(map[string]*tableRows, len(tables)),
		specs:  tables,
	}
	for _, table := range tables {
		out.tables[table.Name] = &tableRows{Rows: make(map[int64]map[string]any)}
	}
	return out
}

func cloneRow(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (s *dbState) AddRow(table string, id int64, row map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.tables[table]
	if _, ok := ts.Rows[id]; !ok {
		ts.IDs = append(ts.IDs, id)
	}
	ts.Rows[id] = cloneRow(row)
}

func (s *dbState) UpdateRow(table string, id int64, changes map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.tables[table]
	current, ok := ts.Rows[id]
	if !ok {
		return
	}
	for k, v := range changes {
		current[k] = v
	}
}

func (s *dbState) DeleteRow(table string, id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteRowLocked(table, id)
}

func (s *dbState) deleteRowLocked(tableName string, id int64) {
	ts := s.tables[tableName]
	if ts == nil {
		return
	}
	if _, exists := ts.Rows[id]; !exists {
		return
	}
	delete(ts.Rows, id)
	for i, v := range ts.IDs {
		if v == id {
			ts.IDs = append(ts.IDs[:i], ts.IDs[i+1:]...)
			break
		}
	}

	for _, spec := range s.specs {
		for _, col := range spec.Columns {
			if col.RefTable == tableName {
				childTable := s.tables[spec.Name]
				if childTable == nil {
					continue
				}
				var childIDsToDelete []int64
				for childID, row := range childTable.Rows {
					val, ok := row[col.Name]
					if ok {
						var valInt64 int64
						switch v := val.(type) {
						case int:
							valInt64 = int64(v)
						case int64:
							valInt64 = v
						case float64:
							valInt64 = int64(v)
						default:
							continue
						}
						if valInt64 == id {
							childIDsToDelete = append(childIDsToDelete, childID)
						}
					}
				}
				for _, childID := range childIDsToDelete {
					s.deleteRowLocked(spec.Name, childID)
				}
			}
		}
	}
}

func (s *dbState) RandomID(table string, rnd *rand.Rand) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts := s.tables[table]
	if len(ts.IDs) == 0 {
		return 0, false
	}
	return ts.IDs[rnd.Intn(len(ts.IDs))], true
}

func (s *dbState) RandomRow(table string, rnd *rand.Rand) (int64, map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts := s.tables[table]
	if len(ts.IDs) == 0 {
		return 0, nil, false
	}
	id := ts.IDs[rnd.Intn(len(ts.IDs))]
	return id, cloneRow(ts.Rows[id]), true
}

func (s *dbState) Count(table string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tables[table].IDs)
}

func (s *dbState) HasComposite(table string, cols []string, candidate map[string]any) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts := s.tables[table]
	for _, row := range ts.Rows {
		match := true
		for _, col := range cols {
			if normalizeValue(row[col]) != normalizeValue(candidate[col]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (s *dbState) HasValue(table, column string, candidate any) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, row := range s.tables[table].Rows {
		if normalizeValue(row[column]) == normalizeValue(candidate) {
			return true
		}
	}
	return false
}

type fakerSource struct {
	mu     sync.Mutex
	rng    *rand.Rand
	faker  *gofakeit.Faker
	unique int64
}

func newFakerSource(seed int64) *fakerSource {
	rng := rand.New(rand.NewSource(seed))
	return &fakerSource{
		rng:   rng,
		faker: gofakeit.New(uint64(seed)),
	}
}

func (f *fakerSource) WithLock(fn func(r *rand.Rand, fake *gofakeit.Faker) any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fn(f.rng, f.faker)
}

func (f *fakerSource) uniqueSuffix() string {
	return strconv.FormatInt(atomic.AddInt64(&f.unique, 1), 10)
}

type runner struct {
	cfg              parsedConfig
	logger           *dualLogger
	tables           []*tableSpec
	tableByName      map[string]*tableSpec
	state            *dbState
	fake             *fakerSource
	ctx              context.Context
	cancel           context.CancelFunc
	enczDB           *encz.DB
	sqliteDB         *sql.DB
	actionNo         atomic.Uint64
	paused           atomic.Bool
	phaseMu          sync.RWMutex
	sem              chan struct{}
	nextCompare      time.Time
	nextReopen       time.Time
	nextBackup       time.Time
	nextRekey        time.Time
	nextSchemaChange time.Time
	nextComplexQuery time.Time
	nextLargeTx      time.Time
	nextSizeCheck    time.Time
	runDeadline      time.Time
	shutdownOnce     sync.Once
	dynamicIndexes   map[string][]string
}

type compareQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func main() {
	configPath := defaultConfigPath
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else {
		if execPath, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(execPath), "config.yaml")
			if _, err := os.Stat(candidate); err == nil {
				configPath = candidate
			}
		}
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, err := newDualLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log error: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeoutCause(ctx, cfg.MaxRunDuration, errors.New("max_run_time reached"))
	defer cancel()

	r := &runner{
		cfg:              cfg,
		logger:           logger,
		tables:           buildTableSpecs(),
		tableByName:      make(map[string]*tableSpec),
		fake:             newFakerSource(cfg.Seed),
		ctx:              ctx,
		cancel:           cancel,
		sem:              make(chan struct{}, cfg.WorkerCount),
		nextCompare:      time.Now().Add(cfg.CompareEvery),
		nextReopen:       time.Now().Add(cfg.ReopenEvery),
		nextBackup:       time.Now().Add(cfg.BackupEvery),
		nextRekey:        time.Now().Add(cfg.RekeyEvery),
		nextSchemaChange: time.Now().Add(cfg.SchemaChangeEvery),
		nextComplexQuery: time.Now().Add(cfg.ComplexQueryEvery),
		nextLargeTx:      time.Now().Add(cfg.LargeTxEvery),
		nextSizeCheck:    time.Now().Add(5 * time.Minute),
		runDeadline:      time.Now().Add(cfg.MaxRunDuration),
		dynamicIndexes:   make(map[string][]string),
	}
	for _, table := range r.tables {
		r.tableByName[table.Name] = table
	}
	r.state = newDBState(r.tables)

	if err := r.openDatabases(); err != nil {
		logger.Error("open databases failed: %v", err)
		os.Exit(1)
	}
	defer r.closeDatabases()

	if err := r.initializeSchema(); err != nil {
		logger.Error("schema init failed: %v", err)
		os.Exit(1)
	}
	if err := r.seedInitialData(); err != nil {
		logger.Error("seed failed: %v", err)
		os.Exit(1)
	}
	if status, err := r.enczDB.RotationStatus(); err != nil {
		logger.Error("rotation status failed: %v", err)
	} else {
		logger.Info("ENCZ rotation status: KEK every %d days, DEK every %d hours, active DEK key id=%d", status.KEKRotationDays, status.DEKRotationHours, status.ActiveDEKKeyID)
	}

	logger.Info("runner started: action_interval=%s compare_interval=%s reopen_interval=%s schema_change_interval=%s complex_query_interval=%s large_tx_interval=%s max_db_size=%s max_run_time=%s workers=%d invalid_write_pct=%d", cfg.ActionEvery, cfg.CompareEvery, cfg.ReopenEvery, cfg.SchemaChangeEvery, cfg.ComplexQueryEvery, cfg.LargeTxEvery, cfg.MaxDBSize, cfg.MaxRunDuration, cfg.WorkerCount, cfg.InvalidWritePct)

	r.run()

	switch cause := context.Cause(ctx); {
	case cause != nil && cause.Error() == "max_run_time reached":
		logger.Info("shutdown: max_run_time reached")
	case ctx.Err() != nil:
		logger.Info("shutdown: signal received")
	default:
		logger.Info("shutdown: complete")
	}
}

func loadConfig(path string) (parsedConfig, error) {
	var raw config
	blob, err := os.ReadFile(path)
	if err != nil {
		return parsedConfig{}, err
	}
	if err := yaml.Unmarshal(blob, &raw); err != nil {
		return parsedConfig{}, err
	}

	parseDur := func(label, value string) (time.Duration, error) {
		if strings.TrimSpace(value) == "" {
			return 0, fmt.Errorf("%s is required", label)
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", label, err)
		}
		if d <= 0 {
			return 0, fmt.Errorf("%s must be greater than zero", label)
		}
		return d, nil
	}

	maxRun, err := parseDur("max_run_time", raw.MaxRunTime)
	if err != nil {
		return parsedConfig{}, err
	}
	actionEvery, err := parseDur("action_interval", raw.ActionInterval)
	if err != nil {
		return parsedConfig{}, err
	}
	compareEvery, err := parseDur("compare_interval", raw.CompareInterval)
	if err != nil {
		return parsedConfig{}, err
	}
	reopenEvery, err := parseDur("reopen_interval", raw.ReopenInterval)
	if err != nil {
		return parsedConfig{}, err
	}
	backupIntervalStr := raw.BackupInterval
	if backupIntervalStr == "" {
		backupIntervalStr = "90m"
	}
	backupEvery, err := parseDur("backup_interval", backupIntervalStr)
	if err != nil {
		return parsedConfig{}, err
	}
	rekeyIntervalStr := raw.RekeyInterval
	if rekeyIntervalStr == "" {
		rekeyIntervalStr = "45m"
	}
	rekeyEvery, err := parseDur("rekey_interval", rekeyIntervalStr)
	if err != nil {
		return parsedConfig{}, err
	}
	schemaChangeIntervalStr := raw.SchemaChangeInterval
	if schemaChangeIntervalStr == "" {
		schemaChangeIntervalStr = "1h"
	}
	schemaChangeEvery, err := parseDur("schema_change_interval", schemaChangeIntervalStr)
	if err != nil {
		return parsedConfig{}, err
	}
	complexQueryIntervalStr := raw.ComplexQueryInterval
	if complexQueryIntervalStr == "" {
		complexQueryIntervalStr = "60m"
	}
	complexQueryEvery, err := parseDur("complex_query_interval", complexQueryIntervalStr)
	if err != nil {
		return parsedConfig{}, err
	}
	largeTxIntervalStr := raw.LargeTxInterval
	if largeTxIntervalStr == "" {
		largeTxIntervalStr = "60m"
	}
	largeTxEvery, err := parseDur("large_tx_interval", largeTxIntervalStr)
	if err != nil {
		return parsedConfig{}, err
	}
	maxDBSizeStr := raw.MaxDBSize
	if maxDBSizeStr == "" {
		maxDBSizeStr = "1GB"
	}
	maxDBSizeBytes, err := parseSize(maxDBSizeStr)
	if err != nil {
		return parsedConfig{}, err
	}
	dekRotation, err := parseDur("rotation_policy.dek_rotation", raw.RotationPolicy.DEKRotation)
	if err != nil {
		return parsedConfig{}, err
	}
	if strings.TrimSpace(raw.EnczDBPath) == "" || strings.TrimSpace(raw.SQLiteDBPath) == "" {
		return parsedConfig{}, errors.New("encz_db_path and sqlite_db_path are required")
	}
	if strings.TrimSpace(raw.EnczPassword) == "" {
		return parsedConfig{}, errors.New("encz_password is required")
	}
	if strings.TrimSpace(raw.LogFile) == "" {
		return parsedConfig{}, errors.New("log_file is required")
	}
	if raw.WorkerCount < 1 {
		return parsedConfig{}, errors.New("worker_count must be >= 1")
	}
	if raw.InvalidWritePct < 0 || raw.InvalidWritePct > 100 {
		return parsedConfig{}, errors.New("invalid_write_pct must be between 0 and 100")
	}
	sum := raw.WorkloadMix.SelectPct + raw.WorkloadMix.InsertPct + raw.WorkloadMix.UpdatePct + raw.WorkloadMix.DeletePct
	if sum != 100 {
		return parsedConfig{}, fmt.Errorf("workload percentages must sum to 100, got %d", sum)
	}
	if raw.RotationPolicy.KEKRotationDays <= 0 {
		return parsedConfig{}, errors.New("rotation_policy.kek_rotation_days must be > 0")
	}
	if dekRotation%time.Hour != 0 {
		return parsedConfig{}, fmt.Errorf("rotation_policy.dek_rotation=%s is unsupported by current ENCZ API; only whole-hour DEK rotation is supported", dekRotation)
	}
	plainDSN := buildSQLiteDSN(raw.SQLiteDBPath, raw.JournalMode)
	return parsedConfig{
		config:            raw,
		MaxRunDuration:    maxRun,
		ActionEvery:       actionEvery,
		CompareEvery:      compareEvery,
		ReopenEvery:       reopenEvery,
		SchemaChangeEvery: schemaChangeEvery,
		BackupEvery:       backupEvery,
		RekeyEvery:        rekeyEvery,
		ComplexQueryEvery: complexQueryEvery,
		LargeTxEvery:      largeTxEvery,
		DEKRotationEvery:  dekRotation,
		RotationPolicy: encz.RotationPolicy{
			KEKRotationDays:  raw.RotationPolicy.KEKRotationDays,
			DEKRotationHours: int(dekRotation / time.Hour),
			AutoRewrap:       raw.RotationPolicy.AutoRewrap,
			KeepPreviousKey:  raw.RotationPolicy.KeepPreviousKey,
		},
		PlainDSN:          plainDSN,
		DefaultConfigPath: path,
		MaxDBSizeBytes:    maxDBSizeBytes,
	}, nil
}

func buildSQLiteDSN(path, journalMode string) string {
	values := url.Values{}
	values.Set("_foreign_keys", "on")
	if journalMode != "" {
		values.Set("_journal_mode", journalMode)
	}
	values.Set("_busy_timeout", "5000")
	return "file:" + filepath.ToSlash(path) + "?" + values.Encode()
}

func (r *runner) openDatabases() error {
	for _, p := range []string{
		r.cfg.EnczDBPath,
		r.cfg.EnczDBPath + "-wal",
		r.cfg.EnczDBPath + "-shm",
		r.cfg.EnczDBPath + ".encz",
		r.cfg.SQLiteDBPath,
		r.cfg.SQLiteDBPath + "-wal",
		r.cfg.SQLiteDBPath + "-shm",
	} {
		_ = os.Remove(p)
	}
	return r.connectDatabases()
}

func (r *runner) connectDatabases() error {
	if err := os.MkdirAll(filepath.Dir(r.cfg.EnczDBPath), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.cfg.SQLiteDBPath), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	plainDB, err := sql.Open(plainDriverName, r.cfg.PlainDSN)
	if err != nil {
		return err
	}
	plainDB.SetMaxOpenConns(r.cfg.WorkerCount + 2)
	plainDB.SetMaxIdleConns(r.cfg.WorkerCount + 2)
	if err := plainDB.PingContext(r.ctx); err != nil {
		_ = plainDB.Close()
		return err
	}

	opts := encz.Options{
		Key:         r.cfg.EnczPassword,
		JournalMode: r.cfg.JournalMode,
		URIParameters: map[string]string{
			"_foreign_keys": "on",
			"_busy_timeout": "5000",
		},
	}
	encDB, err := encz.OpenWithOptions(r.cfg.EnczDBPath, opts)
	if err != nil {
		_ = plainDB.Close()
		return err
	}
	encDB.SetMaxOpenConns(r.cfg.WorkerCount + 2)
	encDB.SetMaxIdleConns(r.cfg.WorkerCount + 2)
	if err := encDB.SetRotationPolicy(r.cfg.RotationPolicy); err != nil {
		_ = encDB.Close()
		_ = plainDB.Close()
		return err
	}
	r.sqliteDB = plainDB
	r.enczDB = encDB
	return nil
}

func (r *runner) closeDatabases() {
	r.shutdownOnce.Do(func() {
		if r.enczDB != nil {
			_ = r.enczDB.Close()
		}
		if r.sqliteDB != nil {
			_ = r.sqliteDB.Close()
		}
	})
}

func (r *runner) initializeSchema() error {
	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, `PRAGMA foreign_keys = ON`); err != nil {
			return fmt.Errorf("%s foreign_keys pragma: %w", db.name, err)
		}
		for _, table := range r.tables {
			for _, stmt := range tableDDL(table) {
				if _, err := db.conn.ExecContext(r.ctx, stmt); err != nil {
					return fmt.Errorf("%s create %s: %w", db.name, table.Name, err)
				}
			}
		}
	}
	return nil
}

func (r *runner) seedInitialData() error {
	for _, table := range r.tables {
		for i := 0; i < table.SeedRows; i++ {
			row, _, err := r.buildInsertRow(table, false)
			if err != nil {
				return fmt.Errorf("seed %s row: %w", table.Name, err)
			}
			if err := r.performInsert(table, row, false, 0); err != nil {
				return fmt.Errorf("seed %s insert: %w", table.Name, err)
			}
		}
	}
	return nil
}

func (r *runner) run() {
	actionTicker := time.NewTicker(r.cfg.ActionEvery)
	compareTicker := time.NewTicker(r.cfg.CompareEvery)
	reopenTicker := time.NewTicker(r.cfg.ReopenEvery)
	schemaChangeTicker := time.NewTicker(r.cfg.SchemaChangeEvery)
	backupTicker := time.NewTicker(r.cfg.BackupEvery)
	rekeyTicker := time.NewTicker(r.cfg.RekeyEvery)
	complexQueryTicker := time.NewTicker(r.cfg.ComplexQueryEvery)
	largeTxTicker := time.NewTicker(r.cfg.LargeTxEvery)
	sizeCheckTicker := time.NewTicker(5 * time.Minute)
	defer actionTicker.Stop()
	defer compareTicker.Stop()
	defer reopenTicker.Stop()
	defer schemaChangeTicker.Stop()
	defer backupTicker.Stop()
	defer rekeyTicker.Stop()
	defer complexQueryTicker.Stop()
	defer largeTxTicker.Stop()
	defer sizeCheckTicker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			r.waitForWorkers()
			return
		case <-actionTicker.C:
			r.tryScheduleAction()
		case <-compareTicker.C:
			r.nextCompare = time.Now().Add(r.cfg.CompareEvery)
			r.runPhase("integrity check", r.checkIntegrity)
		case <-reopenTicker.C:
			r.nextReopen = time.Now().Add(r.cfg.ReopenEvery)
			r.runPhase("close/reopen", r.reopenDatabases)
		case <-backupTicker.C:
			r.nextBackup = time.Now().Add(r.cfg.BackupEvery)
			r.runPhase("backup/restore validation", r.validateBackupRestore)
		case <-rekeyTicker.C:
			r.nextRekey = time.Now().Add(r.cfg.RekeyEvery)
			r.runPhase("rekey validation", r.validateRekey)
		case <-complexQueryTicker.C:
			r.nextComplexQuery = time.Now().Add(r.cfg.ComplexQueryEvery)
			r.runPhase("complex query validation", r.validateComplexQueries)
		case <-largeTxTicker.C:
			r.nextLargeTx = time.Now().Add(r.cfg.LargeTxEvery)
			r.runPhase("large transaction validation", r.validateLargeTransaction)
		case <-schemaChangeTicker.C:
			r.nextSchemaChange = time.Now().Add(r.cfg.SchemaChangeEvery)
			r.runPhase("schema change", func() error {
				if err := r.executeSchemaChange(); err != nil {
					return err
				}
				return r.compareSchemas()
			})
		case <-sizeCheckTicker.C:
			r.nextSizeCheck = time.Now().Add(5 * time.Minute)
			r.runPhase("database size check", r.checkDatabaseSize)
		}
	}
}

func (r *runner) tryScheduleAction() {
	if r.paused.Load() {
		return
	}
	select {
	case r.sem <- struct{}{}:
	default:
		r.logger.Error("action scheduler saturated; skipping scheduled action")
		return
	}
	go func() {
		defer func() { <-r.sem }()
		r.phaseMu.RLock()
		defer r.phaseMu.RUnlock()
		if r.ctx.Err() != nil {
			return
		}
		r.executeAction()
	}()
}

func (r *runner) executeAction() {
	actionNo := r.actionNo.Add(1)
	r.logger.Progress("action (%d)", actionNo)

	op := r.pickOperation()
	switch op {
	case "select":
		r.executeSelect(actionNo)
	case "insert":
		r.executeInsert(actionNo)
	case "update":
		r.executeUpdate(actionNo)
	case "delete":
		r.executeDelete(actionNo)
	}
}

func (r *runner) pickOperation() string {
	return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		n := rnd.Intn(100)
		if n < r.cfg.WorkloadMix.SelectPct {
			return "select"
		}
		n -= r.cfg.WorkloadMix.SelectPct
		if n < r.cfg.WorkloadMix.InsertPct {
			return "insert"
		}
		n -= r.cfg.WorkloadMix.InsertPct
		if n < r.cfg.WorkloadMix.UpdatePct {
			return "update"
		}
		return "delete"
	}).(string)
}

func (r *runner) shouldUseInvalidWrite() bool {
	if r.cfg.InvalidWritePct == 0 {
		return false
	}
	return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(100) < r.cfg.InvalidWritePct
	}).(bool)
}

func (r *runner) executeSelect(actionNo uint64) {
	table := r.randomTable(func(t *tableSpec) bool { return r.state.Count(t.Name) > 0 })
	if table == nil {
		return
	}
	id, ok := r.randomID(table.Name)
	if !ok {
		return
	}
	r.logger.Record("action=%d op=SELECT table=%s id=%d starting", actionNo, table.Name, id)
	sqliteRows, sqliteErr := queryRowsNormalized(r.ctx, r.sqliteDB, table.SelectByIDSQL, id)
	enczRows, enczErr := queryRowsNormalized(r.ctx, r.enczDB.SQLDB(), table.SelectByIDSQL, id)
	if sqliteErr != nil || enczErr != nil {
		if (sqliteErr == nil) != (enczErr == nil) {
			r.logger.Fatal("action=%d op=SELECT table=%s id=%d split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
		} else if sqliteErr.Error() != enczErr.Error() {
			r.logger.Fatal("action=%d op=SELECT table=%s id=%d error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
		} else {
			r.logger.Record("action=%d op=SELECT table=%s id=%d db=sqlite/encz match_error error=%v", actionNo, table.Name, id, sqliteErr)
		}
		return
	}
	if !reflect.DeepEqual(sqliteRows, enczRows) {
		r.logger.Fatal("action=%d op=SELECT table=%s id=%d mismatch sqlite=%v encz=%v", actionNo, table.Name, id, sqliteRows, enczRows)
	}
}

func (r *runner) executeInsert(actionNo uint64) {
	table := r.randomTable(func(t *tableSpec) bool { return true })
	if table == nil {
		return
	}
	invalid := r.shouldUseInvalidWrite()
	r.logger.Record("action=%d op=INSERT table=%s invalid=%t starting", actionNo, table.Name, invalid)
	row, reason, err := r.buildInsertRow(table, invalid)
	if err != nil {
		r.logger.Record("action=%d op=INSERT table=%s build error=%v", actionNo, table.Name, err)
		return
	}
	if err := r.performInsert(table, row, invalid, actionNo); err != nil {
		r.logger.Record("action=%d op=INSERT table=%s invalid=%t reason=%s error=%v", actionNo, table.Name, invalid, reason, err)
	}
}

func (r *runner) executeUpdate(actionNo uint64) {
	table := r.randomTable(func(t *tableSpec) bool {
		return len(t.UpdateableCols) > 0 && r.state.Count(t.Name) > 0
	})
	if table == nil {
		return
	}
	id, current, ok := r.randomRow(table.Name)
	if !ok {
		return
	}
	invalid := r.shouldUseInvalidWrite()
	r.logger.Record("action=%d op=UPDATE table=%s id=%d invalid=%t starting", actionNo, table.Name, id, invalid)
	changes, reason, err := r.buildUpdateChanges(table, id, current, invalid)
	if err != nil {
		r.logger.Record("action=%d op=UPDATE table=%s id=%d build error=%v", actionNo, table.Name, id, err)
		return
	}
	if err := r.performUpdate(table, id, changes, invalid, reason, actionNo); err != nil {
		r.logger.Record("action=%d op=UPDATE table=%s id=%d invalid=%t reason=%s error=%v", actionNo, table.Name, id, invalid, reason, err)
	}
}

func (r *runner) executeDelete(actionNo uint64) {
	table := r.randomTable(func(t *tableSpec) bool { return t.AllowDelete && r.state.Count(t.Name) > 0 })
	if table == nil {
		return
	}
	id, ok := r.randomID(table.Name)
	if !ok {
		return
	}
	r.logger.Record("action=%d op=DELETE table=%s id=%d starting", actionNo, table.Name, id)
	sqlText := fmt.Sprintf("DELETE FROM %s WHERE id = ?", table.Name)
	sqliteResult, sqliteErr := r.sqliteDB.ExecContext(r.ctx, sqlText, id)
	enczResult, enczErr := r.enczDB.ExecContext(r.ctx, sqlText, id)
	if sqliteErr != nil || enczErr != nil {
		if (sqliteErr == nil) != (enczErr == nil) {
			r.logger.Fatal("action=%d op=DELETE table=%s id=%d split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
		} else if sqliteErr.Error() != enczErr.Error() {
			r.logger.Fatal("action=%d op=DELETE table=%s id=%d error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
		} else {
			r.logger.Record("action=%d op=DELETE table=%s id=%d db=sqlite/encz match_error error=%v", actionNo, table.Name, id, sqliteErr)
		}
		return
	}
	sqliteRows, _ := sqliteResult.RowsAffected()
	enczRows, _ := enczResult.RowsAffected()
	if sqliteRows != enczRows {
		r.logger.Fatal("action=%d op=DELETE table=%s id=%d rows_affected mismatch sqlite=%d encz=%d", actionNo, table.Name, id, sqliteRows, enczRows)
	}
	if sqliteRows > 0 && enczRows > 0 {
		r.state.DeleteRow(table.Name, id)
	}
}

func (r *runner) performInsert(table *tableSpec, row map[string]any, invalid bool, actionNo uint64) error {
	args := valuesForColumns(table.Columns, row)
	sqliteResult, sqliteErr := r.sqliteDB.ExecContext(r.ctx, table.InsertSQL, args...)
	enczResult, enczErr := r.enczDB.ExecContext(r.ctx, table.InsertSQL, args...)

	if sqliteErr != nil || enczErr != nil {
		if (sqliteErr == nil) != (enczErr == nil) {
			r.logger.Fatal("action=%d op=INSERT table=%s split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, sqliteErr, enczErr)
			return errors.New("insert mismatch")
		}
		if sqliteErr.Error() != enczErr.Error() {
			r.logger.Fatal("action=%d op=INSERT table=%s error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, sqliteErr, enczErr)
			return errors.New("insert mismatch")
		}
		r.logger.Record("action=%d op=INSERT table=%s db=sqlite/encz match_error error=%v", actionNo, table.Name, sqliteErr)
		return nil
	}

	sqliteID, _ := sqliteResult.LastInsertId()
	enczID, _ := enczResult.LastInsertId()
	if sqliteID != enczID {
		r.logger.Fatal("action=%d op=INSERT table=%s last_insert_id mismatch sqlite=%d encz=%d", actionNo, table.Name, sqliteID, enczID)
		return errors.New("last_insert_id mismatch")
	}

	// Inline validation: select the inserted row back from both databases and verify they are identical
	sqliteRows, sqliteSelectErr := queryRowsNormalized(r.ctx, r.sqliteDB, table.SelectByIDSQL, sqliteID)
	enczRows, enczSelectErr := queryRowsNormalized(r.ctx, r.enczDB.SQLDB(), table.SelectByIDSQL, enczID)

	if sqliteSelectErr != nil || enczSelectErr != nil {
		if (sqliteSelectErr == nil) != (enczSelectErr == nil) {
			r.logger.Fatal("action=%d op=INSERT table=%s inline_verify split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, sqliteSelectErr, enczSelectErr)
			return errors.New("insert inline_verify mismatch")
		}
		if sqliteSelectErr.Error() != enczSelectErr.Error() {
			r.logger.Fatal("action=%d op=INSERT table=%s inline_verify error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, sqliteSelectErr, enczSelectErr)
			return errors.New("insert inline_verify mismatch")
		}
	} else if !reflect.DeepEqual(sqliteRows, enczRows) {
		r.logger.Fatal("action=%d op=INSERT table=%s inline_verify data mismatch sqlite=%v encz=%v", actionNo, table.Name, sqliteRows, enczRows)
		return errors.New("insert inline_verify data mismatch")
	}

	r.state.AddRow(table.Name, sqliteID, row)
	return nil
}

func (r *runner) performUpdate(table *tableSpec, id int64, changes map[string]any, invalid bool, reason string, actionNo uint64) error {
	cols := sortedKeys(changes)
	assignments := make([]string, 0, len(cols))
	args := make([]any, 0, len(cols)+1)
	for _, col := range cols {
		assignments = append(assignments, col+" = ?")
		args = append(args, changes[col])
	}
	args = append(args, id)
	sqlText := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table.Name, strings.Join(assignments, ", "))
	sqliteResult, sqliteErr := r.sqliteDB.ExecContext(r.ctx, sqlText, args...)
	enczResult, enczErr := r.enczDB.ExecContext(r.ctx, sqlText, args...)

	if sqliteErr != nil || enczErr != nil {
		if (sqliteErr == nil) != (enczErr == nil) {
			r.logger.Fatal("action=%d op=UPDATE table=%s id=%d split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
			return errors.New("update mismatch")
		}
		if sqliteErr.Error() != enczErr.Error() {
			r.logger.Fatal("action=%d op=UPDATE table=%s id=%d error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteErr, enczErr)
			return errors.New("update mismatch")
		}
		r.logger.Record("action=%d op=UPDATE table=%s id=%d db=sqlite/encz match_error error=%v", actionNo, table.Name, id, sqliteErr)
		return nil
	}
	sqliteRows, _ := sqliteResult.RowsAffected()
	enczRows, _ := enczResult.RowsAffected()
	if sqliteRows != enczRows {
		r.logger.Fatal("action=%d op=UPDATE table=%s id=%d rows_affected mismatch sqlite=%d encz=%d", actionNo, table.Name, id, sqliteRows, enczRows)
	}

	// Inline validation: select the updated row back from both databases and verify they are identical
	sqliteRowsSelect, sqliteSelectErr := queryRowsNormalized(r.ctx, r.sqliteDB, table.SelectByIDSQL, id)
	enczRowsSelect, enczSelectErr := queryRowsNormalized(r.ctx, r.enczDB.SQLDB(), table.SelectByIDSQL, id)

	if sqliteSelectErr != nil || enczSelectErr != nil {
		if (sqliteSelectErr == nil) != (enczSelectErr == nil) {
			r.logger.Fatal("action=%d op=UPDATE table=%s id=%d inline_verify split_outcome sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteSelectErr, enczSelectErr)
			return errors.New("update inline_verify mismatch")
		}
		if sqliteSelectErr.Error() != enczSelectErr.Error() {
			r.logger.Fatal("action=%d op=UPDATE table=%s id=%d inline_verify error_outcome mismatch sqlite_err=%v encz_err=%v", actionNo, table.Name, id, sqliteSelectErr, enczSelectErr)
			return errors.New("update inline_verify mismatch")
		}
	} else if !reflect.DeepEqual(sqliteRowsSelect, enczRowsSelect) {
		r.logger.Fatal("action=%d op=UPDATE table=%s id=%d inline_verify data mismatch sqlite=%v encz=%v", actionNo, table.Name, sqliteRowsSelect, enczRowsSelect)
		return errors.New("update inline_verify data mismatch")
	}

	if sqliteRows > 0 && enczRows > 0 {
		r.state.UpdateRow(table.Name, id, changes)
	}
	return nil
}

func (r *runner) runPhase(name string, fn func() error) {
	r.paused.Store(true)
	r.waitForWorkers()
	r.phaseMu.Lock()
	defer func() {
		r.phaseMu.Unlock()
		r.paused.Store(false)
		r.logger.Info("starting actions for the next %s", r.nextPauseWindow())
	}()
	r.logger.Info("starting %s between sqlite and encz", name)
	if err := fn(); err != nil {
		r.logger.Fatal("%s failed: %v", name, err)
	} else {
		r.logger.Info("%s complete", name)
	}
}

func (r *runner) waitForWorkers() {
	for len(r.sem) > 0 {
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *runner) compareSchemas() error {
	schemaQuery := "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
	sqliteSchema, sqliteSchemaErr := querySchema(r.ctx, r.sqliteDB, schemaQuery)
	enczSchema, enczSchemaErr := querySchema(r.ctx, r.enczDB.SQLDB(), schemaQuery)

	if sqliteSchemaErr != nil || enczSchemaErr != nil {
		if sqliteSchemaErr != nil {
			r.logger.Fatal("compare schema db=sqlite error=%v", sqliteSchemaErr)
		}
		if enczSchemaErr != nil {
			r.logger.Fatal("compare schema db=encz error=%v", enczSchemaErr)
		}
		return errors.New("failed to query database schema")
	}

	if !reflect.DeepEqual(sqliteSchema, enczSchema) {
		r.logger.Fatal("database schema mismatch! sqlite=%v encz=%v", sqliteSchema, enczSchema)
		return errors.New("schema mismatch")
	}
	r.logger.Record("compare schemas success: identical schemas")
	return nil
}

func (r *runner) checkIntegrity() error {
	var sqliteResult, enczResult string
	sqliteErr := r.sqliteDB.QueryRowContext(r.ctx, "PRAGMA integrity_check").Scan(&sqliteResult)
	enczErr := r.enczDB.QueryRowContext(r.ctx, "PRAGMA integrity_check").Scan(&enczResult)

	if sqliteErr != nil {
		r.logger.Fatal("integrity check sqlite query failed: %v", sqliteErr)
		return sqliteErr
	}
	if enczErr != nil {
		r.logger.Fatal("integrity check encz query failed: %v", enczErr)
		return enczErr
	}

	if sqliteResult != "ok" || enczResult != "ok" {
		r.logger.Fatal("integrity check failed! sqlite=%s encz=%s", sqliteResult, enczResult)
		return fmt.Errorf("integrity check failed: sqlite=%s encz=%s", sqliteResult, enczResult)
	}
	r.logger.Record("database integrity check success")
	return nil
}

func (r *runner) compareDatabases() error {
	if err := r.compareSchemas(); err != nil {
		return err
	}
	return r.checkIntegrity()
}

func (r *runner) reopenDatabases() error {
	r.logger.Info("closing databases")
	if err := r.enczDB.Close(); err != nil {
		r.logger.Error("reopen close encz error=%v", err)
	}
	if err := r.sqliteDB.Close(); err != nil {
		r.logger.Error("reopen close sqlite error=%v", err)
	}
	r.shutdownOnce = sync.Once{}
	if err := r.connectDatabases(); err != nil {
		return err
	}
	r.logger.Info("reopened databases")
	return nil
}

func (r *runner) validateBackupRestore() error {
	backupZipPath := filepath.Join(filepath.Dir(r.cfg.EnczDBPath), "temp_backup.zip")
	_ = os.Remove(backupZipPath)

	// 1. Create backup
	opts := encz.BackupOptions{
		Compression: encz.BackupCompressionDeflate,
	}
	r.logger.Record("creating database backup to %s", backupZipPath)
	if err := r.enczDB.Backup(backupZipPath, opts); err != nil {
		r.logger.Fatal("backup failed: %v", err)
		return err
	}

	// 2. Close active connections to release file locks
	r.logger.Record("closing databases for restore validation")
	if err := r.enczDB.Close(); err != nil {
		r.logger.Error("close encz db failed: %v", err)
	}

	// 3. Delete original database, manifest, WAL and SHM files
	r.logger.Record("deleting original database and manifest files")
	_ = os.Remove(r.cfg.EnczDBPath)
	_ = os.Remove(r.cfg.EnczDBPath + ".encz")
	_ = os.Remove(r.cfg.EnczDBPath + "-wal")
	_ = os.Remove(r.cfg.EnczDBPath + "-shm")

	// 4. Restore database from backup zip
	restoreDir := filepath.Dir(r.cfg.EnczDBPath)
	r.logger.Record("restoring database from %s to %s", backupZipPath, restoreDir)
	if err := encz.RestoreBackup(backupZipPath, r.cfg.EnczPassword, restoreDir, true); err != nil {
		r.logger.Fatal("restore backup failed: %v", err)
		return err
	}

	// Clean up zip archive
	_ = os.Remove(backupZipPath)

	// Rename restored files to original database name
	restoredDBPath := filepath.Join(restoreDir, "temp_backup.bak")
	restoredManifestPath := filepath.Join(restoreDir, "temp_backup.bak.encz")

	if err := os.Rename(restoredDBPath, r.cfg.EnczDBPath); err != nil {
		r.logger.Fatal("failed to rename restored DB file: %v", err)
		return err
	}
	if err := os.Rename(restoredManifestPath, r.cfg.EnczDBPath+".encz"); err != nil {
		r.logger.Fatal("failed to rename restored manifest file: %v", err)
		return err
	}

	// 5. Re-establish connections
	r.logger.Record("reconnecting to databases after restore")
	r.shutdownOnce = sync.Once{}
	if err := r.connectDatabases(); err != nil {
		r.logger.Fatal("failed to reconnect databases after restore: %v", err)
		return err
	}

	// 6. Compare restored database against SQLite
	r.logger.Record("comparing restored database vs sqlite")
	if err := r.compareDatabases(); err != nil {
		r.logger.Fatal("database comparison failed after restore: %v", err)
		return err
	}

	r.logger.Info("backup/restore validation completed successfully")
	return nil
}

func (r *runner) validateRekey() error {
	newPassword := fmt.Sprintf("NewPassword-%s", r.fake.uniqueSuffix())
	oldPassword := r.cfg.EnczPassword

	r.logger.Record("rekeying database from %s to %s", oldPassword, newPassword)
	if err := r.enczDB.ReKey(oldPassword, newPassword); err != nil {
		r.logger.Fatal("rekey failed: %v", err)
		return err
	}

	// Update password in config for subsequent reopens
	r.cfg.EnczPassword = newPassword

	// Reopen database connections to verify they unlock successfully using the new key
	r.logger.Record("reopening databases to verify new key")
	if err := r.reopenDatabases(); err != nil {
		r.logger.Fatal("failed to reopen databases after rekey: %v", err)
		return err
	}

	// Compare databases to assert data remains identical and readable
	r.logger.Record("comparing databases after rekey")
	if err := r.compareDatabases(); err != nil {
		r.logger.Fatal("database comparison failed after rekey: %v", err)
		return err
	}

	r.logger.Info("rekey validation completed successfully")
	return nil
}

func (r *runner) validateComplexQueries() error {
	// Helper to execute identical DDL/DML on both databases
	execBoth := func(stmt string) error {
		if _, err := r.sqliteDB.ExecContext(r.ctx, stmt); err != nil {
			return fmt.Errorf("sqlite failed to exec statement %q: %w", stmt, err)
		}
		if _, err := r.enczDB.ExecContext(r.ctx, stmt); err != nil {
			return fmt.Errorf("encz failed to exec statement %q: %w", stmt, err)
		}
		return nil
	}

	// Helper to compare query results from both databases
	compareRows := func(query string, args ...any) error {
		sqliteRows, err := r.sqliteDB.QueryContext(r.ctx, query, args...)
		if err != nil {
			return fmt.Errorf("sqlite query failed: %w", err)
		}
		defer sqliteRows.Close()

		enczRows, err := r.enczDB.QueryContext(r.ctx, query, args...)
		if err != nil {
			return fmt.Errorf("encz query failed: %w", err)
		}
		defer enczRows.Close()

		sqliteCols, err := sqliteRows.Columns()
		if err != nil {
			return err
		}
		enczCols, err := enczRows.Columns()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(sqliteCols, enczCols) {
			return fmt.Errorf("column names mismatch: sqlite=%v, encz=%v", sqliteCols, enczCols)
		}

		var sqliteResults [][]any
		for sqliteRows.Next() {
			vals := make([]any, len(sqliteCols))
			valPtrs := make([]any, len(sqliteCols))
			for i := range vals {
				valPtrs[i] = &vals[i]
			}
			if err := sqliteRows.Scan(valPtrs...); err != nil {
				return err
			}
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			sqliteResults = append(sqliteResults, vals)
		}

		var enczResults [][]any
		for enczRows.Next() {
			vals := make([]any, len(enczCols))
			valPtrs := make([]any, len(enczCols))
			for i := range vals {
				valPtrs[i] = &vals[i]
			}
			if err := enczRows.Scan(valPtrs...); err != nil {
				return err
			}
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			enczResults = append(enczResults, vals)
		}

		if len(sqliteResults) != len(enczResults) {
			return fmt.Errorf("result row count mismatch: sqlite=%d, encz=%d", len(sqliteResults), len(enczResults))
		}

		for i := range sqliteResults {
			for j := range sqliteResults[i] {
				sVal := sqliteResults[i][j]
				eVal := enczResults[i][j]
				sf, okS := sVal.(float64)
				ef, okE := eVal.(float64)
				if okS && okE {
					if math.Abs(sf-ef) > 1e-9 {
						return fmt.Errorf("float value mismatch at row %d, col %s: sqlite=%v, encz=%v", i, sqliteCols[j], sVal, eVal)
					}
				} else {
					if !reflect.DeepEqual(sVal, eVal) {
						return fmt.Errorf("value mismatch at row %d, col %s: sqlite=%v (%T), encz=%v (%T)", i, sqliteCols[j], sVal, sVal, eVal, eVal)
					}
				}
			}
		}
		return nil
	}

	// 1. Complex Joins
	r.logger.Record("complex queries: running complex joins test")
	stmts1 := []string{
		`CREATE TABLE cx_suppliers (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			country TEXT NOT NULL
		)`,
		`CREATE TABLE cx_products (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			price REAL NOT NULL,
			supplier_id INTEGER,
			FOREIGN KEY(supplier_id) REFERENCES cx_suppliers(id)
		)`,
		`CREATE TABLE cx_customers (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		)`,
		`CREATE TABLE cx_orders (
			id INTEGER PRIMARY KEY,
			customer_id INTEGER,
			order_date TEXT NOT NULL,
			FOREIGN KEY(customer_id) REFERENCES cx_customers(id)
		)`,
		`CREATE TABLE cx_order_items (
			id INTEGER PRIMARY KEY,
			order_id INTEGER,
			product_id INTEGER,
			quantity INTEGER NOT NULL,
			FOREIGN KEY(order_id) REFERENCES cx_orders(id),
			FOREIGN KEY(product_id) REFERENCES cx_products(id)
		)`,
		`INSERT INTO cx_suppliers VALUES (1, "Supplier A", "Canada"), (2, "Supplier B", "USA")`,
		`INSERT INTO cx_products VALUES (10, "Laptop", 999.99, 1), (20, "Mouse", 25.50, 1), (30, "Keyboard", 75.00, 2)`,
		`INSERT INTO cx_customers VALUES (100, "Alice"), (200, "Bob"), (300, "Charlie")`,
		`INSERT INTO cx_orders VALUES (1000, 100, "2026-06-01"), (2000, 200, "2026-06-02"), (3000, 100, "2026-06-03")`,
		`INSERT INTO cx_order_items VALUES (5000, 1000, 10, 1), (5001, 1000, 20, 2), (5002, 2000, 30, 1), (5003, 3000, 20, 5)`,
	}
	for _, s := range stmts1 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	joinQuery := `
		SELECT 
			c.name AS customer_name,
			o.order_date,
			p.name AS product_name,
			p.price,
			oi.quantity,
			(p.price * oi.quantity) AS item_total,
			s.name AS supplier_name,
			s.country AS supplier_country
		FROM cx_customers c
		INNER JOIN cx_orders o ON c.id = o.customer_id
		INNER JOIN cx_order_items oi ON o.id = oi.order_id
		INNER JOIN cx_products p ON oi.product_id = p.id
		INNER JOIN cx_suppliers s ON p.supplier_id = s.id
		ORDER BY o.order_date ASC, p.name DESC
	`
	if err := compareRows(joinQuery); err != nil {
		return fmt.Errorf("complex joins comparison failed: %w", err)
	}

	// Clean up Joins tables
	drops1 := []string{
		`DROP TABLE cx_order_items`,
		`DROP TABLE cx_orders`,
		`DROP TABLE cx_customers`,
		`DROP TABLE cx_products`,
		`DROP TABLE cx_suppliers`,
	}
	for _, s := range drops1 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	// 2. CTEs (Recursive & Standard)
	r.logger.Record("complex queries: running CTEs test")
	stmts2 := []string{
		`CREATE TABLE cx_employees (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			manager_id INTEGER REFERENCES cx_employees(id)
		)`,
		`INSERT INTO cx_employees VALUES
			(1, "CEO", NULL),
			(2, "VP Engineering", 1),
			(3, "VP Sales", 1),
			(4, "Engineering Manager", 2),
			(5, "Software Engineer A", 4),
			(6, "Software Engineer B", 4),
			(7, "Sales Rep", 3)`,
	}
	for _, s := range stmts2 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	cteQuery := `
		WITH RECURSIVE org_chart AS (
			SELECT id, name, manager_id, 0 AS level
			FROM cx_employees
			WHERE manager_id IS NULL
			
			UNION ALL
			
			SELECT e.id, e.name, e.manager_id, o.level + 1
			FROM cx_employees e
			INNER JOIN org_chart o ON e.manager_id = o.id
		)
		SELECT id, name, level FROM org_chart ORDER BY level, id
	`
	if err := compareRows(cteQuery); err != nil {
		return fmt.Errorf("CTEs comparison failed: %w", err)
	}

	if err := execBoth(`DROP TABLE cx_employees`); err != nil {
		return err
	}

	// 3. Subqueries & EXISTS
	r.logger.Record("complex queries: running subqueries and EXISTS test")
	stmts3 := []string{
		`CREATE TABLE cx_products (
			id INTEGER PRIMARY KEY,
			name TEXT,
			price REAL,
			category TEXT
		)`,
		`INSERT INTO cx_products VALUES
			(1, "Laptop", 1200.0, "Electronics"),
			(2, "Phone", 800.0, "Electronics"),
			(3, "Mouse", 30.0, "Electronics"),
			(4, "Desk", 250.0, "Furniture"),
			(5, "Chair", 120.0, "Furniture")`,
	}
	for _, s := range stmts3 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	subQuery1 := `
		SELECT name FROM cx_products p1
		WHERE price > (
			SELECT AVG(price) FROM cx_products p2 WHERE p2.category = p1.category
		)
		ORDER BY id
	`
	if err := compareRows(subQuery1); err != nil {
		return fmt.Errorf("correlated subquery comparison failed: %w", err)
	}

	stmts3b := []string{
		`CREATE TABLE cx_orders (
			id INTEGER PRIMARY KEY,
			product_id INTEGER
		)`,
		`INSERT INTO cx_orders VALUES (1, 1), (2, 3)`,
	}
	for _, s := range stmts3b {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	subQuery2 := `
		SELECT name FROM cx_products p
		WHERE EXISTS (SELECT 1 FROM cx_orders o WHERE o.product_id = p.id)
		ORDER BY p.id
	`
	if err := compareRows(subQuery2); err != nil {
		return fmt.Errorf("EXISTS subquery comparison failed: %w", err)
	}

	drops3 := []string{
		`DROP TABLE cx_orders`,
		`DROP TABLE cx_products`,
	}
	for _, s := range drops3 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	// 4. Window Functions
	r.logger.Record("complex queries: running window functions test")
	stmts4 := []string{
		`CREATE TABLE cx_scores (
			department TEXT,
			employee TEXT,
			score INTEGER
		)`,
		`INSERT INTO cx_scores VALUES
			("Sales", "Alice", 100),
			("Sales", "Bob", 120),
			("Eng", "Charlie", 150),
			("Eng", "Dave", 110),
			("Eng", "Eve", 150)`,
	}
	for _, s := range stmts4 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	windowQuery := `
		SELECT 
			department, 
			employee, 
			score,
			ROW_NUMBER() OVER (PARTITION BY department ORDER BY score DESC, employee ASC) as row_num,
			DENSE_RANK() OVER (PARTITION BY department ORDER BY score DESC) as rank
		FROM cx_scores
		ORDER BY department, rank, row_num
	`
	if err := compareRows(windowQuery); err != nil {
		return fmt.Errorf("window functions comparison failed: %w", err)
	}

	if err := execBoth(`DROP TABLE cx_scores`); err != nil {
		return err
	}

	// 5. Triggers and Views
	r.logger.Record("complex queries: running triggers and views test")
	stmts5 := []string{
		`CREATE TABLE cx_users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL
		)`,
		`CREATE TABLE cx_user_logs (
			user_id INTEGER,
			action TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE VIEW cx_v_active_users AS SELECT id, username FROM cx_users`,
		`CREATE TRIGGER cx_trg_user_insert AFTER INSERT ON cx_users
			BEGIN
				INSERT INTO cx_user_logs (user_id, action) VALUES (new.id, 'INSERT');
			END;`,
		`INSERT INTO cx_users (id, username) VALUES (1, "marc")`,
	}
	for _, s := range stmts5 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	if err := compareRows(`SELECT username FROM cx_v_active_users WHERE id = 1`); err != nil {
		return fmt.Errorf("trigger/view active users comparison failed: %w", err)
	}
	if err := compareRows(`SELECT action FROM cx_user_logs WHERE user_id = 1`); err != nil {
		return fmt.Errorf("trigger log action comparison failed: %w", err)
	}

	drops5 := []string{
		`DROP TRIGGER cx_trg_user_insert`,
		`DROP VIEW cx_v_active_users`,
		`DROP TABLE cx_user_logs`,
		`DROP TABLE cx_users`,
	}
	for _, s := range drops5 {
		if err := execBoth(s); err != nil {
			return err
		}
	}

	// 6. Full-Text Search FTS5
	r.logger.Record("complex queries: running FTS5 test")
	_, err1 := r.sqliteDB.ExecContext(r.ctx, `CREATE VIRTUAL TABLE cx_documents USING fts5(title, body)`)
	_, err2 := r.enczDB.ExecContext(r.ctx, `CREATE VIRTUAL TABLE cx_documents USING fts5(title, body)`)
	if err1 != nil || err2 != nil {
		r.logger.Info("skipping FTS5 validation (FTS5 not supported in this environment): sqlite_err=%v, encz_err=%v", err1, err2)
		if err1 == nil {
			r.sqliteDB.ExecContext(r.ctx, `DROP TABLE IF EXISTS cx_documents`)
		}
		if err2 == nil {
			r.enczDB.ExecContext(r.ctx, `DROP TABLE IF EXISTS cx_documents`)
		}
	} else {
		// Populate and compare FTS5
		stmts6 := []string{
			`INSERT INTO cx_documents (title, body) VALUES
				("Introduction to Go Programming", "Go is a statically typed programming language developed at Google. It is highly efficient."),
				("SQLite VFS transparent encryption", "The encz library registers a custom Virtual File System (VFS) to provide transparent database encryption.")`,
		}
		for _, s := range stmts6 {
			if err := execBoth(s); err != nil {
				return err
			}
		}

		if err := compareRows(`SELECT title FROM cx_documents WHERE cx_documents MATCH 'encryption'`); err != nil {
			return fmt.Errorf("FTS5 match 'encryption' comparison failed: %w", err)
		}
		if err := compareRows(`SELECT title FROM cx_documents WHERE cx_documents MATCH 'google'`); err != nil {
			return fmt.Errorf("FTS5 match 'google' comparison failed: %w", err)
		}

		if err := execBoth(`DROP TABLE cx_documents`); err != nil {
			return err
		}
	}

	r.logger.Info("complex SQL validation completed successfully")
	return nil
}

func (r *runner) validateLargeTransaction() error {
	const (
		rowCount    = 15000
		payloadSize = 3500
	)

	tableName := fmt.Sprintf("large_tx_validation_%s", strings.ReplaceAll(r.fake.uniqueSuffix(), "-", ""))
	createSQL := fmt.Sprintf("CREATE TABLE %s (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)", tableName)
	dropSQL := fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)
	insertSQL := fmt.Sprintf("INSERT INTO %s (payload) VALUES (?)", tableName)
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)

	cleanup := func() error {
		if _, err := r.sqliteDB.ExecContext(r.ctx, dropSQL); err != nil {
			return fmt.Errorf("sqlite cleanup: %w", err)
		}
		if _, err := r.enczDB.ExecContext(r.ctx, dropSQL); err != nil {
			return fmt.Errorf("encz cleanup: %w", err)
		}
		return nil
	}

	if err := cleanup(); err != nil {
		return err
	}
	defer func() {
		if err := cleanup(); err != nil {
			r.logger.Error("large transaction cleanup failed: %v", err)
		}
	}()

	payload := make([]byte, payloadSize)
	r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		for i := range payload {
			payload[i] = byte(rnd.Intn(256))
		}
		return nil
	})

	execTx := func(label string, db *sql.DB) error {
		if _, err := db.ExecContext(r.ctx, createSQL); err != nil {
			return fmt.Errorf("%s create table: %w", label, err)
		}

		tx, err := db.BeginTx(r.ctx, nil)
		if err != nil {
			return fmt.Errorf("%s begin: %w", label, err)
		}

		stmt, err := tx.PrepareContext(r.ctx, insertSQL)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s prepare: %w", label, err)
		}

		for i := 0; i < rowCount; i++ {
			if _, err := stmt.ExecContext(r.ctx, payload); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return fmt.Errorf("%s insert %d: %w", label, i, err)
			}
		}
		if err := stmt.Close(); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s close stmt: %w", label, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%s commit: %w", label, err)
		}
		return nil
	}

	r.logger.Record("large transaction: inserting %d rows with %d-byte payload into %s", rowCount, payloadSize, tableName)
	if err := execTx("sqlite", r.sqliteDB); err != nil {
		return err
	}
	if err := execTx("encz", r.enczDB.SQLDB()); err != nil {
		return err
	}

	var sqliteCount, enczCount int
	if err := r.sqliteDB.QueryRowContext(r.ctx, countSQL).Scan(&sqliteCount); err != nil {
		return fmt.Errorf("sqlite count: %w", err)
	}
	if err := r.enczDB.QueryRowContext(r.ctx, countSQL).Scan(&enczCount); err != nil {
		return fmt.Errorf("encz count: %w", err)
	}
	if sqliteCount != rowCount || enczCount != rowCount {
		return fmt.Errorf("large transaction row count mismatch: sqlite=%d encz=%d expected=%d", sqliteCount, enczCount, rowCount)
	}

	r.logger.Record("large transaction: row counts matched at %d", rowCount)
	if err := r.checkIntegrity(); err != nil {
		return err
	}
	r.logger.Info("large transaction validation completed successfully")
	return nil
}

func (r *runner) nextPauseWindow() time.Duration {
	candidates := []time.Time{r.runDeadline}
	if !r.nextCompare.IsZero() {
		candidates = append(candidates, r.nextCompare)
	}
	if !r.nextReopen.IsZero() {
		candidates = append(candidates, r.nextReopen)
	}
	if !r.nextBackup.IsZero() {
		candidates = append(candidates, r.nextBackup)
	}
	if !r.nextRekey.IsZero() {
		candidates = append(candidates, r.nextRekey)
	}
	if !r.nextSchemaChange.IsZero() {
		candidates = append(candidates, r.nextSchemaChange)
	}
	if !r.nextComplexQuery.IsZero() {
		candidates = append(candidates, r.nextComplexQuery)
	}
	if !r.nextLargeTx.IsZero() {
		candidates = append(candidates, r.nextLargeTx)
	}
	if !r.nextSizeCheck.IsZero() {
		candidates = append(candidates, r.nextSizeCheck)
	}
	next := candidates[0]
	for _, ts := range candidates[1:] {
		if ts.Before(next) {
			next = ts
		}
	}
	d := time.Until(next)
	if d < 0 {
		return 0
	}
	return d.Round(time.Second)
}

func (r *runner) randomTable(filter func(*tableSpec) bool) *tableSpec {
	candidates := make([]*tableSpec, 0, len(r.tables))
	for _, table := range r.tables {
		if filter(table) {
			candidates = append(candidates, table)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return candidates[rnd.Intn(len(candidates))]
	}).(*tableSpec)
}

func (r *runner) randomID(table string) (int64, bool) {
	res := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		id, ok := r.state.RandomID(table, rnd)
		return []any{id, ok}
	}).([]any)
	return res[0].(int64), res[1].(bool)
}

func (r *runner) randomRow(table string) (int64, map[string]any, bool) {
	res := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		id, row, ok := r.state.RandomRow(table, rnd)
		return []any{id, row, ok}
	}).([]any)
	if !res[2].(bool) {
		return 0, nil, false
	}
	return res[0].(int64), res[1].(map[string]any), true
}

func (r *runner) buildInsertRow(table *tableSpec, invalid bool) (map[string]any, string, error) {
	row := make(map[string]any, len(table.Columns))
	for _, col := range table.Columns {
		val, err := r.generateValidValue(table, col)
		if err != nil {
			return nil, "", err
		}
		row[col.Name] = val
	}
	for _, col := range table.Columns {
		if !col.Unique {
			continue
		}
		for tries := 0; tries < 25 && r.state.HasValue(table.Name, col.Name, row[col.Name]); tries++ {
			val, err := r.generateValidValue(table, col)
			if err != nil {
				return nil, "", err
			}
			row[col.Name] = val
		}
		if !invalid && r.state.HasValue(table.Name, col.Name, row[col.Name]) {
			return nil, "", fmt.Errorf("unique value depletion for %s.%s", table.Name, col.Name)
		}
	}
	for _, uniqueCols := range table.CompositeUniques {
		for tries := 0; tries < 25 && r.state.HasComposite(table.Name, uniqueCols, row); tries++ {
			for _, colName := range uniqueCols {
				col := findColumn(table, colName)
				val, err := r.generateValidValue(table, col)
				if err != nil {
					return nil, "", err
				}
				row[colName] = val
			}
		}
		if !invalid && r.state.HasComposite(table.Name, uniqueCols, row) {
			return nil, "", fmt.Errorf("composite unique value depletion for %s.%v", table.Name, uniqueCols)
		}
	}
	if !invalid {
		return row, "", nil
	}
	col, reason, err := r.applyInvalidValue(table, row)
	if err != nil {
		return nil, "", err
	}
	return row, fmt.Sprintf("%s:%s", col.Name, reason), nil
}

func (r *runner) buildUpdateChanges(table *tableSpec, id int64, current map[string]any, invalid bool) (map[string]any, string, error) {
	if len(table.UpdateableCols) == 0 {
		return nil, "", errors.New("no updateable columns")
	}
	changes := make(map[string]any)
	selectedCount := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return 1 + rnd.Intn(min(3, len(table.UpdateableCols)))
	}).(int)
	perm := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Perm(len(table.UpdateableCols))
	}).([]int)
	for _, idx := range perm[:selectedCount] {
		col := table.UpdateableCols[idx]
		val, err := r.generateValidValue(table, col)
		if err != nil {
			return nil, "", err
		}
		if normalizeValue(val) == normalizeValue(current[col.Name]) {
			val, err = r.generateValidValue(table, col)
			if err != nil {
				return nil, "", err
			}
		}

		if col.Unique {
			for tries := 0; tries < 25; tries++ {
				exists := false
				r.state.mu.RLock()
				for otherID, otherRow := range r.state.tables[table.Name].Rows {
					if otherID != id && normalizeValue(otherRow[col.Name]) == normalizeValue(val) {
						exists = true
						break
					}
				}
				r.state.mu.RUnlock()
				if !exists {
					break
				}
				val, err = r.generateValidValue(table, col)
				if err != nil {
					return nil, "", err
				}
			}
			if !invalid {
				exists := false
				r.state.mu.RLock()
				for otherID, otherRow := range r.state.tables[table.Name].Rows {
					if otherID != id && normalizeValue(otherRow[col.Name]) == normalizeValue(val) {
						exists = true
						break
					}
				}
				r.state.mu.RUnlock()
				if exists {
					return nil, "", fmt.Errorf("unique value depletion on update for %s.%s", table.Name, col.Name)
				}
			}
		}

		changes[col.Name] = val
	}

	projectedRow := cloneRow(current)
	for k, v := range changes {
		projectedRow[k] = v
	}

	for _, uniqueCols := range table.CompositeUniques {
		affected := false
		for _, colName := range uniqueCols {
			if _, ok := changes[colName]; ok {
				affected = true
				break
			}
		}
		if !affected {
			continue
		}

		for tries := 0; tries < 25; tries++ {
			exists := false
			r.state.mu.RLock()
			for otherID, otherRow := range r.state.tables[table.Name].Rows {
				if otherID != id {
					match := true
					for _, colName := range uniqueCols {
						if normalizeValue(otherRow[colName]) != normalizeValue(projectedRow[colName]) {
							match = false
							break
						}
					}
					if match {
						exists = true
						break
					}
				}
			}
			r.state.mu.RUnlock()
			if !exists {
				break
			}

			for _, colName := range uniqueCols {
				if _, ok := changes[colName]; ok {
					col := findColumn(table, colName)
					val, err := r.generateValidValue(table, col)
					if err != nil {
						return nil, "", err
					}
					changes[colName] = val
					projectedRow[colName] = val
				}
			}
		}
		if !invalid {
			exists := false
			r.state.mu.RLock()
			for otherID, otherRow := range r.state.tables[table.Name].Rows {
				if otherID != id {
					match := true
					for _, colName := range uniqueCols {
						if normalizeValue(otherRow[colName]) != normalizeValue(projectedRow[colName]) {
							match = false
							break
						}
					}
					if match {
						exists = true
						break
					}
				}
			}
			r.state.mu.RUnlock()
			if exists {
				return nil, "", fmt.Errorf("composite unique value depletion on update for %s.%v", table.Name, uniqueCols)
			}
		}
	}

	if !invalid {
		return changes, "", nil
	}
	targetCols := make([]columnSpec, 0, len(table.UpdateableCols))
	for _, col := range table.UpdateableCols {
		if col.InvalidCap {
			targetCols = append(targetCols, col)
		}
	}
	if len(targetCols) == 0 {
		return changes, "", nil
	}
	col := targetCols[r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(len(targetCols))
	}).(int)]
	reason, err := r.setInvalidValue(table, col, changes)
	if err != nil {
		return nil, "", err
	}
	return changes, fmt.Sprintf("%s:%s", col.Name, reason), nil
}

func (r *runner) applyInvalidValue(table *tableSpec, row map[string]any) (columnSpec, string, error) {
	candidates := make([]columnSpec, 0, len(table.Columns))
	for _, col := range table.Columns {
		if col.InvalidCap {
			candidates = append(candidates, col)
		}
	}
	if len(candidates) == 0 {
		return columnSpec{}, "", errors.New("no invalid candidate column")
	}
	col := candidates[r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(len(candidates))
	}).(int)]
	reason, err := r.setInvalidValue(table, col, row)
	return col, reason, err
}

func (r *runner) setInvalidValue(table *tableSpec, col columnSpec, values map[string]any) (string, error) {
	switch col.Kind {
	case kindFK:
		values[col.Name] = int64(9_999_999)
		return "fk_violation", nil
	case kindBool:
		values[col.Name] = 7
		return "bool_violation", nil
	case kindInt:
		values[col.Name] = col.MaxInt + 10_000
		if col.MinInt == 0 && col.MaxInt == 0 {
			values[col.Name] = int64(-1)
		}
		return "int_range_violation", nil
	case kindReal:
		values[col.Name] = col.MaxFloat + 100_000
		if col.MinFloat == 0 && col.MaxFloat == 0 {
			values[col.Name] = math.Inf(1)
		}
		return "real_range_violation", nil
	case kindEnum:
		values[col.Name] = "invalid-enum-value"
		return "enum_violation", nil
	case kindDate:
		values[col.Name] = "bad-date"
		return "date_violation", nil
	case kindTimestamp:
		values[col.Name] = "bad-timestamp"
		return "timestamp_violation", nil
	case kindBlob:
		values[col.Name] = nil
		return "null_blob", nil
	default:
		if !col.Nullable {
			if col.MaxLen > 0 {
				values[col.Name] = strings.Repeat("X", col.MaxLen+50)
				return "length_violation", nil
			}
			values[col.Name] = nil
			return "null_violation", nil
		}
		values[col.Name] = strings.Repeat("X", max(col.MaxLen+50, 128))
		return "length_violation", nil
	}
}

func (r *runner) generateValidValue(table *tableSpec, col columnSpec) (any, error) {
	if col.Nullable {
		if r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any { return rnd.Intn(100) < 20 }).(bool) {
			return nil, nil
		}
	}
	switch col.Kind {
	case kindFK:
		res := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
			id, ok := r.state.RandomID(col.RefTable, rnd)
			return []any{id, ok}
		}).([]any)
		id, ok := res[0].(int64), res[1].(bool)
		if !ok {
			return nil, fmt.Errorf("no parent rows for %s.%s -> %s", table.Name, col.Name, col.RefTable)
		}
		return id, nil
	case kindBool:
		if r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any { return rnd.Intn(2) == 0 }).(bool) {
			return 0, nil
		}
		return 1, nil
	case kindInt:
		minVal := col.MinInt
		maxVal := col.MaxInt
		if minVal == 0 && maxVal == 0 {
			minVal, maxVal = 1, 10_000
		}
		return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
			return minVal + rnd.Int63n(maxVal-minVal+1)
		}).(int64), nil
	case kindReal:
		minVal := col.MinFloat
		maxVal := col.MaxFloat
		if minVal == 0 && maxVal == 0 {
			minVal, maxVal = 0.1, 9999.9
		}
		return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
			return minVal + rnd.Float64()*(maxVal-minVal)
		}).(float64), nil
	case kindBlob:
		size := col.BlobBytes
		if size == 0 {
			size = 64
		}
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			return []byte(fake.LetterN(uint(size)))
		}).([]byte), nil
	case kindEnum:
		return r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
			return col.Enum[rnd.Intn(len(col.Enum))]
		}).(string), nil
	case kindDate:
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			return fake.Date().UTC().Format("2006-01-02")
		}).(string), nil
	case kindTimestamp:
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			return fake.Date().UTC().Format(time.RFC3339Nano)
		}).(string), nil
	case kindEmail:
		return fmt.Sprintf("user-%s@example.com", r.fake.uniqueSuffix()), nil
	case kindURL:
		return fmt.Sprintf("https://example.com/%s", r.fake.uniqueSuffix()), nil
	case kindIP:
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			return fake.IPv4Address()
		}).(string), nil
	case kindUUID:
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			return fake.UUID()
		}).(string), nil
	default:
		return r.fake.WithLock(func(_ *rand.Rand, fake *gofakeit.Faker) any {
			base := fake.Word()
			switch {
			case strings.Contains(col.Name, "name"):
				base = fake.Name()
			case strings.Contains(col.Name, "title"), strings.Contains(col.Name, "subject"):
				base = fake.Sentence(4)
			case strings.Contains(col.Name, "description"), strings.Contains(col.Name, "details"), strings.Contains(col.Name, "body"), strings.Contains(col.Name, "message"), strings.Contains(col.Name, "bio"):
				base = fake.Paragraph(1, 3, 8, " ")
			case strings.Contains(col.Name, "slug"), strings.Contains(col.Name, "code"), strings.Contains(col.Name, "sku"), strings.Contains(col.Name, "token"), strings.Contains(col.Name, "key"), strings.Contains(col.Name, "checksum"), strings.Contains(col.Name, "order_number"), strings.Contains(col.Name, "platform"), strings.Contains(col.Name, "mime_type"), strings.Contains(col.Name, "postal_code"), strings.Contains(col.Name, "path"):
				base = fake.LetterN(12) + "-" + r.fake.uniqueSuffix()
			}
			if col.Unique {
				base = base + "-" + r.fake.uniqueSuffix()
			}
			if col.MaxLen > 0 && len(base) > col.MaxLen {
				base = base[:col.MaxLen]
			}
			for len(base) < col.MinLen {
				base += "x"
			}
			return base
		}).(string), nil
	}
}

func tableDDL(table *tableSpec) []string {
	defs := []string{"id INTEGER PRIMARY KEY"}
	for _, col := range table.Columns {
		defs = append(defs, columnDDL(col))
	}
	for _, cols := range table.CompositeUniques {
		defs = append(defs, fmt.Sprintf("UNIQUE (%s)", strings.Join(cols, ", ")))
	}
	out := []string{fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", table.Name, strings.Join(defs, ", "))}
	for i, idxCols := range table.Indexes {
		idxName := fmt.Sprintf("idx_%s_%d", table.Name, i+1)
		out = append(out, fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s)", idxName, table.Name, strings.Join(idxCols, ", ")))
	}
	return out
}

func columnDDL(col columnSpec) string {
	parts := []string{col.Name, columnType(col)}
	if !col.Nullable {
		parts = append(parts, "NOT NULL")
	}
	if col.Unique {
		parts = append(parts, "UNIQUE")
	}
	if col.RefTable != "" {
		parts = append(parts, fmt.Sprintf("REFERENCES %s(id) ON DELETE CASCADE", col.RefTable))
	}
	if checks := columnChecks(col); len(checks) > 0 {
		parts = append(parts, fmt.Sprintf("CHECK (%s)", strings.Join(checks, " AND ")))
	}
	return strings.Join(parts, " ")
}

func columnType(col columnSpec) string {
	switch col.Kind {
	case kindBool, kindInt, kindFK:
		return "INTEGER"
	case kindReal:
		return "REAL"
	case kindBlob:
		return "BLOB"
	default:
		return "TEXT"
	}
}

func columnChecks(col columnSpec) []string {
	name := col.Name
	guard := func(expr string) string {
		if col.Nullable {
			return fmt.Sprintf("(%s IS NULL OR %s)", name, expr)
		}
		return expr
	}

	var checks []string
	switch col.Kind {
	case kindBool:
		checks = append(checks, guard(fmt.Sprintf("%s IN (0,1)", name)))
	case kindInt, kindFK:
		if col.MinInt != 0 {
			checks = append(checks, guard(fmt.Sprintf("%s >= %d", name, col.MinInt)))
		}
		if col.MaxInt != 0 {
			checks = append(checks, guard(fmt.Sprintf("%s <= %d", name, col.MaxInt)))
		}
	case kindReal:
		if col.MinFloat != 0 {
			checks = append(checks, guard(fmt.Sprintf("%s >= %g", name, col.MinFloat)))
		}
		if col.MaxFloat != 0 {
			checks = append(checks, guard(fmt.Sprintf("%s <= %g", name, col.MaxFloat)))
		}
	case kindDate:
		checks = append(checks, guard(fmt.Sprintf("length(%s) = 10", name)))
	case kindTimestamp:
		checks = append(checks, guard(fmt.Sprintf("length(%s) >= 20", name)))
	case kindEnum:
		quoted := make([]string, 0, len(col.Enum))
		for _, v := range col.Enum {
			quoted = append(quoted, fmt.Sprintf("'%s'", v))
		}
		checks = append(checks, guard(fmt.Sprintf("%s IN (%s)", name, strings.Join(quoted, ", "))))
	}
	if col.MinLen > 0 {
		checks = append(checks, guard(fmt.Sprintf("length(%s) >= %d", name, col.MinLen)))
	}
	if col.MaxLen > 0 {
		checks = append(checks, guard(fmt.Sprintf("length(%s) <= %d", name, col.MaxLen)))
	}
	return checks
}

func buildTableSpecs() []*tableSpec {
	specs := []*tableSpec{
		newTable("countries", 3, false, []columnSpec{
			col("code", kindText, false, true, "", nil, 2, 2, 0, 0, 0, 0, 0, true, true),
			col("name", kindText, false, true, "", nil, 2, 80, 0, 0, 0, 0, 0, true, true),
			col("region", kindEnum, false, false, "", []string{"amer", "emea", "apac"}, 0, 0, 0, 0, 0, 0, 0, true, true),
		}, nil, [][]string{{"code"}, {"name"}}),
		newTable("addresses", 5, false, []columnSpec{
			col("line1", kindText, false, false, "", nil, 5, 120, 0, 0, 0, 0, 0, false, true),
			col("line2", kindText, true, false, "", nil, 0, 120, 0, 0, 0, 0, 0, false, true),
			col("city", kindText, false, false, "", nil, 2, 80, 0, 0, 0, 0, 0, true, true),
			col("postal_code", kindText, false, false, "", nil, 3, 12, 0, 0, 0, 0, 0, true, true),
			col("country_id", kindFK, false, false, "countries", nil, 0, 0, 1, 0, 0, 0, 0, true, true),
			col("latitude", kindReal, false, false, "", nil, 0, 0, 0, 0, -90, 90, 0, false, true),
			col("longitude", kindReal, false, false, "", nil, 0, 0, 0, 0, -180, 180, 0, false, true),
		}, nil, [][]string{{"country_id"}, {"city"}, {"postal_code"}}),
		newTable("users", 8, false, []columnSpec{
			col("email", kindEmail, false, true, "", nil, 8, 120, 0, 0, 0, 0, 0, true, true),
			col("username", kindText, false, true, "", nil, 3, 40, 0, 0, 0, 0, 0, true, true),
			col("full_name", kindText, false, false, "", nil, 3, 120, 0, 0, 0, 0, 0, false, true),
			col("password_hash", kindText, false, false, "", nil, 12, 128, 0, 0, 0, 0, 0, false, true),
			col("age", kindInt, false, false, "", nil, 0, 0, 13, 120, 0, 0, 0, false, true),
			col("active", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("address_id", kindFK, true, false, "addresses", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"email"}, {"username"}, {"active"}, {"created_at"}}),
		newTable("profiles", 6, true, []columnSpec{
			col("user_id", kindFK, false, true, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("birth_date", kindDate, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, false, true),
			col("bio", kindText, true, false, "", nil, 0, 500, 0, 0, 0, 0, 0, false, true),
			col("website", kindURL, true, false, "", nil, 8, 120, 0, 0, 0, 0, 0, false, true),
			col("avatar_blob", kindBlob, true, false, "", nil, 0, 0, 0, 0, 0, 0, 64, false, true),
			col("reputation", kindReal, false, false, "", nil, 0, 0, 0, 0, 0, 100, 0, true, true),
		}, nil, [][]string{{"user_id"}, {"reputation"}}),
		newTable("roles", 4, false, []columnSpec{
			col("role_name", kindText, false, true, "", nil, 3, 50, 0, 0, 0, 0, 0, true, true),
			col("description", kindText, false, false, "", nil, 3, 200, 0, 0, 0, 0, 0, false, true),
		}, nil, [][]string{{"role_name"}}),
		newTable("user_roles", 8, true, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("role_id", kindFK, false, false, "roles", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("granted_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, [][]string{{"user_id", "role_id"}}, [][]string{{"user_id"}, {"role_id"}}),
		newTable("sessions", 8, false, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("session_token", kindUUID, false, true, "", nil, 8, 64, 0, 0, 0, 0, 0, true, true),
			col("ip_address", kindIP, false, false, "", nil, 7, 45, 0, 0, 0, 0, 0, true, true),
			col("user_agent", kindText, false, false, "", nil, 8, 200, 0, 0, 0, 0, 0, false, true),
			col("last_seen_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
			col("is_mobile", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
		}, nil, [][]string{{"user_id"}, {"session_token"}, {"last_seen_at"}}),
		newTable("api_keys", 6, true, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("key_name", kindText, false, false, "", nil, 3, 80, 0, 0, 0, 0, 0, true, true),
			col("secret_hash", kindText, false, true, "", nil, 24, 96, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
			col("expires_at", kindTimestamp, true, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("revoked", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
		}, nil, [][]string{{"user_id"}, {"secret_hash"}}),
		newTable("login_attempts", 10, true, []columnSpec{
			col("user_id", kindFK, true, false, "users", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("email_attempt", kindEmail, false, false, "", nil, 8, 120, 0, 0, 0, 0, 0, true, true),
			col("success", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("ip_address", kindIP, false, false, "", nil, 7, 45, 0, 0, 0, 0, 0, true, true),
			col("attempted_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
			col("failure_reason", kindText, true, false, "", nil, 0, 120, 0, 0, 0, 0, 0, false, true),
		}, nil, [][]string{{"user_id"}, {"success"}, {"attempted_at"}}),
		newTable("categories", 5, false, []columnSpec{
			col("slug", kindText, false, true, "", nil, 3, 60, 0, 0, 0, 0, 0, true, true),
			col("name", kindText, false, false, "", nil, 3, 80, 0, 0, 0, 0, 0, true, true),
			col("description", kindText, true, false, "", nil, 0, 200, 0, 0, 0, 0, 0, false, true),
			col("display_order", kindInt, false, false, "", nil, 0, 0, 0, 999, 0, 0, 0, true, true),
		}, nil, [][]string{{"slug"}, {"name"}}),
		newTable("tags", 6, false, []columnSpec{
			col("slug", kindText, false, true, "", nil, 3, 60, 0, 0, 0, 0, 0, true, true),
			col("name", kindText, false, true, "", nil, 2, 60, 0, 0, 0, 0, 0, true, true),
			col("color", kindText, false, false, "", nil, 7, 7, 0, 0, 0, 0, 0, true, true),
		}, nil, [][]string{{"slug"}, {"name"}}),
		newTable("products", 12, false, []columnSpec{
			col("category_id", kindFK, false, false, "categories", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("created_by_user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("sku", kindText, false, true, "", nil, 6, 40, 0, 0, 0, 0, 0, true, true),
			col("name", kindText, false, false, "", nil, 3, 120, 0, 0, 0, 0, 0, true, true),
			col("description", kindText, true, false, "", nil, 0, 400, 0, 0, 0, 0, 0, false, true),
			col("price_cents", kindInt, false, false, "", nil, 0, 0, 0, 10_000_000, 0, 0, 0, true, true),
			col("stock_qty", kindInt, false, false, "", nil, 0, 0, 0, 100_000, 0, 0, 0, true, true),
			col("weight_kg", kindReal, false, false, "", nil, 0, 0, 0, 0, 0, 1000, 0, false, true),
			col("active", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"category_id"}, {"created_by_user_id"}, {"sku"}, {"name"}, {"active"}}),
		newTable("product_tags", 8, true, []columnSpec{
			col("product_id", kindFK, false, false, "products", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("tag_id", kindFK, false, false, "tags", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
		}, [][]string{{"product_id", "tag_id"}}, [][]string{{"product_id"}, {"tag_id"}}),
		newTable("carts", 6, false, []columnSpec{
			col("user_id", kindFK, false, true, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("status", kindEnum, false, false, "", []string{"open", "checked_out", "abandoned"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
			col("updated_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"status"}}),
		newTable("cart_items", 8, true, []columnSpec{
			col("cart_id", kindFK, false, false, "carts", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("product_id", kindFK, false, false, "products", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("quantity", kindInt, false, false, "", nil, 0, 0, 1, 1000, 0, 0, 0, true, true),
			col("added_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, [][]string{{"cart_id", "product_id"}}, [][]string{{"cart_id"}, {"product_id"}}),
		newTable("orders", 8, false, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("shipping_address_id", kindFK, false, false, "addresses", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("order_number", kindText, false, true, "", nil, 6, 40, 0, 0, 0, 0, 0, true, true),
			col("status", kindEnum, false, false, "", []string{"pending", "paid", "shipped", "cancelled"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("subtotal_cents", kindInt, false, false, "", nil, 0, 0, 0, 50_000_000, 0, 0, 0, false, true),
			col("tax_cents", kindInt, false, false, "", nil, 0, 0, 0, 5_000_000, 0, 0, 0, false, true),
			col("total_cents", kindInt, false, false, "", nil, 0, 0, 0, 55_000_000, 0, 0, 0, true, true),
			col("placed_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"shipping_address_id"}, {"order_number"}, {"status"}, {"placed_at"}}),
		newTable("order_items", 8, true, []columnSpec{
			col("order_id", kindFK, false, false, "orders", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("product_id", kindFK, false, false, "products", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("quantity", kindInt, false, false, "", nil, 0, 0, 1, 1000, 0, 0, 0, true, true),
			col("unit_price_cents", kindInt, false, false, "", nil, 0, 0, 0, 10_000_000, 0, 0, 0, false, true),
		}, [][]string{{"order_id", "product_id"}}, [][]string{{"order_id"}, {"product_id"}}),
		newTable("posts", 8, false, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("title", kindText, false, false, "", nil, 5, 150, 0, 0, 0, 0, 0, true, true),
			col("body", kindText, false, false, "", nil, 20, 2000, 0, 0, 0, 0, 0, false, true),
			col("published", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("published_at", kindTimestamp, true, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
		}, nil, [][]string{{"user_id"}, {"title"}, {"published"}}),
		newTable("comments", 10, true, []columnSpec{
			col("post_id", kindFK, false, false, "posts", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("body", kindText, false, false, "", nil, 3, 800, 0, 0, 0, 0, 0, false, true),
			col("flagged", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"post_id"}, {"user_id"}, {"flagged"}}),
		newTable("likes", 8, true, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("post_id", kindFK, false, false, "posts", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("reaction", kindEnum, false, false, "", []string{"like", "love", "laugh"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, [][]string{{"user_id", "post_id"}}, [][]string{{"user_id"}, {"post_id"}}),
		newTable("notifications", 8, true, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("channel", kindEnum, false, false, "", []string{"email", "push", "sms", "inapp"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("message", kindText, false, false, "", nil, 5, 300, 0, 0, 0, 0, 0, false, true),
			col("read_flag", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"channel"}, {"read_flag"}}),
		newTable("tickets", 6, false, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("subject", kindText, false, false, "", nil, 5, 150, 0, 0, 0, 0, 0, true, true),
			col("body", kindText, false, false, "", nil, 10, 1000, 0, 0, 0, 0, 0, false, true),
			col("priority", kindEnum, false, false, "", []string{"low", "medium", "high"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("status", kindEnum, false, false, "", []string{"open", "pending", "closed"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("opened_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"priority"}, {"status"}}),
		newTable("ticket_events", 10, true, []columnSpec{
			col("ticket_id", kindFK, false, false, "tickets", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("actor_user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("event_type", kindEnum, false, false, "", []string{"note", "status_change", "assignment"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("details", kindText, false, false, "", nil, 3, 500, 0, 0, 0, 0, 0, false, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"ticket_id"}, {"actor_user_id"}, {"event_type"}}),
		newTable("attachments", 8, true, []columnSpec{
			col("owner_user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("ticket_id", kindFK, true, false, "tickets", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("post_id", kindFK, true, false, "posts", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("file_name", kindText, false, false, "", nil, 3, 120, 0, 0, 0, 0, 0, true, true),
			col("mime_type", kindText, false, false, "", nil, 3, 80, 0, 0, 0, 0, 0, true, true),
			col("size_bytes", kindInt, false, false, "", nil, 0, 0, 0, 10_000_000, 0, 0, 0, true, true),
			col("checksum", kindText, false, true, "", nil, 16, 64, 0, 0, 0, 0, 0, true, true),
			col("blob_data", kindBlob, false, false, "", nil, 0, 0, 0, 0, 0, 0, 48, false, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"owner_user_id"}, {"ticket_id"}, {"post_id"}, {"checksum"}}),
		newTable("feature_flags", 5, true, []columnSpec{
			col("flag_key", kindText, false, true, "", nil, 3, 80, 0, 0, 0, 0, 0, true, true),
			col("enabled", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("rollout_pct", kindInt, false, false, "", nil, 0, 0, 0, 100, 0, 0, 0, true, true),
			col("description", kindText, true, false, "", nil, 0, 200, 0, 0, 0, 0, 0, false, true),
			col("updated_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"flag_key"}, {"enabled"}}),
		newTable("settings", 5, true, []columnSpec{
			col("namespace", kindText, false, false, "", nil, 3, 40, 0, 0, 0, 0, 0, true, true),
			col("setting_key", kindText, false, false, "", nil, 3, 80, 0, 0, 0, 0, 0, true, true),
			col("setting_value", kindText, false, false, "", nil, 0, 200, 0, 0, 0, 0, 0, false, true),
			col("updated_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, [][]string{{"namespace", "setting_key"}}, [][]string{{"namespace"}, {"setting_key"}}),
		newTable("audit_events", 12, true, []columnSpec{
			col("actor_user_id", kindFK, true, false, "users", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("entity_type", kindEnum, false, false, "", []string{"user", "order", "product", "ticket", "post"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("entity_id", kindInt, false, false, "", nil, 0, 0, 1, 1_000_000, 0, 0, 0, true, true),
			col("action", kindEnum, false, false, "", []string{"create", "update", "delete", "login"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("details", kindText, false, false, "", nil, 3, 500, 0, 0, 0, 0, 0, false, true),
			col("created_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"actor_user_id"}, {"entity_type"}, {"entity_id"}, {"created_at"}}),
		newTable("page_views", 12, true, []columnSpec{
			col("user_id", kindFK, true, false, "users", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("session_id", kindFK, true, false, "sessions", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("path", kindText, false, false, "", nil, 1, 200, 0, 0, 0, 0, 0, true, true),
			col("referrer", kindURL, true, false, "", nil, 0, 120, 0, 0, 0, 0, 0, false, true),
			col("duration_ms", kindInt, false, false, "", nil, 0, 0, 0, 600_000, 0, 0, 0, true, true),
			col("viewed_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"session_id"}, {"path"}, {"viewed_at"}}),
		newTable("devices", 8, true, []columnSpec{
			col("user_id", kindFK, false, false, "users", nil, 0, 0, 1, 0, 0, 0, 0, true, false),
			col("device_uuid", kindUUID, false, true, "", nil, 8, 64, 0, 0, 0, 0, 0, true, true),
			col("platform", kindEnum, false, false, "", []string{"ios", "android", "web", "desktop"}, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("push_token", kindText, true, false, "", nil, 10, 120, 0, 0, 0, 0, 0, false, true),
			col("trusted", kindBool, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, true),
			col("last_seen_at", kindTimestamp, false, false, "", nil, 0, 0, 0, 0, 0, 0, 0, true, false),
		}, nil, [][]string{{"user_id"}, {"device_uuid"}, {"platform"}}),
	}

	for _, spec := range specs {
		spec.AllColumnNames = append(spec.AllColumnNames, "id")
		insertCols := make([]string, 0, len(spec.Columns))
		placeholders := make([]string, 0, len(spec.Columns))
		for _, col := range spec.Columns {
			insertCols = append(insertCols, col.Name)
			placeholders = append(placeholders, "?")
			spec.AllColumnNames = append(spec.AllColumnNames, col.Name)
			if col.Updatable {
				spec.UpdateableCols = append(spec.UpdateableCols, col)
			}
		}
		spec.InsertSQL = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", spec.Name, strings.Join(insertCols, ", "), strings.Join(placeholders, ", "))
		spec.SelectByIDSQL = fmt.Sprintf("SELECT * FROM %s WHERE id = ?", spec.Name)
	}
	return specs
}

func newTable(name string, seedRows int, allowDelete bool, columns []columnSpec, composite [][]string, indexes [][]string) *tableSpec {
	return &tableSpec{
		Name:             name,
		Columns:          columns,
		CompositeUniques: composite,
		Indexes:          indexes,
		SeedRows:         seedRows,
		AllowDelete:      allowDelete,
	}
}

func col(name string, kind kind, nullable, unique bool, ref string, enum []string, minLen, maxLen int, minInt, maxInt int64, minFloat, maxFloat float64, blobBytes int, indexed, updatable bool) columnSpec {
	return columnSpec{
		Name:       name,
		Kind:       kind,
		Nullable:   nullable,
		Unique:     unique,
		RefTable:   ref,
		Enum:       enum,
		MinLen:     minLen,
		MaxLen:     maxLen,
		MinInt:     minInt,
		MaxInt:     maxInt,
		MinFloat:   minFloat,
		MaxFloat:   maxFloat,
		BlobBytes:  blobBytes,
		Indexed:    indexed,
		Updatable:  updatable,
		InvalidCap: true,
	}
}

func findColumn(table *tableSpec, name string) columnSpec {
	for _, col := range table.Columns {
		if col.Name == name {
			return col
		}
	}
	return columnSpec{}
}

func valuesForColumns(cols []columnSpec, row map[string]any) []any {
	out := make([]any, 0, len(cols))
	for _, col := range cols {
		out = append(out, row[col.Name])
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func queryRowsNormalized(ctx context.Context, db compareQueryer, query string, args ...any) ([][]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := make([][]string, 0)
	for rows.Next() {
		dest := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		record := make([]string, len(cols))
		for i, v := range dest {
			record[i] = normalizeValue(v)
		}
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeValue(v any) string {
	switch value := v.(type) {
	case nil:
		return "<nil>"
	case []byte:
		return fmt.Sprintf("bytes:%x", value)
	case time.Time:
		return value.UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r *runner) refreshTableSQL(spec *tableSpec) {
	spec.AllColumnNames = []string{"id"}
	spec.UpdateableCols = nil
	insertCols := make([]string, 0, len(spec.Columns))
	placeholders := make([]string, 0, len(spec.Columns))
	for _, col := range spec.Columns {
		insertCols = append(insertCols, col.Name)
		placeholders = append(placeholders, "?")
		spec.AllColumnNames = append(spec.AllColumnNames, col.Name)
		if col.Updatable {
			spec.UpdateableCols = append(spec.UpdateableCols, col)
		}
	}
	spec.InsertSQL = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", spec.Name, strings.Join(insertCols, ", "), strings.Join(placeholders, ", "))
	spec.SelectByIDSQL = fmt.Sprintf("SELECT * FROM %s WHERE id = ?", spec.Name)
}

func (r *runner) executeSchemaChange() error {
	choice := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(6)
	}).(int)

	switch choice {
	case 0:
		return r.schemaAddTable()
	case 1:
		return r.schemaDropTable()
	case 2:
		return r.schemaAddColumn()
	case 3:
		return r.schemaDropColumn()
	case 4:
		return r.schemaAddIndex()
	case 5:
		return r.schemaDropIndex()
	}
	return nil
}

func (r *runner) schemaAddTable() error {
	tblNum := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(10000)
	}).(int)
	tableName := fmt.Sprintf("dynamic_table_%d", tblNum)

	spec := &tableSpec{
		Name: tableName,
		Columns: []columnSpec{
			col("col_text", kindText, false, false, "", nil, 3, 50, 0, 0, 0, 0, 0, false, true),
			col("col_int", kindInt, false, false, "", nil, 0, 0, 1, 10000, 0, 0, 0, false, true),
		},
		AllowDelete: true,
		SeedRows:    5,
	}
	r.refreshTableSQL(spec)

	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		for _, stmt := range tableDDL(spec) {
			if _, err := db.conn.ExecContext(r.ctx, stmt); err != nil {
				return fmt.Errorf("add table %s on %s: %w", tableName, db.name, err)
			}
		}
	}

	r.tables = append(r.tables, spec)
	r.tableByName[tableName] = spec

	r.state.mu.Lock()
	r.state.tables[tableName] = &tableRows{Rows: make(map[int64]map[string]any)}
	r.state.mu.Unlock()

	for i := 0; i < spec.SeedRows; i++ {
		row, _, err := r.buildInsertRow(spec, false)
		if err != nil {
			return fmt.Errorf("seed dynamic table %s row: %w", tableName, err)
		}
		if err := r.performInsert(spec, row, false, 0); err != nil {
			return fmt.Errorf("seed dynamic table %s insert: %w", tableName, err)
		}
	}

	r.logger.Info("schema change: added table %s", tableName)
	return nil
}

func (r *runner) schemaDropTable() error {
	var candidates []*tableSpec
	for _, spec := range r.tables {
		if strings.HasPrefix(spec.Name, "dynamic_table_") {
			candidates = append(candidates, spec)
		}
	}
	if len(candidates) == 0 {
		r.logger.Info("schema change: no dynamic tables to drop")
		return nil
	}

	spec := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return candidates[rnd.Intn(len(candidates))]
	}).(*tableSpec)

	tableName := spec.Name

	sqlText := fmt.Sprintf("DROP TABLE %s", tableName)
	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, sqlText); err != nil {
			return fmt.Errorf("drop table %s on %s: %w", tableName, db.name, err)
		}
	}

	for i, t := range r.tables {
		if t.Name == tableName {
			r.tables = append(r.tables[:i], r.tables[i+1:]...)
			break
		}
	}
	delete(r.tableByName, tableName)
	delete(r.dynamicIndexes, tableName)

	r.state.mu.Lock()
	delete(r.state.tables, tableName)
	r.state.mu.Unlock()

	r.logger.Info("schema change: dropped table %s", tableName)
	return nil
}

func (r *runner) schemaAddColumn() error {
	table := r.randomTable(func(t *tableSpec) bool { return true })
	if table == nil {
		return nil
	}

	colNum := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(10000)
	}).(int)
	colName := fmt.Sprintf("dyn_col_%d", colNum)

	newCol := col(colName, kindText, true, false, "", nil, 3, 50, 0, 0, 0, 0, 0, false, true)

	sqlText := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table.Name, columnDDL(newCol))

	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, sqlText); err != nil {
			return fmt.Errorf("add column %s to %s on %s: %w", colName, table.Name, db.name, err)
		}
	}

	table.Columns = append(table.Columns, newCol)
	r.refreshTableSQL(table)

	r.state.mu.Lock()
	tRows := r.state.tables[table.Name]
	for id := range tRows.Rows {
		tRows.Rows[id][colName] = nil
	}
	r.state.mu.Unlock()

	r.logger.Info("schema change: added column %s to table %s", colName, table.Name)
	return nil
}

func (r *runner) schemaDropColumn() error {
	type candidate struct {
		table   *tableSpec
		colIdx  int
		colName string
	}
	var candidates []candidate
	for _, table := range r.tables {
		for i, c := range table.Columns {
			if strings.HasPrefix(c.Name, "dyn_col_") {
				candidates = append(candidates, candidate{table: table, colIdx: i, colName: c.Name})
			}
		}
	}

	if len(candidates) == 0 {
		r.logger.Info("schema change: no dynamic columns to drop")
		return nil
	}

	choice := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return candidates[rnd.Intn(len(candidates))]
	}).(candidate)

	table := choice.table
	colName := choice.colName

	sqlText := fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", table.Name, colName)

	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, sqlText); err != nil {
			return fmt.Errorf("drop column %s from %s on %s: %w", colName, table.Name, db.name, err)
		}
	}

	table.Columns = append(table.Columns[:choice.colIdx], table.Columns[choice.colIdx+1:]...)
	r.refreshTableSQL(table)

	r.state.mu.Lock()
	tRows := r.state.tables[table.Name]
	for id := range tRows.Rows {
		delete(tRows.Rows[id], colName)
	}
	r.state.mu.Unlock()

	r.logger.Info("schema change: dropped column %s from table %s", colName, table.Name)
	return nil
}

func (r *runner) schemaAddIndex() error {
	table := r.randomTable(func(t *tableSpec) bool { return len(t.Columns) > 0 })
	if table == nil {
		return nil
	}

	col := table.Columns[r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return rnd.Intn(len(table.Columns))
	}).(int)]

	alreadyIndexed := false
	for _, idx := range table.Indexes {
		if len(idx) == 1 && idx[0] == col.Name {
			alreadyIndexed = true
			break
		}
	}
	if alreadyIndexed {
		return nil
	}

	idxName := fmt.Sprintf("dyn_idx_%s_%s", table.Name, col.Name)
	sqlText := fmt.Sprintf("CREATE INDEX %s ON %s (%s)", idxName, table.Name, col.Name)

	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, sqlText); err != nil {
			return fmt.Errorf("create index %s on %s(%s) on %s: %w", idxName, table.Name, col.Name, db.name, err)
		}
	}

	table.Indexes = append(table.Indexes, []string{col.Name})
	r.dynamicIndexes[table.Name] = append(r.dynamicIndexes[table.Name], col.Name)

	r.logger.Info("schema change: added index %s on %s(%s)", idxName, table.Name, col.Name)
	return nil
}

func (r *runner) schemaDropIndex() error {
	type candidate struct {
		tableName string
		colIdx    int
		colName   string
	}
	var candidates []candidate
	for tblName, cols := range r.dynamicIndexes {
		for i, colName := range cols {
			candidates = append(candidates, candidate{tableName: tblName, colIdx: i, colName: colName})
		}
	}

	if len(candidates) == 0 {
		r.logger.Info("schema change: no dynamic indexes to drop")
		return nil
	}

	choice := r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
		return candidates[rnd.Intn(len(candidates))]
	}).(candidate)

	table := r.tableByName[choice.tableName]
	if table == nil {
		return nil
	}
	colName := choice.colName
	idxName := fmt.Sprintf("dyn_idx_%s_%s", table.Name, colName)

	sqlText := fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName)

	for _, db := range []struct {
		name string
		conn *sql.DB
	}{
		{name: "sqlite", conn: r.sqliteDB},
		{name: "encz", conn: r.enczDB.SQLDB()},
	} {
		if _, err := db.conn.ExecContext(r.ctx, sqlText); err != nil {
			return fmt.Errorf("drop index %s on %s: %w", idxName, db.name, err)
		}
	}

	for i, idx := range table.Indexes {
		if len(idx) == 1 && idx[0] == colName {
			table.Indexes = append(table.Indexes[:i], table.Indexes[i+1:]...)
			break
		}
	}

	cols := r.dynamicIndexes[choice.tableName]
	r.dynamicIndexes[choice.tableName] = append(cols[:choice.colIdx], cols[choice.colIdx+1:]...)

	r.logger.Info("schema change: dropped index %s", idxName)
	return nil
}

type schemaObject struct {
	Type    string
	Name    string
	TblName string
	SQL     string
}

func querySchema(ctx context.Context, db *sql.DB, query string) ([]schemaObject, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []schemaObject
	for rows.Next() {
		var obj schemaObject
		var sqlVal sql.NullString
		if err := rows.Scan(&obj.Type, &obj.Name, &obj.TblName, &sqlVal); err != nil {
			return nil, err
		}
		obj.SQL = sqlVal.String
		list = append(list, obj)
	}
	return list, rows.Err()
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, errors.New("empty size")
	}
	var multiplier int64 = 1
	if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	} else if strings.HasSuffix(s, "B") {
		s = strings.TrimSuffix(s, "B")
	}
	val, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %w", err)
	}
	return val * multiplier, nil
}

func getFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (r *runner) checkDatabaseSize() error {
	limit := r.cfg.MaxDBSizeBytes

	sqliteSize := getFileSize(r.cfg.SQLiteDBPath)
	enczSize := getFileSize(r.cfg.EnczDBPath)

	if sqliteSize > limit || enczSize > limit {
		r.logger.Info("database size limit exceeded! sqlite=%d encz=%d limit=%d. Pruning 50%% of deletable items...", sqliteSize, enczSize, limit)

		r.paused.Store(true)
		r.waitForWorkers()
		r.phaseMu.Lock()
		defer r.phaseMu.Unlock()
		r.paused.Store(false)

		for _, table := range r.tables {
			if !table.AllowDelete {
				continue
			}

			r.state.mu.RLock()
			var ids []int64
			if tRows, ok := r.state.tables[table.Name]; ok {
				ids = append(ids, tRows.IDs...)
			}
			r.state.mu.RUnlock()

			if len(ids) == 0 {
				continue
			}

			r.fake.WithLock(func(rnd *rand.Rand, _ *gofakeit.Faker) any {
				rnd.Shuffle(len(ids), func(i, j int) {
					ids[i], ids[j] = ids[j], ids[i]
				})
				return nil
			})

			toDeleteCount := len(ids) / 2
			if toDeleteCount == 0 && len(ids) > 0 {
				toDeleteCount = 1
			}

			for i := 0; i < toDeleteCount; i++ {
				id := ids[i]
				sqlText := fmt.Sprintf("DELETE FROM %s WHERE id = ?", table.Name)
				_, sqliteErr := r.sqliteDB.ExecContext(r.ctx, sqlText, id)
				_, enczErr := r.enczDB.ExecContext(r.ctx, sqlText, id)

				if sqliteErr == nil && enczErr == nil {
					r.state.DeleteRow(table.Name, id)
				} else {
					if sqliteErr != nil {
						r.logger.Error("prune DELETE table=%s id=%d sqlite error=%v", table.Name, id, sqliteErr)
					}
					if enczErr != nil {
						r.logger.Error("prune DELETE table=%s id=%d encz error=%v", table.Name, id, enczErr)
					}
				}
			}
		}

		r.logger.Info("running VACUUM on sqlite and encz databases...")
		if _, err := r.sqliteDB.ExecContext(r.ctx, "VACUUM"); err != nil {
			r.logger.Error("sqlite VACUUM error: %v", err)
		}
		if _, err := r.enczDB.SQLDB().ExecContext(r.ctx, "VACUUM"); err != nil {
			r.logger.Error("encz VACUUM error: %v", err)
		}

		newSqliteSize := getFileSize(r.cfg.SQLiteDBPath)
		newEnczSize := getFileSize(r.cfg.EnczDBPath)
		r.logger.Info("pruning complete. New database sizes: sqlite=%d encz=%d", newSqliteSize, newEnczSize)
	}

	return nil
}
