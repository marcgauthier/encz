package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
)

func TestPublicAPICertification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping encrypted API certification in short mode")
	}
	dir := t.TempDir()
	logger, err := newLiveLogger(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	apiDir := dir
	if err := certifyPublicAPI(apiDir, "integration-master-key-2026", logger); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedOracleWorkload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping encrypted workload in short mode")
	}
	dir := t.TempDir()
	logger, err := newLiveLogger(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	ctx, cancel := context.WithCancelCause(context.Background())
	cfg := testConfig(dir)
	r := newRunner(ctx, cancel, cfg, logger)
	if err := r.initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })

	tokens := make(chan struct{}, 100)
	for i := 0; i < 100; i++ {
		tokens <- struct{}{}
	}
	close(tokens)
	for worker := 0; worker < 2; worker++ {
		r.workerWG.Add(1)
		go r.worker(worker, tokens)
	}
	r.workerWG.Wait()
	if cause := context.Cause(ctx); cause != nil {
		t.Fatal(cause)
	}
	if r.stats.operations() == 0 {
		t.Fatal("workload executed no operations")
	}
	if err := r.finalAudit(); err != nil {
		t.Fatal(err)
	}
}

func testConfig(dir string) config {
	return config{
		rawConfig: rawConfig{
			Workers:             2,
			OperationsPerSecond: 100,
			RowsPerTable:        25,
			InitialRowsPerTable: 2,
			Seed:                77,
			DatabaseFile:        "test.db",
			MasterKey:           "bounded-workload-master-key",
			Cipher:              string(sqliteseal.CipherAES256GCM),
			JournalMode:         "WAL",
			Workload: workloadConfig{
				InsertPct: 20, UpdatePct: 25, SelectPct: 35, JoinPct: 20,
			},
		},
		BusyTimeoutValue: 2 * time.Second,
		CacheBytes:       8 << 20,
		ProgressEvery:    time.Second,
		AuditEvery:       time.Hour,
		ReopenEvery:      time.Hour,
		BackupEvery:      time.Hour,
		RekeyEvery:       time.Hour,
		CipherValue:      sqliteseal.CipherAES256GCM,
		RunDir:           dir,
		DBPath:           filepath.Join(dir, "test.db"),
		LogPath:          filepath.Join(dir, "test.log"),
	}
}
