package sqliteseal

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryReplicationBusyWaitsForApplicationWriter(t *testing.T) {
	shortTimeout := 1
	db, err := OpenWithOptions(filepath.Join(t.TempDir(), "busy-retry.db"), Options{
		Key:               "busy-retry-key",
		JournalMode:       "WAL",
		BusyTimeoutMillis: &shortTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	if _, err = db.Exec(`CREATE TABLE busy_retry(value INTEGER)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO busy_retry VALUES(1)`); err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = tx.Commit()
		close(release)
	}()

	var attempts atomic.Int64
	err = retryReplicationBusy(context.Background(), func() error {
		attempts.Add(1)
		_, execErr := db.Exec(`INSERT INTO busy_retry VALUES(2)`)
		return execErr
	})
	<-release
	if err != nil {
		t.Fatal(err)
	}
	if attempts.Load() < 2 {
		t.Fatalf("attempts=%d want at least 2", attempts.Load())
	}

	var count int
	if err = db.QueryRow(`SELECT count(*) FROM busy_retry`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows=%d want 2", count)
	}
}
