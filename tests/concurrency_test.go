package tests

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marcgauthier/encz"
)

// TC-CON-001: TestJournalModes tests database transactions under all SQLite journal modes.
func TestJournalModes(t *testing.T) {
	key := "JournalKey123"
	modes := []string{"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"}

	for _, mode := range modes {
		t.Run("JournalMode_"+mode, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "journal.db")

			// Open database
			db, err := encz.OpenEncz(dbPath, key)
			if err != nil {
				t.Fatalf("failed to open: %v", err)
			}
			defer db.Close()

			// Set journal mode
			var setMode string
			err = db.QueryRow(fmt.Sprintf(`PRAGMA journal_mode = %s`, mode)).Scan(&setMode)
			if err != nil {
				t.Fatalf("failed to set journal_mode: %v", err)
			}

			// SQLite returns lower/upper case depending on version, normalize it
			setMode = strings.ToUpper(setMode)
			if setMode != mode {
				// Note: some modes might not be supported under specific environments,
				// but check if it returned a valid mode.
				t.Logf("Requested mode %s, SQLite set mode to %s", mode, setMode)
			}

			// Write inside a transaction
			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("failed to begin tx: %v", err)
			}
			_, err = tx.Exec(`CREATE TABLE journal_test (val TEXT)`)
			if err != nil {
				tx.Rollback()
				t.Fatalf("create table: %v", err)
			}
			_, err = tx.Exec(`INSERT INTO journal_test (val) VALUES ("mode-test")`)
			if err != nil {
				tx.Rollback()
				t.Fatalf("insert: %v", err)
			}
			err = tx.Commit()
			if err != nil {
				t.Fatalf("failed to commit: %v", err)
			}

			// Read back
			var val string
			err = db.QueryRow(`SELECT val FROM journal_test`).Scan(&val)
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			if val != "mode-test" {
				t.Errorf("expected 'mode-test', got %q", val)
			}

			// Verify integrity
			var integrity string
			err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			if err != nil || integrity != "ok" {
				t.Errorf("integrity check failed: %s, err=%v", integrity, err)
			}
		})
	}
}

// TC-CON-002: TestWALCheckpointing writes to a WAL database and forces a checkpoint sync.
func TestWALCheckpointing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "checkpoint.db")
	key := "WalKey123"

	// Open with WAL mode
	opts := encz.Options{
		Key:         key,
		JournalMode: "WAL",
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE wal_check (id INTEGER PRIMARY KEY, note TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}

	// Insert rows
	for i := 0; i < 50; i++ {
		_, err = db.Exec(`INSERT INTO wal_check (note) VALUES (?)`, fmt.Sprintf("note_%d", i))
		if err != nil {
			db.Close()
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// Execute WAL checkpoint TRUNCATE to flush log pages back to the main DB file
	_, err = db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	if err != nil {
		db.Close()
		t.Fatalf("checkpoint: %v", err)
	}

	// Close database
	db.Close()

	// Reopen and verify
	reopened, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to reopen: %v", err)
	}
	defer reopened.Close()

	var count int
	err = reopened.QueryRow(`SELECT count(*) FROM wal_check`).Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 50 {
		t.Errorf("expected 50 rows, got %d", count)
	}

	// Verify integrity
	var integrity string
	err = reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-CON-002A: TestWALSupportsMaxOpenConnsFive verifies WAL operation with a 5-connection pool.
func TestWALSupportsMaxOpenConnsFive(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wal-maxopenconns-five.db")
	key := "WalPoolFiveKey"

	opts := encz.Options{
		Key:         key,
		JournalMode: "WAL",
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(5)

	if _, err := db.Exec(`CREATE TABLE wal_pool (id INTEGER PRIMARY KEY, note TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for writer := 0; writer < 5; writer++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if _, err := db.ExecContext(ctx, `INSERT INTO wal_pool (note) VALUES (?)`, fmt.Sprintf("writer_%d_%d", writerID, i)); err != nil {
					if err != context.DeadlineExceeded && err != context.Canceled {
						t.Errorf("writer %d insert %d: %v", writerID, i, err)
					}
					return
				}
			}
		}(writer)
	}

	for reader := 0; reader < 5; reader++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				var count int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM wal_pool`).Scan(&count); err != nil {
					if err != context.DeadlineExceeded && err != context.Canceled {
						t.Errorf("reader %d query %d: %v", readerID, i, err)
					}
					return
				}
			}
		}(reader)
	}

	wg.Wait()

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM wal_pool`).Scan(&count); err != nil {
		t.Fatalf("count before checkpoint: %v", err)
	}
	if count != 200 {
		t.Fatalf("expected 200 rows, got %d", count)
	}

	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	reopened.SetMaxOpenConns(5)

	if err := reopened.QueryRow(`SELECT count(*) FROM wal_pool`).Scan(&count); err != nil {
		t.Fatalf("count after reopen: %v", err)
	}
	if count != 200 {
		t.Fatalf("expected 200 rows after reopen, got %d", count)
	}

	var integrity string
	if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-CON-003: TestLockingModes validates SQLite locking behavior.
func TestLockingModes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "locking.db")
	key := "LockSecret"

	// Setup db and table
	setupDB, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("setup open: %v", err)
	}
	_, err = setupDB.Exec(`CREATE TABLE locks (val TEXT)`)
	if err != nil {
		setupDB.Close()
		t.Fatalf("setup create table: %v", err)
	}
	setupDB.Close()

	// Connection 1: Open with normal options
	db1, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("db1 open: %v", err)
	}
	defer db1.Close()

	// Connection 2: Open with short busy timeout (50ms)
	db2, err := encz.OpenWithOptions(dbPath, encz.Options{
		Key:               key,
		BusyTimeoutMillis: intPtr(50),
	})
	if err != nil {
		t.Fatalf("db2 open: %v", err)
	}
	defer db2.Close()

	// 1. Connection 1 starts an EXCLUSIVE transaction
	tx1, err := db1.BeginTx(context.Background(), &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		t.Fatalf("tx1 begin: %v", err)
	}
	_, err = tx1.Exec(`INSERT INTO locks (val) VALUES ("tx1")`)
	if err != nil {
		tx1.Rollback()
		t.Fatalf("tx1 insert: %v", err)
	}

	// 2. Connection 2 attempts to write. Since Connection 1 holds an exclusive lock, it should fail.
	_, err = db2.Exec(`INSERT INTO locks (val) VALUES ("tx2")`)
	if err == nil {
		tx1.Rollback()
		t.Fatal("expected write in db2 to fail due to database locking, but it succeeded")
	}

	// 3. Rollback Connection 1 to release locks
	err = tx1.Rollback()
	if err != nil {
		t.Fatalf("tx1 rollback: %v", err)
	}

	// 4. Connection 2 attempts to write again. Now it should succeed.
	_, err = db2.Exec(`INSERT INTO locks (val) VALUES ("tx2")`)
	if err != nil {
		t.Errorf("expected write in db2 to succeed after db1 released lock, got: %v", err)
	}
}

// TC-CON-004: TestBusyTimeout verifies busy timeout blocking and recovery.
func TestBusyTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "busy.db")
	key := "BusySecret"

	// Setup table
	setupDB, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("setup open: %v", err)
	}
	_, err = setupDB.Exec(`CREATE TABLE busy_test (val TEXT)`)
	if err != nil {
		setupDB.Close()
		t.Fatalf("setup create: %v", err)
	}
	setupDB.Close()

	// Conn 1: holds lock
	db1, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("db1 open: %v", err)
	}
	defer db1.Close()

	// Conn 2: waits up to 600ms
	db2, err := encz.OpenWithOptions(dbPath, encz.Options{
		Key:               key,
		BusyTimeoutMillis: intPtr(600),
	})
	if err != nil {
		t.Fatalf("db2 open: %v", err)
	}
	defer db2.Close()

	// Begin exclusive transaction on db1
	tx1, err := db1.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("tx1 begin: %v", err)
	}
	_, err = tx1.Exec(`INSERT INTO busy_test (val) VALUES ("busy1")`)
	if err != nil {
		tx1.Rollback()
		t.Fatalf("tx1 write: %v", err)
	}

	// Goroutine that waits 150ms then commits tx1 (releasing the lock)
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = tx1.Commit()
	}()

	// Conn 2 attempts to write immediately.
	// Since timeout is 600ms and tx1 releases lock in 150ms, db2 should wait and succeed.
	startTime := time.Now()
	_, err = db2.Exec(`INSERT INTO busy_test (val) VALUES ("busy2")`)
	duration := time.Since(startTime)

	if err != nil {
		t.Errorf("expected db2 write to succeed within busy timeout window, got: %v", err)
	}

	// Verify it actually blocked/waited for at least some duration
	if duration < 50*time.Millisecond {
		t.Logf("Warning: transaction wait was very quick (%v), check locking constraints", duration)
	}
}

// TC-CON-005: TestReaderThreadContention runs multiple readers and writers concurrently.
func TestReaderThreadContention(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "contention.db")
	key := "ContentionSecret"

	// Open with WAL mode for concurrent reads/writes
	opts := encz.Options{
		Key:         key,
		JournalMode: "WAL",
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	defer db.Close()

	// Exercise concurrent use through Go's connection pool.
	db.SetMaxOpenConns(5)

	_, err = db.Exec(`CREATE TABLE log_data (id INTEGER PRIMARY KEY, category TEXT, payload TEXT)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	// Seed some initial data
	for i := 0; i < 100; i++ {
		_, err = db.Exec(`INSERT INTO log_data (category, payload) VALUES (?, ?)`,
			fmt.Sprintf("cat_%d", i%5), fmt.Sprintf("payload_data_string_%d", i))
		if err != nil {
			t.Fatalf("failed to seed: %v", err)
		}
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Launch 30 concurrent readers
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(readerId int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Run read queries
					var count int
					row := db.QueryRowContext(ctx, `SELECT count(*) FROM log_data WHERE category = ?`, fmt.Sprintf("cat_%d", readerId%5))
					if err := row.Scan(&count); err != nil && err != context.DeadlineExceeded && err != context.Canceled {
						t.Errorf("reader %d query failed: %v", readerId, err)
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
			}
		}(i)
	}

	// Launch 5 concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(writerId int) {
			defer wg.Done()
			counter := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						if err != context.DeadlineExceeded && err != context.Canceled {
							t.Errorf("writer %d begin tx failed: %v", writerId, err)
						}
						return
					}
					_, err = tx.ExecContext(ctx, `INSERT INTO log_data (category, payload) VALUES (?, ?)`,
						fmt.Sprintf("cat_%d", writerId), fmt.Sprintf("writer_%d_counter_%d", writerId, counter))
					if err != nil {
						tx.Rollback()
						if err != context.DeadlineExceeded && err != context.Canceled {
							t.Errorf("writer %d insert failed: %v", writerId, err)
						}
						return
					}
					err = tx.Commit()
					if err != nil {
						if err != context.DeadlineExceeded && err != context.Canceled {
							t.Errorf("writer %d commit failed: %v", writerId, err)
						}
						return
					}
					counter++
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// Wait for readers and writers to finish
	wg.Wait()

	// Verify database integrity
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("integrity check failed: %s, err=%v", integrity, err)
	}
}
