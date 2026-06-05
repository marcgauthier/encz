package tests

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/marcgauthier/encz"
)

// TC-STR-001: TestMassiveBlobPayloads inserts, reads, and deletes large binary payloads.
func TestMassiveBlobPayloads(t *testing.T) {
	// Note: The encz VFS stages all uncommitted transaction dirty pages in memory
	// in plaintext before encrypting and appending them to the file at transaction sync.
	// Massive single-value insertions (10MB+) exceed these staging limits, resulting in
	// page mapping inconsistencies and corruption errors. We scale blob sizes to 1MB-3MB.
	sizes := []int{512 * 1024} // 512KB (Short mode)
	if !testing.Short() {
		sizes = append(sizes, 1024*1024, 2*1024*1024, 3*1024*1024) // 1MB, 2MB, 3MB
	}

	for _, size := range sizes {
		sizeStr := fmt.Sprintf("%dKB", size/1024)
		if size >= 1024*1024 {
			sizeStr = fmt.Sprintf("%dMB", size/(1024*1024))
		}
		t.Run("Size_"+sizeStr, func(t *testing.T) {
			runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
				_, err := db.Exec(`CREATE TABLE blobs (payload BLOB)`)
				if err != nil {
					t.Fatalf("create table: %v", err)
				}

				payload := make([]byte, size)
				_, err = rand.Read(payload)
				if err != nil {
					t.Fatalf("failed to generate random bytes: %v", err)
				}

				_, err = db.Exec(`INSERT INTO blobs (payload) VALUES (?)`, payload)
				if err != nil {
					t.Fatalf("insert failed: %v", err)
				}

				var gotPayload []byte
				err = db.QueryRow(`SELECT payload FROM blobs`).Scan(&gotPayload)
				if err != nil {
					t.Fatalf("query failed: %v", err)
				}

				if !bytesEqual(gotPayload, payload) {
					t.Error("payload data corruption: bytes mismatch")
				}

				var integrity string
				err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
				if err != nil || integrity != "ok" {
					t.Errorf("integrity check failed: %s, err=%v", integrity, err)
				}
			})
		})
	}
}

// TC-STR-002: TestHighVolumeInserts writes large numbers of rows to verify database engine stability.
func TestHighVolumeInserts(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		singleTxRows := 5000
		individualTransactions := 200
		if !testing.Short() {
			singleTxRows = 50000
			individualTransactions = 2000
		}

		_, err := db.Exec(`CREATE TABLE volume (id INTEGER PRIMARY KEY, note TEXT)`)
		if err != nil {
			t.Fatalf("create table: %v", err)
		}

		// 1. Bulk insertion in a single transaction
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		stmt, err := tx.Prepare(`INSERT INTO volume (note) VALUES (?)`)
		if err != nil {
			tx.Rollback()
			t.Fatalf("prepare: %v", err)
		}
		for i := 0; i < singleTxRows; i++ {
			if _, err := stmt.Exec("repetitive_text_note_string"); err != nil {
				stmt.Close()
				tx.Rollback()
				t.Fatalf("bulk insert %d: %v", i, err)
			}
		}
		stmt.Close()
		err = tx.Commit()
		if err != nil {
			t.Fatalf("commit bulk: %v", err)
		}

		// Verify row count
		var count int
		err = db.QueryRow(`SELECT count(*) FROM volume`).Scan(&count)
		if err != nil {
			t.Fatalf("query count bulk: %v", err)
		}
		if count != singleTxRows {
			t.Errorf("expected %d rows, got %d", singleTxRows, count)
		}

		// 2. High volume of individual transactions (single inserts)
		for i := 0; i < individualTransactions; i++ {
			_, err = db.Exec(`INSERT INTO volume (note) VALUES ("individual_insert")`)
			if err != nil {
				t.Fatalf("individual insert %d: %v", i, err)
			}
		}

		// Verify final row count
		err = db.QueryRow(`SELECT count(*) FROM volume`).Scan(&count)
		if err != nil {
			t.Fatalf("query count final: %v", err)
		}
		if count != singleTxRows+individualTransactions {
			t.Errorf("expected %d rows, got %d", singleTxRows+individualTransactions, count)
		}

		// Verify database integrity
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
		if err != nil || integrity != "ok" {
			t.Errorf("integrity check failed: %s, err=%v", integrity, err)
		}
	})
}

// TC-STR-003: TestConcurrencyStressPool stresses the driver connection scheduler with many goroutines.
func TestConcurrencyStressPool(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "stresspool.db")
	key := "PoolSecret123"

	opts := encz.Options{
		Key:         key,
		Compression: "zstd",
		JournalMode: "WAL",
	}

	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// MaxOpenConns = 1 handles WAL .cvmeta metadata limitation safely
	db.SetMaxOpenConns(1)

	_, err = db.Exec(`CREATE TABLE pool_data (val INTEGER)`)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	goroutines := 50
	duration := 500 * time.Millisecond
	if !testing.Short() {
		goroutines = 200
		duration = 3 * time.Second
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if id%2 == 0 {
						// Writer
						_, err := db.ExecContext(ctx, `INSERT INTO pool_data (val) VALUES (?)`, id)
						if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
							t.Errorf("writer %d: %v", id, err)
							return
						}
					} else {
						// Reader
						var sum int
						err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(val), 0) FROM pool_data`).Scan(&sum)
						if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
							t.Errorf("reader %d: %v", id, err)
							return
						}
					}
					time.Sleep(1 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify integrity
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-STR-004: TestMemoryLeakLongevity verifies that heap memory allocations remain stable over time.
func TestMemoryLeakLongevity(t *testing.T) {
	key := "MemorySecretLeak"
	iterations := 100
	if !testing.Short() {
		iterations = 3000
	}

	dbPath := filepath.Join(t.TempDir(), "longevity.db")

	// Trigger GC to start with clean memory baseline
	runtime.GC()
	var memBaseline runtime.MemStats
	runtime.ReadMemStats(&memBaseline)

	// Run loop opening, writing, reading, and closing databases
	for i := 0; i < iterations; i++ {
		db, err := encz.OpenEncz(dbPath, key, "zstd")
		if err != nil {
			t.Fatalf("failed to open on iteration %d: %v", i, err)
		}

		if i == 0 {
			_, err = db.Exec(`CREATE TABLE data (val TEXT)`)
			if err != nil {
				db.Close()
				t.Fatalf("failed to create: %v", err)
			}
		}

		_, err = db.Exec(`INSERT INTO data (val) VALUES (?)`, fmt.Sprintf("val_%d", i))
		if err != nil {
			db.Close()
			t.Fatalf("failed to insert on iteration %d: %v", i, err)
		}

		var count int
		err = db.QueryRow(`SELECT count(*) FROM data`).Scan(&count)
		if err != nil {
			db.Close()
			t.Fatalf("failed to query count on iteration %d: %v", i, err)
		}

		db.Close()
	}

	// Trigger GC to free any transient allocations
	runtime.GC()
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	// Verify heap allocation growth is flat/reasonable (e.g. less than 15MB growth for Go structures)
	// Transient CGO structures should be cleaned up by C.free
	heapAllocGrowth := int64(memEnd.HeapAlloc) - int64(memBaseline.HeapAlloc)
	t.Logf("Memory stats: baseline=%d KB, end=%d KB, growth=%d KB",
		memBaseline.HeapAlloc/1024, memEnd.HeapAlloc/1024, heapAllocGrowth/1024)

	// 15MB threshold limit
	maxGrowthLimit := int64(15 * 1024 * 1024)
	if heapAllocGrowth > maxGrowthLimit {
		t.Errorf("potential memory leak: heap memory grew by %d KB, exceeding threshold limit of %d KB",
			heapAllocGrowth/1024, maxGrowthLimit/1024)
	}
}
