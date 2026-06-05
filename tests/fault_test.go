package tests

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/encz"
)

func init() {
	if os.Getenv("GO_TEST_CRASH_HELPER") == "1" {
		runCrashHelper()
		os.Exit(0)
	}
	if os.Getenv("GO_TEST_EXIT_ZERO_HELPER") == "1" {
		runExitZeroHelper()
		os.Exit(0)
	}
}

func runCrashHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "CrashPassword123"
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		os.Exit(2)
	}
	tx, err := db.Begin()
	if err != nil {
		os.Exit(3)
	}
	_, err = tx.Exec(`CREATE TABLE crash_data (val TEXT)`)
	if err != nil {
		os.Exit(4)
	}
	for i := 0; i < 100; i++ {
		_, err = tx.Exec(`INSERT INTO crash_data VALUES (?)`, fmt.Sprintf("crash_%d", i))
		if err != nil {
			os.Exit(5)
		}
	}
	// Kill ourselves instantly (SIGKILL simulation) to leave a hot rollback journal
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Kill()
}

// TC-FLT-001: TestSimulateNoDiskSpace verifies that SQLite database rolls back gracefully when max page count is hit.
func TestSimulateNoDiskSpace(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE fill (val TEXT)`)
		if err != nil {
			t.Fatalf("create table: %v", err)
		}

		// Restrict database page limit to force SQLITE_FULL
		_, err = db.Exec(`PRAGMA max_page_count = 5`)
		if err != nil {
			t.Fatalf("set max page count: %v", err)
		}

		// Try to write substantial data to exceed the page limit
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		stmt, err := tx.Prepare(`INSERT INTO fill (val) VALUES (?)`)
		if err != nil {
			tx.Rollback()
			t.Fatalf("prepare: %v", err)
		}

		failed := false
		largeString := "Exceeding the page size limit to force a database full error. "
		for i := 0; i < 1000; i++ {
			_, err = stmt.Exec(largeString)
			if err != nil {
				failed = true
				break
			}
		}
		stmt.Close()

		if !failed {
			tx.Commit()
			t.Error("expected write to fail with SQLITE_FULL due to max_page_count limit, but it succeeded")
			return
		}

		// Rollback transaction (discard error as SQLite may have already aborted the transaction internally)
		_ = tx.Rollback()

		// Verify database remains completely integral and readable
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
		if err != nil || integrity != "ok" {
			t.Errorf("integrity check failed after disk full rollback: %s, err=%v", integrity, err)
		}
	})
}

// TC-FLT-002: TestCrashRecovery tests recovery from a hard process termination (SIGKILL) mid-transaction.
func TestCrashRecovery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "crash.db")
	key := "CrashPassword123"

	// 1. Setup the database file with initial schema
	setupDB, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("failed to setup: %v", err)
	}
	_, err = setupDB.Exec(`CREATE TABLE initial (val TEXT)`)
	if err != nil {
		setupDB.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = setupDB.Exec(`INSERT INTO initial VALUES ("before-crash")`)
	if err != nil {
		setupDB.Close()
		t.Fatalf("insert initial: %v", err)
	}
	setupDB.Close()

	// 2. Spawn crash helper subprocess
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to find executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestCrashRecovery")
	cmd.Env = append(os.Environ(), "GO_TEST_CRASH_HELPER=1", "CRASH_DB_PATH="+dbPath)
	err = cmd.Run()
	// The helper terminates itself using SIGKILL, so cmd.Run must fail
	t.Logf("crash helper exited, error: %v", err)

	// 3. Reopen and verify recovery
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("reopen after crash failed: %v", err)
	}
	defer db.Close()

	// Verify the pre-crash data is intact
	var val string
	err = db.QueryRow(`SELECT val FROM initial`).Scan(&val)
	if err != nil {
		t.Fatalf("failed to read initial data: %v", err)
	}
	if val != "before-crash" {
		t.Errorf("expected 'before-crash', got %q", val)
	}

	// Verify that any uncommitted tables from the crash helper are rolled back (they should not exist)
	var count int
	err = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='crash_data'`).Scan(&count)
	if err != nil {
		t.Fatalf("query catalog failed: %v", err)
	}
	if count != 0 {
		t.Error("expected table 'crash_data' to be rolled back and absent, but it exists")
	}

	// Verify database integrity check
	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Errorf("post-crash database integrity check failed: %s, err=%v", integrity, err)
	}
}

// TC-FLT-003: TestReadOnlyFileSystem verifies read-only access behavior on write-protected files.
func TestReadOnlyFileSystem(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "readonly.db")
	key := "ReadOnlyKey"

	// 1. Create and write initial table
	db, err := encz.OpenEncz(dbPath, key, "none")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE read_test (val TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO read_test VALUES ("accessible")`)
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	// 2. Chmod the file to read-only (0400)
	err = os.Chmod(dbPath, 0400)
	if err != nil {
		t.Fatalf("failed to chmod read-only: %v", err)
	}
	t.Cleanup(func() {
		// Restore permissions at test end so cleanup TempDir can delete it
		_ = os.Chmod(dbPath, 0600)
	})

	// 3. Attempt to open in read-only mode using URI parameters
	opts := encz.Options{
		Key:         key,
		Compression: "none",
		URIParameters: map[string]string{
			"mode": "ro",
		},
	}
	dbRO, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open read-only DB: %v", err)
	}
	defer dbRO.Close()

	// Read should succeed
	var val string
	err = dbRO.QueryRow(`SELECT val FROM read_test`).Scan(&val)
	if err != nil {
		t.Fatalf("read failed on read-only database: %v", err)
	}
	if val != "accessible" {
		t.Errorf("expected 'accessible', got %q", val)
	}

	// Write should fail
	_, err = dbRO.Exec(`INSERT INTO read_test VALUES ("blocked")`)
	if err == nil {
		t.Error("expected write operation to fail on read-only database, but it succeeded")
	}
}

// TC-FLT-004: TestCorruptionTampering verifies that tampering with the encrypted file is caught.
func TestCorruptionTampering(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "corrupt.db")
	key := "CorruptKey"

	// 1. Create and write initial data
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE secure (val TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create: %v", err)
	}
	_, err = db.Exec(`INSERT INTO secure VALUES ("secure-value")`)
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	// 2. Open file directly and overwrite page data with garbage
	file, err := os.OpenFile(dbPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("failed to open file directly: %v", err)
	}

	// Overwrite both header Slot 0 and Slot 1 (first 1024 bytes of the file).
	// Because the VFS is append-only, page data shifts offsets on each commit,
	// but the header slots are always updated in-place at offset 0 and 512.
	garbage := make([]byte, 1024)
	_, err = rand.Read(garbage)
	if err != nil {
		file.Close()
		t.Fatalf("failed to generate random garbage: %v", err)
	}

	_, err = file.WriteAt(garbage, 0)
	file.Close()
	if err != nil {
		t.Fatalf("failed to write garbage: %v", err)
	}

	// 3. Attempt to open and read from the tampered database.
	// Either the header load (OpenEncz/Ping) must fail, or the subsequent query must fail.
	dbReopened, err := encz.OpenEncz(dbPath, key, "zstd")
	if err == nil {
		defer dbReopened.Close()
		// Try to query data
		var val string
		err = dbReopened.QueryRow(`SELECT val FROM secure`).Scan(&val)
		if err == nil {
			t.Error("expected database open or query to fail on corrupted database, but both succeeded!")
		}
	}
}

func runExitZeroHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "ExitZeroPassword123"
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		os.Exit(2)
	}
	_, err = db.Exec(`CREATE TABLE exit_zero_data (id INTEGER PRIMARY KEY, val TEXT)`)
	if err != nil {
		os.Exit(3)
	}
	tx, err := db.Begin()
	if err != nil {
		os.Exit(4)
	}
	for i := 0; i < 1000; i++ {
		_, err = tx.Exec(`INSERT INTO exit_zero_data (val) VALUES (?)`, fmt.Sprintf("val_%d", i))
		if err != nil {
			tx.Rollback()
			os.Exit(5)
		}
	}
	err = tx.Commit()
	if err != nil {
		os.Exit(6)
	}
	os.Exit(0)
}

// TestAbruptExitGrace validates that calling os.Exit(0) mid-process without closing the DB
// does not corrupt the database and all committed transaction data is preserved.
func TestAbruptExitGrace(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "exit_zero.db")
	key := "ExitZeroPassword123"

	// 1. Spawn the helper process to insert 1000 items and call os.Exit(0)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to find executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestAbruptExitGrace")
	cmd.Env = append(os.Environ(), "GO_TEST_EXIT_ZERO_HELPER=1", "CRASH_DB_PATH="+dbPath)
	err = cmd.Run()
	if err != nil {
		t.Fatalf("helper process failed to run: %v", err)
	}

	// 2. Reopen the database and verify integrity
	db, err := encz.OpenEncz(dbPath, key, "zstd")
	if err != nil {
		t.Fatalf("failed to reopen DB after exit(0): %v", err)
	}
	defer db.Close()

	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil || integrity != "ok" {
		t.Fatalf("integrity check failed: %s, err=%v", integrity, err)
	}

	// Verify all 1000 rows are present
	var count int
	err = db.QueryRow(`SELECT count(*) FROM exit_zero_data`).Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1000 {
		t.Errorf("expected 1000 rows, got %d", count)
	}
}
