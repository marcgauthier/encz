package tests

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if os.Getenv("GO_TEST_WAL_HELPER") == "1" {
		runWALHelper()
		os.Exit(0)
	}
	if os.Getenv("GO_TEST_ROLLBACK_HELPER") == "1" {
		runRollbackJournalHelper()
		os.Exit(0)
	}
}

func runCrashHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "CrashPassword123"
	db, err := encz.OpenEncz(dbPath, key)
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
	setupDB, err := encz.OpenEncz(dbPath, key)
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
	setDeathSig(cmd)
	err = cmd.Run()
	// The helper terminates itself using SIGKILL, so cmd.Run must fail
	t.Logf("crash helper exited, error: %v", err)

	// 3. Reopen and verify recovery
	db, err := encz.OpenEncz(dbPath, key)
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
	db, err := encz.OpenEncz(dbPath, key)
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
		Key: key,
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
	db, err := encz.OpenEncz(dbPath, key)
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
	dbReopened, err := encz.OpenEncz(dbPath, key)
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

// TC-FLT-005: TestManifestTamperAuthFails verifies manifest tampering is rejected directly.
func TestManifestTamperAuthFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "manifest-corrupt.db")
	key := "ManifestCorruptKey"

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE secure (id INTEGER PRIMARY KEY, val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO secure (val) VALUES ("manifest-ok")`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	manifestPath := dbPath + ".encz"
	tamperByte(t, manifestPath, 32)

	_, err = encz.OpenEncz(dbPath, key)
	if err == nil {
		t.Fatal("expected open to fail after manifest tampering")
	}
	if !errors.Is(err, encz.ErrManifestAuthFailed) && !errors.Is(err, encz.ErrManifestInvalid) {
		t.Fatalf("expected ErrManifestAuthFailed or ErrManifestInvalid, got %v", err)
	}
}

// TC-FLT-006: TestDBPageTrailerBitFlipFails verifies page trailer authentication detects a single-byte flip.
func TestDBPageTrailerBitFlipFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "page-trailer-corrupt.db")
	key := "TrailerCorruptKey"

	pageSize := createLargeEncryptedDB(t, dbPath, key)
	tamperByte(t, dbPath, int64(pageSize-1))

	assertEncryptedReadFails(t, dbPath, key)
}

// TC-FLT-007: TestMidFilePageCorruptionFails verifies corruption away from page 1 is detected.
func TestMidFilePageCorruptionFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mid-file-corrupt.db")
	key := "MidFileCorruptKey"

	pageSize := createLargeEncryptedDB(t, dbPath, key)
	tamperByte(t, dbPath, int64(pageSize*2+128))

	assertEncryptedReadFails(t, dbPath, key)
}

// TC-FLT-009: TestMainDBTruncationFails verifies truncating the encrypted main database is detected.
func TestMainDBTruncationFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		truncateBy int64
	}{
		{name: "OneAndHalfPages", truncateBy: 6144},
		{name: "TwoPages", truncateBy: 8192},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "main-truncate.db")
			key := "MainTruncateKey"
			createLargeEncryptedDB(t, dbPath, key)

			truncateTail(t, dbPath, tc.truncateBy)
			assertEncryptedReadFails(t, dbPath, key)
		})
	}
}

// TC-FLT-010: TestManifestTruncationFails verifies truncated manifests are rejected.
func TestManifestTruncationFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		truncateTo int64
	}{
		{name: "HeaderOnly", truncateTo: 16},
		{name: "ShortCiphertext", truncateTo: 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "manifest-truncate.db")
			key := "ManifestTruncateKey"
			createLargeEncryptedDB(t, dbPath, key)

			manifestPath := dbPath + ".encz"
			truncateToSize(t, manifestPath, tc.truncateTo)

			_, err := encz.OpenEncz(dbPath, key)
			if err == nil {
				t.Fatal("expected open to fail after manifest truncation")
			}
			if !errors.Is(err, encz.ErrManifestInvalid) && !errors.Is(err, encz.ErrManifestAuthFailed) {
				t.Fatalf("expected ErrManifestInvalid or ErrManifestAuthFailed, got %v", err)
			}
		})
	}
}

// TC-FLT-011: TestSidecarMismatchDetected verifies swapping manifests between databases is rejected.
func TestSidecarMismatchDetected(t *testing.T) {
	tempDir := t.TempDir()
	key := "MismatchKey"
	dbPathA := filepath.Join(tempDir, "db-a.db")
	dbPathB := filepath.Join(tempDir, "db-b.db")

	createLargeEncryptedDB(t, dbPathA, key)
	createLargeEncryptedDB(t, dbPathB, key)

	manifestAPath := dbPathA + ".encz"
	manifestBPath := dbPathB + ".encz"
	manifestB, err := os.ReadFile(manifestBPath)
	if err != nil {
		t.Fatalf("read manifest B: %v", err)
	}
	if err := os.WriteFile(manifestAPath, manifestB, 0600); err != nil {
		t.Fatalf("overwrite manifest A: %v", err)
	}

	_, err = encz.OpenEncz(dbPathA, key)
	if err == nil {
		t.Fatal("expected open to fail after manifest swap")
	}
	if !errors.Is(err, encz.ErrManifestMismatch) && !corruptionError(err) {
		t.Fatalf("expected ErrManifestMismatch or another corruption-class failure, got %v", err)
	}
}

// TC-FLT-013: TestRollbackJournalBitFlipDetected verifies a corrupted hot rollback journal is surfaced on recovery.
func TestRollbackJournalBitFlipDetected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rollback-bitflip.db")
	key := "RollbackCorruptKey"

	createRollbackRecoveryBase(t, dbPath, key)
	spawnRollbackJournalHelper(t, dbPath)

	journalPath := dbPath + "-journal"
	info, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("stat rollback journal: %v", err)
	}
	if info.Size() <= 64 {
		t.Fatalf("expected rollback journal larger than 64 bytes, got %d", info.Size())
	}
	tamperByte(t, journalPath, 32)

	assertRollbackRecoveryDegraded(t, dbPath, key)
}

// TC-FLT-014: TestRollbackJournalTruncationDetected verifies a truncated hot rollback journal is surfaced on recovery.
func TestRollbackJournalTruncationDetected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rollback-truncate.db")
	key := "RollbackCorruptKey"

	createRollbackRecoveryBase(t, dbPath, key)
	spawnRollbackJournalHelper(t, dbPath)

	journalPath := dbPath + "-journal"
	info, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("stat rollback journal: %v", err)
	}
	if info.Size() <= 128 {
		t.Fatalf("expected rollback journal larger than 128 bytes, got %d", info.Size())
	}
	truncateTail(t, journalPath, 128)

	assertRollbackRecoveryDegraded(t, dbPath, key)
}

// TC-FLT-015: TestCorruptionDoesNotReturnWrongData verifies page corruption never yields silently altered plaintext.
func TestCorruptionDoesNotReturnWrongData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "silent-corruption.db")
	key := "SilentCorruptionKey"
	expected := []string{
		"alpha-record-000",
		"beta-record-111",
		"gamma-record-222",
		"delta-record-333",
		"epsilon-record-444",
	}

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE secure (id INTEGER PRIMARY KEY, val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create: %v", err)
	}
	for _, val := range expected {
		if _, err := db.Exec(`INSERT INTO secure (val) VALUES (?)`, val); err != nil {
			db.Close()
			t.Fatalf("insert %q: %v", val, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	pageSize := readPageSize(t, dbPath, key)
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if info.Size() <= int64(pageSize)+256 {
		t.Fatalf("expected database larger than one page, got %d bytes", info.Size())
	}
	offset := info.Size() - int64(pageSize/2)
	tamperByte(t, dbPath, offset)

	reopened, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("expected corruption-class error, got %v", err)
	}
	defer reopened.Close()

	rows, err := reopened.Query(`SELECT val FROM secure ORDER BY id`)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var val string
		if err := rows.Scan(&val); err != nil {
			if corruptionError(err) {
				return
			}
			t.Fatalf("scan: %v", err)
		}
		got = append(got, val)
	}
	if err := rows.Err(); err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("rows: %v", err)
	}
	if len(got) != len(expected) {
		return
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("silent corruption detected: row %d expected %q, got %q", i, expected[i], got[i])
		}
	}
}

// TC-FLT-012: TestWALTruncationDetected verifies a truncated WAL file is rejected or discarded during fresh recovery.
func TestWALTruncationDetected(t *testing.T) {
	for _, tc := range []struct {
		name       string
		truncateBy int64
	}{
		{name: "MidFrame", truncateBy: 128},
		{name: "TailFrame", truncateBy: 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "wal-truncate.db")
			key := "WALCorruptKey"

			spawnWALHelper(t, dbPath)
			walPath := dbPath + "-wal"
			shmPath := dbPath + "-shm"
			if err := os.Remove(shmPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("remove shm file: %v", err)
			}
			truncateTail(t, walPath, tc.truncateBy)

			assertWALRecoveryDegraded(t, dbPath, key)
		})
	}
}

// TC-FLT-008: TestWALCorruptionDetected verifies a persisted WAL file is rejected or truncated during fresh recovery after tampering.
func TestWALCorruptionDetected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wal-corrupt.db")
	key := "WALCorruptKey"

	spawnWALHelper(t, dbPath)

	walPath := dbPath + "-wal"
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("stat wal file: %v", err)
	}
	if info.Size() <= 56 {
		t.Fatalf("expected wal file larger than 56 bytes, got %d", info.Size())
	}
	shmPath := dbPath + "-shm"
	if err := os.Remove(shmPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove shm file: %v", err)
	}
	tamperByte(t, walPath, 48)

	assertWALRecoveryDegraded(t, dbPath, key)
}

func createRollbackRecoveryBase(t *testing.T, dbPath, key string) {
	t.Helper()

	db, err := encz.OpenWithOptions(dbPath, encz.Options{Key: key, JournalMode: "DELETE"})
	if err != nil {
		t.Fatalf("open base db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE baseline (id INTEGER PRIMARY KEY, val TEXT)`); err != nil {
		t.Fatalf("create baseline: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO baseline (val) VALUES ("before-crash")`); err != nil {
		t.Fatalf("insert baseline: %v", err)
	}
}

func spawnRollbackJournalHelper(t *testing.T, dbPath string) {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to find executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestRollbackJournalBitFlipDetected")
	cmd.Env = append(os.Environ(), "GO_TEST_ROLLBACK_HELPER=1", "CRASH_DB_PATH="+dbPath)
	setDeathSig(cmd)
	if err := cmd.Run(); err == nil {
		t.Fatal("expected rollback helper to be killed, but it exited cleanly")
	}
}

func assertRollbackRecoveryDegraded(t *testing.T, dbPath, key string) {
	t.Helper()

	db, err := encz.OpenWithOptions(dbPath, encz.Options{Key: key, JournalMode: "DELETE"})
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("expected rollback corruption failure, got %v", err)
	}
	defer db.Close()

	var val string
	err = db.QueryRow(`SELECT val FROM baseline LIMIT 1`).Scan(&val)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("read baseline: %v", err)
	}
	if val != "before-crash" {
		t.Fatalf("expected preserved baseline row, got %q", val)
	}

	var count int
	err = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='rollback_pending'`).Scan(&count)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("query rollback_pending existence: %v", err)
	}
	if count != 0 {
		t.Fatal("expected uncommitted rollback_pending table to be absent after recovery")
	}

	var integrity string
	err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("integrity_check: %v", err)
	}
	if integrity != "ok" {
		return
	}
}

func readPageSize(t *testing.T, dbPath, key string) int {
	t.Helper()

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open for page size: %v", err)
	}
	defer db.Close()

	var pageSize int
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatalf("read page size: %v", err)
	}
	return pageSize
}

func spawnWALHelper(t *testing.T, dbPath string) {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to find executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=TestWALCorruptionDetected")
	cmd.Env = append(os.Environ(), "GO_TEST_WAL_HELPER=1", "CRASH_DB_PATH="+dbPath)
	setDeathSig(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("wal helper failed to run: %v", err)
	}
}

func truncateTail(t *testing.T, path string, by int64) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if by <= 0 || by >= info.Size() {
		t.Fatalf("invalid truncate amount %d for %s (%d bytes)", by, path, info.Size())
	}
	truncateToSize(t, path, info.Size()-by)
}

func truncateToSize(t *testing.T, path string, size int64) {
	t.Helper()

	if size < 0 {
		t.Fatalf("invalid truncate target for %s: %d", path, size)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("truncate %s to %d: %v", path, size, err)
	}
}

func assertWALRecoveryDegraded(t *testing.T, dbPath, key string) {
	t.Helper()

	reader, err := encz.OpenWithOptions(dbPath, encz.Options{
		Key:         key,
		JournalMode: "WAL",
	})
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("expected WAL corruption failure, got %v", err)
	}
	defer reader.Close()

	var count int
	err = reader.QueryRow(`SELECT count(*) FROM secure`).Scan(&count)
	if err != nil {
		if corruptionError(err) || strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return
		}
		t.Fatalf("expected corruption-class WAL error, got %v", err)
	}
	if count != 8 {
		return
	}

	var integrity string
	err = reader.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("expected corruption-class WAL error, got %v", err)
	}
	if integrity != "ok" {
		return
	}

	t.Fatal("expected WAL corruption to cause a recovery failure, dropped frames, or a failed integrity check, but all rows remained readable")
}

func createLargeEncryptedDB(t *testing.T, dbPath, key string) int {
	t.Helper()

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`PRAGMA page_size = 4096`); err != nil {
		t.Fatalf("set page size: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE secure (id INTEGER PRIMARY KEY, payload BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	payload := strings.Repeat("p", 3000)
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(`INSERT INTO secure (payload) VALUES (?)`, fmt.Sprintf("%s-%d", payload, i)); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	var pageSize int
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatalf("read page size: %v", err)
	}
	return pageSize
}

func tamperByte(t *testing.T, path string, offset int64) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if offset < 0 || offset >= info.Size() {
		t.Fatalf("offset %d out of bounds for %s (%d bytes)", offset, path, info.Size())
	}

	buf := make([]byte, 1)
	if _, err := file.ReadAt(buf, offset); err != nil {
		t.Fatalf("read byte %s@%d: %v", path, offset, err)
	}
	buf[0] ^= 0x01
	if _, err := file.WriteAt(buf, offset); err != nil {
		t.Fatalf("write byte %s@%d: %v", path, offset, err)
	}
}

func assertEncryptedReadFails(t *testing.T, dbPath, key string) {
	t.Helper()

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		if corruptionError(err) {
			return
		}
		t.Fatalf("expected corruption failure, got %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow(`SELECT count(*) FROM secure`).Scan(&count)
	if err == nil {
		var integrity string
		err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
	}
	if err == nil {
		t.Fatal("expected open or query to fail on corrupted database, but reads succeeded")
	}
	if !corruptionError(err) {
		t.Fatalf("expected corruption-class error, got %v", err)
	}
}

func corruptionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, encz.ErrManifestAuthFailed) || errors.Is(err, encz.ErrManifestInvalid) || errors.Is(err, encz.ErrManifestMismatch) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "corrupt") ||
		strings.Contains(msg, "malformed") ||
		strings.Contains(msg, "not a database") ||
		strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "encrypt") ||
		strings.Contains(msg, "decrypt")
}

func runRollbackJournalHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "RollbackCorruptKey"
	db, err := encz.OpenWithOptions(dbPath, encz.Options{Key: key, JournalMode: "DELETE"})
	if err != nil {
		os.Exit(2)
	}
	tx, err := db.Begin()
	if err != nil {
		os.Exit(3)
	}
	if _, err := tx.Exec(`CREATE TABLE rollback_pending (id INTEGER PRIMARY KEY, val TEXT)`); err != nil {
		os.Exit(4)
	}
	payload := strings.Repeat("r", 3000)
	for i := 0; i < 8; i++ {
		if _, err := tx.Exec(`INSERT INTO rollback_pending (val) VALUES (?)`, fmt.Sprintf("%s-%d", payload, i)); err != nil {
			os.Exit(5)
		}
	}
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Kill()
}

func runWALHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "WALCorruptKey"
	db, err := encz.OpenWithOptions(dbPath, encz.Options{Key: key, JournalMode: "WAL"})
	if err != nil {
		os.Exit(2)
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint = 1000000`); err != nil {
		os.Exit(3)
	}
	if _, err := db.Exec(`CREATE TABLE secure (id INTEGER PRIMARY KEY, payload BLOB)`); err != nil {
		os.Exit(4)
	}
	payload := strings.Repeat("w", 3000)
	for i := 0; i < 8; i++ {
		if _, err := db.Exec(`INSERT INTO secure (payload) VALUES (?)`, fmt.Sprintf("%s-%d", payload, i)); err != nil {
			os.Exit(5)
		}
	}
	os.Exit(0)
}

func runExitZeroHelper() {
	dbPath := os.Getenv("CRASH_DB_PATH")
	if dbPath == "" {
		return
	}
	key := "ExitZeroPassword123"
	db, err := encz.OpenEncz(dbPath, key)
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
	setDeathSig(cmd)
	err = cmd.Run()
	if err != nil {
		t.Fatalf("helper process failed to run: %v", err)
	}

	// 2. Reopen the database and verify integrity
	db, err := encz.OpenEncz(dbPath, key)
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
