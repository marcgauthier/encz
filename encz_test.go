package encz

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestOpenWithOptionsRequiresKey(t *testing.T) {
	_, err := OpenWithOptions(filepath.Join(t.TempDir(), "encz.db"), Options{})
	if err == nil {
		t.Fatal("expected OpenWithOptions to reject missing key")
	}
	if err != ErrKeyRequired {
		t.Fatalf("expected ErrKeyRequired, got %v", err)
	}
}

func TestBuildEnczDSN(t *testing.T) {
	dsn := BuildEnczDSN("users.db", "secret")
	expected := "file:users.db?crypto_key=secret&vfs=encz"
	if dsn != expected {
		t.Fatalf("unexpected dsn %q", dsn)
	}
}

func TestOpenEnczSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "encz.db")

	db, err := OpenEncz(dbPath, "Password123")
	if err != nil {
		t.Fatalf("OpenEncz: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO items(name) VALUES (?)`, "secret"); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close after write: %v", err)
	}

	reopened, err := OpenEncz(dbPath, "Password123")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var got string
	if err := reopened.QueryRow(`SELECT name FROM items WHERE id = 1`).Scan(&got); err != nil {
		t.Fatalf("query after reopen: %v", err)
	}
	if got != "secret" {
		t.Fatalf("unexpected reopened value %q", got)
	}
}

func TestManifestCreatedAndOpaque(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "manifest.db")
	masterKey := "ManifestMasterPass"

	db, err := OpenEncz(dbPath, masterKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE manifest_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	manifestPath := dbPath + ".encz"
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if len(manifest) == 0 {
		t.Fatal("expected manifest data")
	}
	if !bytes.HasPrefix(manifest, []byte(manifestMagic)) {
		t.Fatalf("expected manifest magic prefix %q", manifestMagic)
	}
	if bytes.Contains(manifest, []byte(masterKey)) {
		t.Fatal("manifest should not contain the master key in plaintext")
	}
	if bytes.Contains(manifest, []byte("active_dek_hex")) {
		t.Fatal("manifest should not expose JSON payload in plaintext")
	}
}

func TestMissingManifestFails(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing-manifest.db")
	db, err := OpenEncz(dbPath, "MissingManifestPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE missing_manifest_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.Remove(dbPath + ".encz"); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	if _, err := OpenEncz(dbPath, "MissingManifestPass"); !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("expected ErrManifestMissing, got %v", err)
	}
}

func TestOpenPlainSQLiteFailsWithMissingManifest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "plain.db")
	plain, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open plain db: %v", err)
	}
	if _, err := plain.Exec(`CREATE TABLE plain_data (val TEXT)`); err != nil {
		plain.Close()
		t.Fatalf("create plain table: %v", err)
	}
	if err := plain.Close(); err != nil {
		t.Fatalf("close plain db: %v", err)
	}

	if _, err := OpenEncz(dbPath, "Password123"); !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("expected ErrManifestMissing, got %v", err)
	}
}

func TestReKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rekey.db")
	oldKey := "OldManifestMasterPass"
	newKey := "NewManifestMasterPass"

	db, err := OpenEncz(dbPath, oldKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE rekey_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO rekey_test (val) VALUES ('ok')`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.ReKey(oldKey, newKey); err != nil {
		db.Close()
		t.Fatalf("ReKey: %v", err)
	}

	var val string
	if err := db.QueryRow(`SELECT val FROM rekey_test LIMIT 1`).Scan(&val); err != nil {
		db.Close()
		t.Fatalf("query after rekey: %v", err)
	}
	if val != "ok" {
		db.Close()
		t.Fatalf("unexpected value %q", val)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := OpenEncz(dbPath, oldKey); err == nil {
		t.Fatal("expected old manifest key to fail after rotation")
	}
	reopened, err := OpenEncz(dbPath, newKey)
	if err != nil {
		t.Fatalf("reopen with new key: %v", err)
	}
	defer reopened.Close()
	if err := reopened.QueryRow(`SELECT val FROM rekey_test LIMIT 1`).Scan(&val); err != nil {
		t.Fatalf("query after reopen: %v", err)
	}
	if val != "ok" {
		t.Fatalf("unexpected value %q", val)
	}
}

func TestSetRotationPolicyPersists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	db, err := OpenEncz(dbPath, "RotationPolicyPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	policy := RotationPolicy{KEKRotationDays: 21, AutoRewrap: false, KeepPreviousKey: false}
	if err := db.SetRotationPolicy(policy); err != nil {
		db.Close()
		t.Fatalf("SetRotationPolicy: %v", err)
	}
	status, err := db.RotationStatus()
	if err != nil {
		db.Close()
		t.Fatalf("RotationStatus: %v", err)
	}
	if status.KEKRotationDays != 21 || status.AutoRewrap || status.KeepPreviousKey {
		db.Close()
		t.Fatalf("unexpected status after update: %+v", status)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenEncz(dbPath, "RotationPolicyPass")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	status, err = reopened.RotationStatus()
	if err != nil {
		t.Fatalf("RotationStatus after reopen: %v", err)
	}
	if status.KEKRotationDays != 21 {
		t.Fatalf("expected persisted KEKRotationDays=21, got %d", status.KEKRotationDays)
	}
	if status.AutoRewrap {
		t.Fatal("expected AutoRewrap to remain disabled")
	}
	if status.KeepPreviousKey {
		t.Fatal("expected KeepPreviousKey to remain disabled")
	}
}

func TestHandleMethodsFailAfterClose(t *testing.T) {
	db, err := OpenEncz(filepath.Join(t.TempDir(), "closed.db"), "ClosedPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := db.SetRotationPolicy(RotationPolicy{KEKRotationDays: 10}); !errors.Is(err, ErrDBClosed) {
		t.Fatalf("expected ErrDBClosed from SetRotationPolicy, got %v", err)
	}
	if err := db.ReKey("ClosedPass", "OtherPass"); !errors.Is(err, ErrDBClosed) {
		t.Fatalf("expected ErrDBClosed from ReKey, got %v", err)
	}
	if _, err := db.RotationStatus(); !errors.Is(err, ErrDBClosed) {
		t.Fatalf("expected ErrDBClosed from RotationStatus, got %v", err)
	}
}

func TestBackupCreatesArchiveAndRestores(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		compression BackupCompression
		method      uint16
	}{
		{name: "deflate", compression: BackupCompressionDeflate, method: zip.Deflate},
		{name: "store", compression: BackupCompressionStore, method: zip.Store},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			dbPath := filepath.Join(tempDir, "backup-source.db")
			archivePath := filepath.Join(tempDir, "backup.zip")
			key := "BackupPass123"

			db, err := OpenWithOptions(dbPath, Options{
				Key:         key,
				JournalMode: "WAL",
			})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer db.Close()

			if _, err := db.Exec(`CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
				t.Fatalf("create table: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO items(name) VALUES (?), (?)`, "alpha", "beta"); err != nil {
				t.Fatalf("insert rows: %v", err)
			}

			if err := db.Backup(archivePath, BackupOptions{Compression: tc.compression}); err != nil {
				t.Fatalf("Backup: %v", err)
			}

			backupDBPath := backupTempDBPath(db.path, archivePath)
			if _, err := os.Stat(backupDBPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected temporary backup db cleanup, stat err=%v", err)
			}
			if _, err := os.Stat(backupDBPath + ".encz"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected temporary backup manifest cleanup, stat err=%v", err)
			}
			if _, err := os.Stat(archivePath + ".plainzip"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected temporary plaintext zip cleanup, stat err=%v", err)
			}

			names, methods := zipEntryInfo(t, archivePath, key, tempDir)
			expectedDBName := filepath.Base(backupDBPath)
			expectedManifestName := expectedDBName + ".encz"
			if len(names) != 2 {
				t.Fatalf("expected 2 archive entries, got %d (%v)", len(names), names)
			}
			if names[0] != expectedDBName || names[1] != expectedManifestName {
				t.Fatalf("unexpected archive entries %v", names)
			}
			for _, method := range methods {
				if method != tc.method {
					t.Fatalf("expected zip method %d, got %d", tc.method, method)
				}
			}

			extractDir := filepath.Join(tempDir, "restore")
			if err := testBackup(archivePath, key, extractDir); err != nil {
				t.Fatalf("testBackup: %v", err)
			}
			restoredDBPath := filepath.Join(extractDir, expectedDBName)
			reopened, err := OpenEncz(restoredDBPath, key)
			if err != nil {
				t.Fatalf("open restored backup: %v", err)
			}
			defer reopened.Close()

			var count int
			if err := reopened.QueryRow(`SELECT count(*) FROM items`).Scan(&count); err != nil {
				t.Fatalf("count restored rows: %v", err)
			}
			if count != 2 {
				t.Fatalf("expected 2 restored rows, got %d", count)
			}

			var integrity string
			if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
				t.Fatalf("integrity_check: %v", err)
			}
			if integrity != "ok" {
				t.Fatalf("expected integrity_check ok, got %q", integrity)
			}
		})
	}
}

func TestBackupRejectsUnsupportedCompression(t *testing.T) {
	db, err := OpenEncz(filepath.Join(t.TempDir(), "unsupported.db"), "UnsupportedBackupPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if err := db.Backup(filepath.Join(t.TempDir(), "unsupported.zip"), BackupOptions{Compression: BackupCompressionZstd}); !errors.Is(err, ErrBackupCompressionUnsupported) {
		t.Fatalf("expected ErrBackupCompressionUnsupported, got %v", err)
	}
}

func TestBackupFailsWhenOutputExists(t *testing.T) {
	tempDir := t.TempDir()
	db, err := OpenEncz(filepath.Join(tempDir, "exists.db"), "BackupExistsPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	archivePath := filepath.Join(tempDir, "exists.zip")
	if err := os.WriteFile(archivePath, []byte("already here"), 0o600); err != nil {
		t.Fatalf("seed archive path: %v", err)
	}

	if err := db.Backup(archivePath, BackupOptions{}); !errors.Is(err, ErrBackupOutputExists) {
		t.Fatalf("expected ErrBackupOutputExists, got %v", err)
	}
}

func TestBackupFailsWhenManifestMissing(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "missing-backup-manifest.db")
	db, err := OpenEncz(dbPath, "MissingBackupManifestPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if err := os.Remove(dbPath + ".encz"); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	if err := db.Backup(filepath.Join(tempDir, "missing.zip"), BackupOptions{}); !errors.Is(err, ErrManifestMissing) {
		t.Fatalf("expected ErrManifestMissing, got %v", err)
	}
}

func TestBackupFailsAfterClose(t *testing.T) {
	tempDir := t.TempDir()
	db, err := OpenEncz(filepath.Join(tempDir, "closed-backup.db"), "ClosedBackupPass")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := db.Backup(filepath.Join(tempDir, "closed.zip"), BackupOptions{}); !errors.Is(err, ErrDBClosed) {
		t.Fatalf("expected ErrDBClosed, got %v", err)
	}
}

func TestEnczWALCheckpointReopenIntegrity(t *testing.T) {
	const (
		seedCount  = 1000
		writeCount = 2000
	)

	dbPath := filepath.Join(t.TempDir(), "encz-wal.db")
	ctx := context.Background()
	seedUsers := makeTestUsers(0, seedCount)
	writeUsers := makeTestUsers(seedCount, writeCount)

	db, err := OpenWithOptions(dbPath, Options{
		Key:         "Password123",
		JournalMode: "WAL",
	})
	if err != nil {
		t.Fatalf("open wal db: %v", err)
	}

	if err := createTestSchema(ctx, db); err != nil {
		_ = db.Close()
		t.Fatalf("create schema: %v", err)
	}
	if err := insertTestUsers(ctx, db, "users", seedUsers); err != nil {
		_ = db.Close()
		t.Fatalf("insert seed users: %v", err)
	}
	if err := insertTestUsers(ctx, db, "benchmark_writes", writeUsers); err != nil {
		_ = db.Close()
		t.Fatalf("insert benchmark writes: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = db.Close()
		t.Fatalf("checkpoint wal: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close after checkpoint: %v", err)
	}

	reopened, err := OpenWithOptions(dbPath, Options{
		Key:         "Password123",
		JournalMode: "WAL",
	})
	if err != nil {
		t.Fatalf("reopen wal db: %v", err)
	}
	defer reopened.Close()

	assertCount(t, reopened, `SELECT count(*) FROM users`, seedCount, "reopen users count")
	assertCount(t, reopened, `SELECT count(*) FROM benchmark_writes`, writeCount, "reopen benchmark_writes count")
	assertUserRow(t, reopened, "users", 1, seedUsers[0])
	assertUserRow(t, reopened, "users", seedCount, seedUsers[len(seedUsers)-1])
	assertUserRow(t, reopened, "benchmark_writes", 1, writeUsers[0])
	assertUserRow(t, reopened, "benchmark_writes", writeCount, writeUsers[len(writeUsers)-1])
}

type testUser struct {
	Username string
	Email    string
	City     string
	Age      int
	Profile  string
	Payload  []byte
}

func createTestSchema(ctx context.Context, db *DB) error {
	for _, stmt := range []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE TABLE benchmark_writes (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT NOT NULL,
			city TEXT NOT NULL,
			age INTEGER NOT NULL,
			profile_json TEXT NOT NULL,
			payload BLOB NOT NULL
		)`,
		`CREATE INDEX idx_users_email ON users(email)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func insertTestUsers(ctx context.Context, db *DB, table string, users []testUser) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, fmt.Sprintf(`INSERT INTO %s(username, email, city, age, profile_json, payload) VALUES(?, ?, ?, ?, ?, ?)`, table))
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, user := range users {
		if _, err := stmt.ExecContext(ctx, user.Username, user.Email, user.City, user.Age, user.Profile, user.Payload); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func assertCount(t *testing.T, db *DB, query string, want int, label string) {
	t.Helper()
	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if got != want {
		t.Fatalf("%s: got %d want %d", label, got, want)
	}
}

func assertUserRow(t *testing.T, db *DB, table string, id int, want testUser) {
	t.Helper()
	var got testUser
	if err := db.QueryRow(
		fmt.Sprintf(`SELECT username, email, city, age, profile_json, payload FROM %s WHERE id = ?`, table),
		id,
	).Scan(&got.Username, &got.Email, &got.City, &got.Age, &got.Profile, &got.Payload); err != nil {
		t.Fatalf("read %s id=%d: %v", table, id, err)
	}
	if got.Username != want.Username || got.Email != want.Email || got.City != want.City || got.Age != want.Age || got.Profile != want.Profile || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("mismatch in %s id=%d", table, id)
	}
}

func zipEntryInfo(t *testing.T, archivePath, masterKey, tempDir string) ([]string, []uint16) {
	t.Helper()

	zipPath, err := decryptBackupArchive(archivePath, masterKey, filepath.Join(tempDir, "zipinfo"))
	if err != nil {
		t.Fatalf("decrypt backup archive: %v", err)
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	names := make([]string, 0, len(r.File))
	methods := make([]uint16, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
		methods = append(methods, f.Method)
	}
	return names, methods
}

func makeTestUsers(offset, count int) []testUser {
	users := make([]testUser, 0, count)
	cities := []string{"Toronto", "Montreal", "Vancouver", "Calgary", "Ottawa", "Halifax"}
	for i := 0; i < count; i++ {
		id := offset + i + 1
		payload := make([]byte, 1024+(id%7)*128)
		for j := range payload {
			payload[j] = byte((id + j) % 251)
		}
		username := fmt.Sprintf("user_%06d", id)
		city := cities[id%len(cities)]
		users = append(users, testUser{
			Username: username,
			Email:    fmt.Sprintf("%s@example.com", username),
			City:     city,
			Age:      20 + (id % 50),
			Profile:  fmt.Sprintf(`{"id":%d,"city":"%s","checksum":%d}`, id, city, payload[0]),
			Payload:  payload,
		})
	}
	return users
}

func TestLogHandler(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "log-test.db")
	pass := "TestLogHandlerPass123"

	// Create and write something
	db, err := OpenEncz(dbPath, pass)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = db.Exec("CREATE TABLE t1(x TEXT)")
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec("INSERT INTO t1 VALUES ('hello')")
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Corrupt the MAC tag (last 16 bytes of the first page, which is at offset 4096-16 = 4080)
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if len(data) < 4096 {
		t.Fatalf("file too small: %d", len(data))
	}
	for i := 4080; i < 4096; i++ {
		data[i] ^= 0xff
	}
	err = os.WriteFile(dbPath, data, 0644)
	if err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Setup LogHandler to capture the error message
	var logged []string
	var mu sync.Mutex
	LogHandler = func(msg string) {
		mu.Lock()
		logged = append(logged, msg)
		mu.Unlock()
	}
	defer func() {
		LogHandler = nil
	}()

	// Reopen and try to read, which should trigger decryption error
	reopened, err := OpenEncz(dbPath, pass)
	if err == nil {
		_, _ = reopened.Exec("SELECT * FROM t1")
		reopened.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Errorf("expected at least one log message from encz, got none")
	} else {
		found := false
		for _, msg := range logged {
			if strings.Contains(msg, "DecryptFinal") || strings.Contains(msg, "MAC check failed") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected decrypt/MAC error log message, got: %v", logged)
		}
	}
}
