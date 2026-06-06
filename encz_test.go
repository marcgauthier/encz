package encz

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRequiresKey(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "plain.db"))
	if err == nil {
		t.Fatal("expected Open to reject missing key")
	}
	if err != ErrKeyRequired {
		t.Fatalf("expected ErrKeyRequired, got %v", err)
	}
}

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
	if _, err := OpenEncz(dbPath, "MissingManifestPass"); err != ErrManifestMissing {
		t.Fatalf("expected ErrManifestMissing, got %v", err)
	}
}

func TestRotateManifestKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rotate-manifest.db")
	oldKey := "OldManifestMasterPass"
	newKey := "NewManifestMasterPass"

	db, err := OpenEncz(dbPath, oldKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE rotate_manifest_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO rotate_manifest_test (val) VALUES ('ok')`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := RotateManifestKey(dbPath, oldKey, newKey, Options{}); err != nil {
		t.Fatalf("RotateManifestKey: %v", err)
	}
	if _, err := OpenEncz(dbPath, oldKey); err == nil {
		t.Fatal("expected old manifest key to fail after rotation")
	}
	reopened, err := OpenEncz(dbPath, newKey)
	if err != nil {
		t.Fatalf("reopen with new key: %v", err)
	}
	defer reopened.Close()
	var val string
	if err := reopened.QueryRow(`SELECT val FROM rotate_manifest_test LIMIT 1`).Scan(&val); err != nil {
		t.Fatalf("query after rotation: %v", err)
	}
	if val != "ok" {
		t.Fatalf("unexpected value %q", val)
	}
}

func TestMigrateLegacyKeyedDatabase(t *testing.T) {
	if err := mustRegister(); err != nil {
		t.Fatalf("register: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	legacyKey := "LegacyDirectKeyPass"
	masterKey := "ManifestMasterKeyPass"

	legacyDB, err := openDSN(BuildDSN(dbPath, Options{Key: legacyKey}))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := legacyDB.Exec(`CREATE TABLE legacy_data (val TEXT)`); err != nil {
		legacyDB.Close()
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := legacyDB.Exec(`INSERT INTO legacy_data (val) VALUES ('legacy-ok')`); err != nil {
		legacyDB.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	if err := MigrateLegacyKeyedDatabase(dbPath, legacyKey, Options{Key: masterKey}); err != nil {
		t.Fatalf("MigrateLegacyKeyedDatabase: %v", err)
	}
	if _, err := os.Stat(dbPath + ".encz"); err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if _, err := OpenEncz(dbPath, legacyKey); err == nil {
		t.Fatal("expected legacy direct key to fail after migration")
	}
	reopened, err := OpenEncz(dbPath, masterKey)
	if err != nil {
		t.Fatalf("reopen migrated db: %v", err)
	}
	defer reopened.Close()
	var val string
	if err := reopened.QueryRow(`SELECT val FROM legacy_data LIMIT 1`).Scan(&val); err != nil {
		t.Fatalf("query migrated row: %v", err)
	}
	if val != "legacy-ok" {
		t.Fatalf("unexpected migrated value %q", val)
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

func createTestSchema(ctx context.Context, db *sql.DB) error {
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

func insertTestUsers(ctx context.Context, db *sql.DB, table string, users []testUser) error {
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

func assertCount(t *testing.T, db *sql.DB, query string, want int, label string) {
	t.Helper()
	var got int
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	if got != want {
		t.Fatalf("%s: got %d want %d", label, got, want)
	}
}

func assertUserRow(t *testing.T, db *sql.DB, table string, id int, want testUser) {
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
