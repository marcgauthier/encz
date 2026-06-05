package encz

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestOpenPlainSQLite(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "plain.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO items(name) VALUES (?)`, "plain"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	var got string
	if err := db.QueryRow(`SELECT name FROM items WHERE id = 1`).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if got != "plain" {
		t.Fatalf("unexpected value %q", got)
	}
}

func TestBuildEnczDSN(t *testing.T) {
	dsn := BuildEnczDSN("users.db", "secret", "zstd")
	expected := "file:users.db?crypto_compression=zstd&crypto_key=secret&vfs=encz"
	if dsn != expected {
		t.Fatalf("unexpected dsn %q", dsn)
	}
}

func TestOpenEnczSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "encz.db")

	db, err := OpenEncz(dbPath, "Password123", "none")
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

	reopened, err := OpenEncz(dbPath, "Password123", "none")
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
		Compression: "none",
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
		Compression: "none",
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
