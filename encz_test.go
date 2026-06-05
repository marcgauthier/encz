package encz

import (
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
