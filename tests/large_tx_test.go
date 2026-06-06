package tests

import (
	"path/filepath"
	"testing"

	"github.com/marcgauthier/encz"
)

// TestLargeSingleTransactionCommit exercises the encz commit path used by
// OVERWATCH populate: encrypted SQLite, DELETE journal mode,
// and one large transaction that dirties many pages before commit.
func TestLargeSingleTransactionCommit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "large-tx.db")
	db, err := encz.OpenWithOptions(dbPath, encz.Options{
		Key:         "LargeTxSecret123",
		JournalMode: "DELETE",
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`PRAGMA page_size = 4096`); err != nil {
		t.Fatalf("set page size: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE large_tx (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO large_tx (payload) VALUES (?)`)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()

	payload := make([]byte, 3500)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	rowCount := 15000
	for i := 0; i < rowCount; i++ {
		if _, err := stmt.Exec(payload); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		t.Fatalf("close stmt: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM large_tx`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != rowCount {
		t.Fatalf("expected %d rows, got %d", rowCount, count)
	}

	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity query: %v", err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity check = %q", integrity)
	}
}
