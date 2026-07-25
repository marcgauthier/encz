package testutil

import (
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/encz"
	_ "github.com/mattn/go-sqlite3"
)

var JournalModes = []string{"MEMORY", "WAL"}

// OpenTestDB opens a test database with specific VFS configuration.
func OpenTestDB(t *testing.T, encrypted bool, foreignKeys bool, journalMode string) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	if !encrypted {
		values := make(url.Values)
		if journalMode != "" {
			values.Set("_journal_mode", journalMode)
		}
		if foreignKeys {
			values.Set("_foreign_keys", "1")
		}
		dsn := "file:" + filepath.ToSlash(dbPath)
		if encoded := values.Encode(); encoded != "" {
			dsn += "?" + encoded
		}
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			t.Fatalf("failed to open plain database: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db, dbPath
	}
	opts := encz.Options{Key: "TestSecretKey123"}
	if journalMode != "" {
		opts.JournalMode = journalMode
	}
	if foreignKeys {
		opts.URIParameters = map[string]string{
			"_foreign_keys": "1",
		}
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open database (encrypted=%v): %v", encrypted, err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db.SQLDB(), dbPath
}

// RunWithConfigs runs the test case function with multiple VFS configurations:
// - Plain SQLite (unencrypted)
// - Encrypted
func RunWithConfigs(t *testing.T, foreignKeys bool, testFn func(t *testing.T, db *sql.DB)) {
	configs := []struct {
		name      string
		encrypted bool
	}{
		{name: "Plain", encrypted: false},
		{name: "Encrypted", encrypted: true},
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			for _, journalMode := range JournalModes {
				journalMode := journalMode
				t.Run("JournalMode_"+journalMode, func(t *testing.T) {
					db, _ := OpenTestDB(t, cfg.encrypted, foreignKeys, journalMode)
					testFn(t, db)
				})
			}
		})
	}
}
