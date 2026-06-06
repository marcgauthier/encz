package encz

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var compatJournalModes = []string{"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"}

func TestCompatOpenTxlock(t *testing.T) {
	cases := []struct {
		name string
		tx   string
		want bool
	}{
		{name: "default", tx: "", want: true},
		{name: "immediate", tx: "immediate", want: true},
		{name: "deferred", tx: "deferred", want: true},
		{name: "exclusive", tx: "exclusive", want: true},
		{name: "bogus", tx: "bogus", want: false},
	}
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					dbPath := filepath.Join(t.TempDir(), "open.db")
					opts := compatOptions(journalMode)
					if tc.tx != "" {
						opts.URIParameters["_txlock"] = tc.tx
					}
					db, err := OpenWithOptions(dbPath, opts)
					if tc.want {
						if err != nil {
							t.Fatalf("open: %v", err)
						}
						defer db.Close()
						if _, err := db.Exec(`CREATE TABLE foo (id INTEGER)`); err != nil {
							t.Fatalf("create table: %v", err)
						}
						if _, err := os.Stat(dbPath); err != nil {
							t.Fatalf("stat db: %v", err)
						}
					} else if err == nil {
						defer db.Close()
						t.Fatal("expected open to fail")
					}
				})
			}
		})
	}
}

func TestCompatOpenNoCreate(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "missing.db")
			_, err := OpenWithOptions(dbPath, Options{
				Key: "Password123",
				URIParameters: map[string]string{
					"mode": "rw",
				},
			})
			if err == nil {
				t.Fatal("expected mode=rw open to fail for a missing db")
			}
			if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
				t.Fatalf("expected db file to be absent, stat err=%v", statErr)
			}

			db, err := OpenWithOptions(dbPath, Options{
				Key: "Password123",
				URIParameters: map[string]string{
					"mode": "rwc",
				},
				JournalMode: journalMode,
			})
			if err != nil {
				t.Fatalf("mode=rwc open: %v", err)
			}
			defer db.Close()
			if _, err := os.Stat(dbPath); err != nil {
				t.Fatalf("expected db file to exist: %v", err)
			}
		})
	}
}

func TestCompatReadonly(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "readonly.db")
			writer, err := OpenWithOptions(dbPath, compatOptions(journalMode))
			if err != nil {
				t.Fatalf("writer open: %v", err)
			}
			if _, err := writer.Exec(`CREATE TABLE test (x int, y float)`); err != nil {
				_ = writer.Close()
				t.Fatalf("create table: %v", err)
			}
			if _, err := writer.Exec(`INSERT INTO test VALUES (1, 3.14)`); err != nil {
				_ = writer.Close()
				t.Fatalf("seed row: %v", err)
			}
			if journalMode == "WAL" {
				if _, err := writer.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
					_ = writer.Close()
					t.Fatalf("checkpoint: %v", err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			reader, err := OpenWithOptions(dbPath, Options{
				Key: "Password123",
				URIParameters: map[string]string{
					"mode": "ro",
				},
				JournalMode: journalMode,
			})
			if err != nil {
				t.Fatalf("reader open: %v", err)
			}
			defer reader.Close()
			if _, err := reader.Exec(`INSERT INTO test VALUES (1, 3.14)`); err == nil {
				t.Fatal("expected readonly insert to fail")
			}
		})
	}
}

func TestCompatForeignKeysAndDeferred(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "fk.db")
			db, err := OpenWithOptions(dbPath, Options{
				Key:         "Password123",
				JournalMode: journalMode,
				URIParameters: map[string]string{
					"_foreign_keys": "1",
				},
			})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer db.Close()

			var enabled bool
			if err := db.QueryRow(`PRAGMA foreign_keys;`).Scan(&enabled); err != nil {
				t.Fatalf("query foreign_keys: %v", err)
			}
			if !enabled {
				t.Fatal("expected foreign_keys pragma to be enabled")
			}

			stmts := []string{
				`CREATE TABLE bar (id INTEGER PRIMARY KEY)`,
				`CREATE TABLE foo (bar_id INTEGER, FOREIGN KEY(bar_id) REFERENCES bar(id) DEFERRABLE INITIALLY DEFERRED)`,
			}
			for _, stmt := range stmts {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatalf("exec %q: %v", stmt, err)
				}
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			if _, err := tx.Exec(`INSERT INTO foo (bar_id) VALUES (123)`); err != nil {
				_ = tx.Rollback()
				t.Fatalf("deferred insert: %v", err)
			}
			if err := tx.Commit(); err == nil {
				t.Fatal("expected deferred foreign key commit to fail")
			}
		})
	}
}

func TestCompatCRUDAndTypes(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			db := compatOpenDB(t, journalMode, "crud.db")
			defer db.Close()

			if _, err := db.Exec(`CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT, active BOOL, payload BLOB, created_at TIMESTAMP)`); err != nil {
				t.Fatalf("create table: %v", err)
			}

			ts := time.Date(2026, 6, 5, 6, 0, 0, 0, time.UTC)
			payload := []byte{0, 1, 2, 3, 4, 0, 5}
			res, err := db.Exec(`INSERT INTO foo(name, active, payload, created_at) VALUES(?, ?, ?, ?)`, "alpha", true, payload, ts)
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				t.Fatalf("last insert id: %v", err)
			}

			var name string
			var active bool
			var gotPayload []byte
			var gotTS time.Time
			if err := db.QueryRow(`SELECT name, active, payload, created_at FROM foo WHERE id = ?`, id).Scan(&name, &active, &gotPayload, &gotTS); err != nil {
				t.Fatalf("select inserted row: %v", err)
			}
			if name != "alpha" || !active || !bytesEqual(gotPayload, payload) || !gotTS.Equal(ts) {
				t.Fatalf("roundtrip mismatch name=%q active=%t payload=%v ts=%v", name, active, gotPayload, gotTS)
			}

			if _, err := db.Exec(`UPDATE foo SET name = ?, active = ? WHERE id = ?`, "beta", false, id); err != nil {
				t.Fatalf("update: %v", err)
			}
			if err := db.QueryRow(`SELECT name, active FROM foo WHERE id = ?`, id).Scan(&name, &active); err != nil {
				t.Fatalf("select updated row: %v", err)
			}
			if name != "beta" || active {
				t.Fatalf("unexpected updated row name=%q active=%t", name, active)
			}

			if _, err := db.Exec(`DELETE FROM foo WHERE id = ?`, id); err != nil {
				t.Fatalf("delete: %v", err)
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM foo`).Scan(&count); err != nil {
				t.Fatalf("count after delete: %v", err)
			}
			if count != 0 {
				t.Fatalf("expected 0 rows after delete, got %d", count)
			}
		})
	}
}

func TestCompatUpsertNamedParamsAndNull(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			db := compatOpenDB(t, journalMode, "named.db")
			defer db.Close()

			if _, err := db.Exec(`CREATE TABLE foo (name TEXT PRIMARY KEY, counter INTEGER, note TEXT NULL)`); err != nil {
				t.Fatalf("create table: %v", err)
			}
			for i := 0; i < 5; i++ {
				if _, err := db.Exec(`INSERT INTO foo(name, counter, note) VALUES(:name, 1, :note)
					ON CONFLICT(name) DO UPDATE SET counter=counter+1`,
					sql.Named("name", "key"),
					sql.Named("note", nil),
				); err != nil {
					t.Fatalf("upsert iteration %d: %v", i, err)
				}
			}

			var counter int
			var note sql.NullString
			if err := db.QueryRow(`SELECT counter, note FROM foo WHERE name = ?`, "key").Scan(&counter, &note); err != nil {
				t.Fatalf("select upsert row: %v", err)
			}
			if counter != 5 {
				t.Fatalf("expected counter 5, got %d", counter)
			}
			if note.Valid {
				t.Fatal("expected NULL note")
			}
		})
	}
}

func TestCompatTransactionRollback(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			db := compatOpenDB(t, journalMode, "tx.db")
			defer db.Close()
			if _, err := db.Exec(`CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
				t.Fatalf("create table: %v", err)
			}

			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			if _, err := tx.Exec(`INSERT INTO foo(name) VALUES (?)`, "rolled-back"); err != nil {
				_ = tx.Rollback()
				t.Fatalf("insert in tx: %v", err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatalf("rollback: %v", err)
			}

			var count int
			if err := db.QueryRow(`SELECT count(*) FROM foo`).Scan(&count); err != nil {
				t.Fatalf("count after rollback: %v", err)
			}
			if count != 0 {
				t.Fatalf("expected rollback to leave 0 rows, got %d", count)
			}
		})
	}
}

func TestCompatCorruptDbError(t *testing.T) {
	for _, journalMode := range compatJournalModes {
		journalMode := journalMode
		t.Run("JournalMode_"+journalMode, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "corrupt.db")
			if err := os.WriteFile(dbPath, []byte{1, 2, 3, 4, 5}, 0o644); err != nil {
				t.Fatalf("write corrupt db: %v", err)
			}
			_, err := OpenWithOptions(dbPath, compatOptions(journalMode))
			if err == nil {
				t.Fatal("expected corrupt db open to fail")
			}
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "not a database") && !strings.Contains(msg, "malformed") && !strings.Contains(msg, "corrupt") {
				t.Fatalf("unexpected corrupt db error: %v", err)
			}
		})
	}
}

func compatOpenDB(t *testing.T, journalMode, name string) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), name)
	db, err := OpenWithOptions(dbPath, compatOptions(journalMode))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func compatOptions(journalMode string) Options {
	return Options{
		Key:         "Password123",
		JournalMode: journalMode,
		URIParameters: map[string]string{
			"_busy_timeout": "5000",
		},
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
