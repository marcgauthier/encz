package tests

import (
	"bytes"
	"database/sql"
	"math"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcgauthier/encz"
	_ "github.com/mattn/go-sqlite3"
)

var journalModes = []string{"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"}

// openTestDB opens a test database with specific VFS configuration.
func openTestDB(t *testing.T, encrypted bool, foreignKeys bool, journalMode string) (*sql.DB, string) {
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
	return db, dbPath
}

// runWithConfigs runs the test case function with multiple VFS configurations:
// - Plain SQLite (unencrypted)
// - Encrypted
func runWithConfigs(t *testing.T, foreignKeys bool, testFn func(t *testing.T, db *sql.DB)) {
	configs := []struct {
		name      string
		encrypted bool
	}{
		{name: "Plain", encrypted: false},
		{name: "Encrypted", encrypted: true},
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			for _, journalMode := range journalModes {
				journalMode := journalMode
				t.Run("JournalMode_"+journalMode, func(t *testing.T) {
					db, _ := openTestDB(t, cfg.encrypted, foreignKeys, journalMode)
					testFn(t, db)
				})
			}
		})
	}
}

// TC-CORE-001: TestTypeRoundtrip tests CRUD on all standard SQLite types
func TestTypeRoundtrip(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE type_test (
			id INTEGER PRIMARY KEY,
			val_int INTEGER,
			val_real REAL,
			val_text TEXT,
			val_blob BLOB,
			val_null TEXT NULL,
			val_time TIMESTAMP
		)`)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		// Prepare boundary values
		testBlob := make([]byte, 256)
		for i := 0; i < 256; i++ {
			testBlob[i] = byte(i)
		}
		testTime := time.Date(2026, 6, 5, 8, 15, 30, 0, time.UTC)

		// Insert values
		_, err = db.Exec(`INSERT INTO type_test (id, val_int, val_real, val_text, val_blob, val_null, val_time)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			1, math.MaxInt64, math.MaxFloat64, "hello world \u263A", testBlob, nil, testTime)
		if err != nil {
			t.Fatalf("failed to insert boundary values: %v", err)
		}

		// Insert negative boundaries
		_, err = db.Exec(`INSERT INTO type_test (id, val_int, val_real, val_text, val_blob, val_null, val_time)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			2, math.MinInt64, -math.MaxFloat64, "", []byte{}, nil, testTime.Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("failed to insert negative boundaries: %v", err)
		}

		// Query and verify row 1
		var gotInt int64
		var gotReal float64
		var gotText string
		var gotBlob []byte
		var gotNull sql.NullString
		var gotTime time.Time

		err = db.QueryRow(`SELECT val_int, val_real, val_text, val_blob, val_null, val_time FROM type_test WHERE id = 1`).
			Scan(&gotInt, &gotReal, &gotText, &gotBlob, &gotNull, &gotTime)
		if err != nil {
			t.Fatalf("failed to scan row 1: %v", err)
		}

		if gotInt != math.MaxInt64 {
			t.Errorf("expected int %d, got %d", int64(math.MaxInt64), gotInt)
		}
		if gotReal != math.MaxFloat64 {
			t.Errorf("expected real %f, got %f", math.MaxFloat64, gotReal)
		}
		if gotText != "hello world \u263A" {
			t.Errorf("expected text %q, got %q", "hello world \u263A", gotText)
		}
		if !bytes.Equal(gotBlob, testBlob) {
			t.Errorf("blob mismatch")
		}
		if gotNull.Valid {
			t.Errorf("expected null to be invalid, got %q", gotNull.String)
		}
		if !gotTime.Equal(testTime) {
			t.Errorf("expected time %v, got %v", testTime, gotTime)
		}

		// Query and verify row 2
		err = db.QueryRow(`SELECT val_int, val_real, val_text, val_blob, val_null, val_time FROM type_test WHERE id = 2`).
			Scan(&gotInt, &gotReal, &gotText, &gotBlob, &gotNull, &gotTime)
		if err != nil {
			t.Fatalf("failed to scan row 2: %v", err)
		}

		if gotInt != math.MinInt64 {
			t.Errorf("expected int %d, got %d", int64(math.MinInt64), gotInt)
		}
		if gotReal != -math.MaxFloat64 {
			t.Errorf("expected real %f, got %f", -math.MaxFloat64, gotReal)
		}
		if gotText != "" {
			t.Errorf("expected empty text, got %q", gotText)
		}
		if len(gotBlob) != 0 {
			t.Errorf("expected empty blob, got %v", gotBlob)
		}
		if !gotTime.Equal(testTime.Add(-24 * time.Hour)) {
			t.Errorf("expected time %v, got %v", testTime.Add(-24*time.Hour), gotTime)
		}
	})
}

// TC-CORE-002: TestPrimaryUniqueConstraints tests primary key and unique constraints
func TestPrimaryUniqueConstraints(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE constraints_test (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE
		)`)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		// Normal insert
		_, err = db.Exec(`INSERT INTO constraints_test (id, email) VALUES (1, "test@example.com")`)
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}

		// Duplicate Primary Key violation
		_, err = db.Exec(`INSERT INTO constraints_test (id, email) VALUES (1, "other@example.com")`)
		if err == nil {
			t.Error("expected primary key violation error, got nil")
		}

		// Duplicate Unique constraint violation
		_, err = db.Exec(`INSERT INTO constraints_test (id, email) VALUES (2, "test@example.com")`)
		if err == nil {
			t.Error("expected unique constraint violation error, got nil")
		}
	})
}

// TC-CORE-003: TestForeignKeyConstraints tests foreign keys and cascading/deferring constraints
func TestForeignKeyConstraints(t *testing.T) {
	// Foreign keys enabled
	runWithConfigs(t, true, func(t *testing.T, db *sql.DB) {
		// Verify foreign keys are enabled in SQLite
		var enabled int
		err := db.QueryRow("PRAGMA foreign_keys").Scan(&enabled)
		if err != nil {
			t.Fatalf("failed to check foreign_keys pragma: %v", err)
		}
		if enabled != 1 {
			t.Fatalf("foreign keys not enabled: got %d", enabled)
		}

		// Create parent and child tables with ON DELETE CASCADE
		_, err = db.Exec(`CREATE TABLE parents (
			id INTEGER PRIMARY KEY,
			name TEXT
		)`)
		if err != nil {
			t.Fatalf("create parents table: %v", err)
		}

		_, err = db.Exec(`CREATE TABLE children (
			id INTEGER PRIMARY KEY,
			parent_id INTEGER,
			name TEXT,
			FOREIGN KEY(parent_id) REFERENCES parents(id) ON DELETE CASCADE
		)`)
		if err != nil {
			t.Fatalf("create children table: %v", err)
		}

		// Insert parent and child
		_, err = db.Exec(`INSERT INTO parents (id, name) VALUES (10, "Parent A")`)
		if err != nil {
			t.Fatalf("insert parent: %v", err)
		}

		_, err = db.Exec(`INSERT INTO children (id, parent_id, name) VALUES (100, 10, "Child A1")`)
		if err != nil {
			t.Fatalf("insert child: %v", err)
		}

		// Violate foreign key constraint (non-existent parent)
		_, err = db.Exec(`INSERT INTO children (id, parent_id, name) VALUES (101, 999, "Child Fail")`)
		if err == nil {
			t.Error("expected foreign key violation error, got nil")
		}

		// Test cascade delete
		_, err = db.Exec(`DELETE FROM parents WHERE id = 10`)
		if err != nil {
			t.Fatalf("delete parent: %v", err)
		}

		var childCount int
		err = db.QueryRow(`SELECT count(*) FROM children WHERE parent_id = 10`).Scan(&childCount)
		if err != nil {
			t.Fatalf("count children: %v", err)
		}
		if childCount != 0 {
			t.Errorf("expected 0 children due to CASCADE, got %d", childCount)
		}

		// Test DEFERRABLE foreign key
		_, err = db.Exec(`CREATE TABLE deferred_child (
			id INTEGER PRIMARY KEY,
			parent_id INTEGER,
			FOREIGN KEY(parent_id) REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED
		)`)
		if err != nil {
			t.Fatalf("create deferred_child table: %v", err)
		}

		// Begin transaction
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}

		// Insert child referencing non-existent parent (valid inside transaction if deferred)
		_, err = tx.Exec(`INSERT INTO deferred_child (id, parent_id) VALUES (200, 20)`)
		if err != nil {
			tx.Rollback()
			t.Fatalf("insert deferred child inside transaction failed: %v", err)
		}

		// Try to commit transaction while reference is still broken. Should fail.
		err = tx.Commit()
		if err == nil {
			t.Error("expected commit to fail due to unresolved deferred foreign key")
		}

		// Now test satisfying the foreign key before commit
		tx, err = db.Begin()
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}

		// Insert child referencing non-existent parent
		_, err = tx.Exec(`INSERT INTO deferred_child (id, parent_id) VALUES (300, 30)`)
		if err != nil {
			tx.Rollback()
			t.Fatalf("insert deferred child failed: %v", err)
		}

		// Insert parent to satisfy dependency
		_, err = tx.Exec(`INSERT INTO parents (id, name) VALUES (30, "Parent C")`)
		if err != nil {
			tx.Rollback()
			t.Fatalf("insert parent inside tx failed: %v", err)
		}

		// Commit should now succeed
		err = tx.Commit()
		if err != nil {
			t.Errorf("expected commit to succeed since dependency was resolved, got: %v", err)
		}
	})
}

// TC-CORE-004: TestCheckAndNotNullConstraints tests NOT NULL and CHECK constraints
func TestCheckAndNotNullConstraints(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE check_test (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			age INTEGER CHECK(age >= 0)
		)`)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		// Test NOT NULL violation
		_, err = db.Exec(`INSERT INTO check_test (id, name, age) VALUES (1, NULL, 25)`)
		if err == nil {
			t.Error("expected NOT NULL violation error, got nil")
		}

		// Test CHECK constraint violation
		_, err = db.Exec(`INSERT INTO check_test (id, name, age) VALUES (2, "Alice", -5)`)
		if err == nil {
			t.Error("expected CHECK constraint violation error, got nil")
		}

		// Normal insertion
		_, err = db.Exec(`INSERT INTO check_test (id, name, age) VALUES (3, "Alice", 25)`)
		if err != nil {
			t.Fatalf("expected insert to succeed, got: %v", err)
		}
	})
}

// TC-CORE-005: TestNullHandling tests nullable columns, IS NULL, and COALESCE
func TestNullHandling(t *testing.T) {
	runWithConfigs(t, false, func(t *testing.T, db *sql.DB) {
		_, err := db.Exec(`CREATE TABLE null_test (
			id INTEGER PRIMARY KEY,
			description TEXT,
			score INTEGER
		)`)
		if err != nil {
			t.Fatalf("failed to create table: %v", err)
		}

		// Insert with nulls
		_, err = db.Exec(`INSERT INTO null_test (id, description, score) VALUES (1, NULL, NULL)`)
		if err != nil {
			t.Fatalf("insert nulls: %v", err)
		}

		_, err = db.Exec(`INSERT INTO null_test (id, description, score) VALUES (2, "active", 100)`)
		if err != nil {
			t.Fatalf("insert non-nulls: %v", err)
		}

		// Test IS NULL filter
		var nullCount int
		err = db.QueryRow(`SELECT count(*) FROM null_test WHERE description IS NULL AND score IS NULL`).Scan(&nullCount)
		if err != nil {
			t.Fatalf("query IS NULL: %v", err)
		}
		if nullCount != 1 {
			t.Errorf("expected 1 row matching IS NULL query, got %d", nullCount)
		}

		// Test COALESCE
		var desc string
		var score int
		err = db.QueryRow(`SELECT COALESCE(description, "default_desc"), COALESCE(score, -1) FROM null_test WHERE id = 1`).Scan(&desc, &score)
		if err != nil {
			t.Fatalf("query COALESCE: %v", err)
		}
		if desc != "default_desc" || score != -1 {
			t.Errorf("expected default values from COALESCE, got description=%q score=%d", desc, score)
		}

		err = db.QueryRow(`SELECT COALESCE(description, "default_desc"), COALESCE(score, -1) FROM null_test WHERE id = 2`).Scan(&desc, &score)
		if err != nil {
			t.Fatalf("query COALESCE non-null: %v", err)
		}
		if desc != "active" || score != 100 {
			t.Errorf("expected original values from COALESCE, got description=%q score=%d", desc, score)
		}
	})
}
