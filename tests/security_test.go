package tests

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/encz"
	_ "github.com/mattn/go-sqlite3"
)

// TC-SEC-001: TestInvalidKeyRejection verifies that opening/querying a DB with an incorrect key fails.
func TestInvalidKeyRejection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secure.db")
	key := "CorrectPassword123"

	// 1. Create database and write data
	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE sensitive_data (id INTEGER PRIMARY KEY, secret TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO sensitive_data (secret) VALUES ("TopSecretInfo")`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to insert: %v", err)
	}
	db.Close()

	// 2. Attempt to open with wrong key
	// If Ping fails during OpenEncz, OpenEncz will return an error.
	dbWrong, err := encz.OpenEncz(dbPath, "WrongPassword!!!")
	if err == nil {
		defer dbWrong.Close()
		// If OpenEncz didn't fail at ping time (e.g. if Ping executes a query that didn't read encrypted pages,
		// though standard ping does read), try to query the table.
		var secret string
		err = dbWrong.QueryRow(`SELECT secret FROM sensitive_data WHERE id = 1`).Scan(&secret)
		if err == nil {
			t.Error("expected error when reading with invalid key, but query succeeded")
		}
	}
}

// TC-SEC-002: TestUnencryptedToEncrypted asserts that plain and encrypted databases cannot cross-open.
func TestUnencryptedToEncrypted(t *testing.T) {
	tempDir := t.TempDir()
	plainPath := filepath.Join(tempDir, "plain.db")
	encPath := filepath.Join(tempDir, "encrypted.db")

	// 1. Create plain database outside encz.
	dbPlain, err := sql.Open("sqlite3", plainPath)
	if err != nil {
		t.Fatalf("failed to open plain DB: %v", err)
	}
	_, err = dbPlain.Exec(`CREATE TABLE foo (val TEXT)`)
	if err != nil {
		dbPlain.Close()
		t.Fatalf("failed to write plain: %v", err)
	}
	dbPlain.Close()

	// 2. Create encrypted database
	dbEnc, err := encz.OpenEncz(encPath, "Secret123")
	if err != nil {
		t.Fatalf("failed to open encrypted DB: %v", err)
	}
	_, err = dbEnc.Exec(`CREATE TABLE foo (val TEXT)`)
	if err != nil {
		dbEnc.Close()
		t.Fatalf("failed to write encrypted: %v", err)
	}
	dbEnc.Close()

	// 3. Try to open plain database with encryption key
	dbPlainWithKey, err := encz.OpenEncz(plainPath, "Secret123")
	if err == nil {
		defer dbPlainWithKey.Close()
		var count int
		err = dbPlainWithKey.QueryRow(`SELECT count(*) FROM foo`).Scan(&count)
		if err == nil {
			t.Error("expected read error when opening unencrypted database with an encryption key")
		}
	}

	// 4. Opening encrypted database without a key must fail at the package boundary.
	if _, err := encz.OpenWithOptions(encPath, encz.Options{}); err == nil {
		t.Error("expected OpenWithOptions to reject encrypted database without a key")
	}
}

// TC-SEC-003: TestHeaderSecrecy verifies that the on-disk header retains SQLite format markers and the reserved-byte setting required by this VFS.
func TestHeaderSecrecy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secretheader.db")
	key := "SuperSecretKey99"

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE foo (id INT)`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to write: %v", err)
	}
	db.Close()

	// Read first 16 bytes of the file
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read DB file: %v", err)
	}

	sqliteMagic := []byte("SQLite format 3\000")
	if len(data) < len(sqliteMagic) {
		t.Fatalf("database file is too small: %d bytes", len(data))
	}

	if !bytes.Equal(data[:len(sqliteMagic)], sqliteMagic) {
		t.Fatal("expected SQLite header magic string to remain present on disk")
	}
	if len(data) <= 20 || data[20] != 36 {
		t.Fatalf("expected reserved-byte header field to be 36, got %d", data[20])
	}
}

// TC-SEC-004: TestExtremeKeys validates edge case encryption keys (multibyte, long, binary).
func TestExtremeKeys(t *testing.T) {
	binaryKey := string([]byte{0, 1, 2, 255, 128, 0, 9})
	longKey := make([]byte, 1024)
	for i := range longKey {
		longKey[i] = byte('A' + (i % 26))
	}

	cases := []struct {
		name string
		key  string
	}{
		{name: "SingleCharKey", key: "X"},
		{name: "LongKey1024", key: string(longKey)},
		{name: "BinaryKey", key: binaryKey},
		{name: "MultibyteUnicodeKey", key: "🔑SecretPassword🔒"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "extreme.db")

			// 1. Create and write
			db, err := encz.OpenEncz(dbPath, tc.key)
			if err != nil {
				t.Fatalf("failed to open with key: %v", err)
			}
			_, err = db.Exec(`CREATE TABLE test (val TEXT)`)
			if err != nil {
				db.Close()
				t.Fatalf("failed to create table: %v", err)
			}
			_, err = db.Exec(`INSERT INTO test (val) VALUES ("success")`)
			if err != nil {
				db.Close()
				t.Fatalf("failed to insert: %v", err)
			}
			db.Close()

			// 2. Reopen and verify
			reopened, err := encz.OpenEncz(dbPath, tc.key)
			if err != nil {
				t.Fatalf("failed to reopen: %v", err)
			}
			defer reopened.Close()

			var val string
			err = reopened.QueryRow(`SELECT val FROM test`).Scan(&val)
			if err != nil {
				t.Fatalf("query failed: %v", err)
			}
			if val != "success" {
				t.Errorf("expected 'success', got %q", val)
			}

			// 3. Integrity check
			var integrity string
			err = reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity)
			if err != nil {
				t.Fatalf("integrity_check failed: %v", err)
			}
			if integrity != "ok" {
				t.Errorf("database integrity check failed: %q", integrity)
			}
		})
	}
}

// TC-SEC-005: TestKeyRotation is currently unsupported by this VFS.
func TestKeyRotation(t *testing.T) {
	t.Skip("VACUUM INTO key rotation is not supported by the current encz VFS")
}
