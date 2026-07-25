package sqliteseal

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestCipherRoundTripAndPersistence(t *testing.T) {
	for _, algorithm := range []Cipher{CipherAES256GCM, CipherChaCha20Poly1305, CipherXChaCha20Poly1305} {
		t.Run(string(algorithm), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cipher.db")
			db, err := OpenWithOptions(path, Options{Key: "CipherPass123", Cipher: algorithm, JournalMode: "WAL"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT INTO t VALUES ('ok')"); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "backup.zip")
			if err := db.Backup(archive, BackupOptions{}); err != nil {
				t.Fatalf("backup: %v", err)
			}
			if err := TestBackup(archive, "CipherPass123", filepath.Join(t.TempDir(), "test-backup")); err != nil {
				t.Fatalf("test backup: %v", err)
			}
			if err := RestoreBackup(archive, "CipherPass123", filepath.Join(t.TempDir(), "restored"), false); err != nil {
				t.Fatalf("restore backup: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = OpenSQLiteSeal(path, "CipherPass123")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var value string
			if err := db.QueryRow("SELECT v FROM t").Scan(&value); err != nil || value != "ok" {
				t.Fatalf("value=%q err=%v", value, err)
			}
			if _, err := OpenWithOptions(path, Options{Key: "CipherPass123", Cipher: CipherAES256GCM}); algorithm != CipherAES256GCM && !errors.Is(err, ErrCipherMismatch) {
				t.Fatalf("expected cipher mismatch, got %v", err)
			}
		})
	}
}

func TestCipherRejectsUnsupportedValue(t *testing.T) {
	_, err := OpenWithOptions(filepath.Join(t.TempDir(), "cipher.db"), Options{Key: "CipherPass123", Cipher: Cipher("invalid")})
	if !errors.Is(err, ErrCipherUnsupported) {
		t.Fatalf("expected unsupported cipher, got %v", err)
	}
}
