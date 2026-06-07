package tests

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/encz"
	_ "github.com/mattn/go-sqlite3"
)

func TestBackupRestoreIntegration(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "source.db")
	key := "SuperSecretBackupKey123"

	// 1. Create source database and insert test data
	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to create source DB: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create table: %v", err)
	}

	_, err = db.Exec(`INSERT INTO users (name) VALUES (?), (?)`, "Alice", "Bob")
	if err != nil {
		db.Close()
		t.Fatalf("failed to insert data: %v", err)
	}

	// 2. Perform Backup
	backupZipPath := filepath.Join(tempDir, "backup.zip")
	opts := encz.BackupOptions{
		Compression: encz.BackupCompressionDeflate,
	}
	if err := db.Backup(backupZipPath, opts); err != nil {
		db.Close()
		t.Fatalf("failed to perform backup: %v", err)
	}

	// Close the source database
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close source DB: %v", err)
	}

	// 3. Restore to a new folder (should succeed)
	restoreDir := filepath.Join(tempDir, "restored")
	if err := encz.RestoreBackup(backupZipPath, key, restoreDir, false); err != nil {
		t.Fatalf("RestoreBackup failed to a new folder: %v", err)
	}

	// 4. Verify restored database validity and contents
	restoredDBPath := filepath.Join(restoreDir, "backup.bak")
	restoredDB, err := encz.OpenEncz(restoredDBPath, key)
	if err != nil {
		t.Fatalf("failed to open restored DB: %v", err)
	}
	defer restoredDB.Close()

	var integrity string
	if err := restoredDB.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("PRAGMA integrity_check query failed: %v", err)
	}
	if integrity != "ok" {
		t.Fatalf("restored DB integrity check is not ok: %s", integrity)
	}

	var count int
	if err := restoredDB.QueryRow(`SELECT count(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("failed to query users count: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 users in restored DB, got %d", count)
	}

	var name string
	if err := restoredDB.QueryRow(`SELECT name FROM users WHERE id = 1`).Scan(&name); err != nil {
		t.Fatalf("failed to query user 1: %v", err)
	}
	if name != "Alice" {
		t.Fatalf("expected user 1 name to be Alice, got %s", name)
	}

	// 5. Test overwriteExistingFile constraint
	// Restore with overwrite=false to the same folder containing the restored DB must fail
	err = encz.RestoreBackup(backupZipPath, key, restoreDir, false)
	if err == nil {
		t.Fatalf("expected RestoreBackup to fail with overwrite=false when files already exist, but it succeeded")
	}

	// Restore with overwrite=true to the same folder containing the restored DB must succeed
	// Since restoredDB is open, let's close it first to avoid locks or file sharing violations
	restoredDB.Close()
	if err := encz.RestoreBackup(backupZipPath, key, restoreDir, true); err != nil {
		t.Fatalf("expected RestoreBackup to succeed with overwrite=true when files exist, but got err: %v", err)
	}

	// Reopen after overwrite and verify again
	restoredDB2, err := encz.OpenEncz(restoredDBPath, key)
	if err != nil {
		t.Fatalf("failed to open restored DB after overwrite: %v", err)
	}
	defer restoredDB2.Close()

	if err := restoredDB2.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("PRAGMA integrity_check query failed after overwrite: %v", err)
	}
	if integrity != "ok" {
		t.Fatalf("restored DB integrity check is not ok after overwrite: %s", integrity)
	}
}

func TestRestoreBackupInvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "source2.db")
	key := "CorrectKey123"

	db, err := encz.OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE data (id INTEGER PRIMARY KEY)`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create table: %v", err)
	}
	backupZipPath := filepath.Join(tempDir, "backup2.zip")
	if err := db.Backup(backupZipPath, encz.BackupOptions{}); err != nil {
		db.Close()
		t.Fatalf("failed to backup: %v", err)
	}
	db.Close()

	// Restore with incorrect key must fail
	restoreDir := filepath.Join(tempDir, "restored_bad")
	err = encz.RestoreBackup(backupZipPath, "WrongKey", restoreDir, false)
	if err == nil {
		t.Fatal("expected RestoreBackup to fail with incorrect master key, but it succeeded")
	}
	if !errors.Is(err, encz.ErrManifestAuthFailed) && !errors.Is(err, encz.ErrManifestInvalid) {
		t.Logf("RestoreBackup failed with error: %v", err)
	}
}
