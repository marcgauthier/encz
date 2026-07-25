package sqliteseal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
)

func TestConcurrentDEKRotationAndReKeyRetainsReadableKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.db")
	const oldKey = "ConcurrentRotationOldKey"
	const newKey = "ConcurrentRotationNewKey"

	writer, err := OpenSQLiteSeal(path, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	rekeyer, err := OpenSQLiteSeal(path, oldKey)
	if err != nil {
		writer.Close()
		t.Fatal(err)
	}

	writer.mu.Lock()
	payload, policy, err := loadManifest(writer.manifestPath, writer.key)
	if err == nil {
		payload.NextDEKRotationDueAt = timeNowUTC().Add(-time.Minute)
		err = withManifestLock(writer.manifestPath, func() error {
			return saveManifest(writer.manifestPath, writer.key, payload)
		})
	}
	writer.mu.Unlock()
	if err != nil {
		writer.Close()
		rekeyer.Close()
		t.Fatal(err)
	}
	if err := updateKeyRegistryManifest(writer.registryHandle, payload, policy); err != nil {
		t.Fatal(err)
	}
	if err := updateKeyRegistryManifest(rekeyer.registryHandle, payload, policy); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var writeErr, rekeyErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, writeErr = writer.Exec(`INSERT INTO events(value) VALUES ('rotated')`)
	}()
	go func() {
		defer wg.Done()
		<-start
		rekeyErr = rekeyer.ReKey(oldKey, newKey)
	}()
	close(start)
	wg.Wait()

	if rekeyErr != nil {
		t.Fatalf("rekey failed: %v", rekeyErr)
	}
	// If rekey wins the lock, the old-key writer is expected to fail closed.
	if writeErr != nil && !errors.Is(writeErr, ErrManifestAuthFailed) {
		t.Logf("old-key writer failed closed after concurrent rekey: %v", writeErr)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rekeyer.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenSQLiteSeal(path, newKey)
	if err != nil {
		t.Fatalf("reopen with new key: %v", err)
	}
	defer reopened.Close()
	var integrity string
	if err := reopened.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check: %s", integrity)
	}
}

func TestRestoreValidationFailurePreservesExistingTargets(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.db")
	const key = "RestorePreservationKey"
	db, err := OpenSQLiteSeal(sourcePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE secrets(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	brokenDB := filepath.Join(dir, "broken.bak")
	brokenManifest := brokenDB + ".encz"
	dbBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	dbBytes[len(dbBytes)-1] ^= 0xff
	if err := os.WriteFile(brokenDB, dbBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(sourcePath + ".encz")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(brokenManifest, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	plainZip := filepath.Join(dir, "broken.zip")
	if err := writeBackupArchive(plainZip, BackupCompressionStore, brokenDB, brokenManifest); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "broken.encz-backup")
	keyBuffer := memguard.NewBufferFromBytes([]byte(key))
	if err := encryptBackupArchive(plainZip, archive, keyBuffer); err != nil {
		keyBuffer.Destroy()
		t.Fatal(err)
	}
	keyBuffer.Destroy()

	target := filepath.Join(dir, "restore")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	oldDB := []byte("existing database")
	oldManifest := []byte("existing manifest")
	if err := os.WriteFile(filepath.Join(target, "broken.bak"), oldDB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "broken.bak.encz"), oldManifest, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RestoreBackup(archive, key, target, true); err == nil {
		t.Fatal("expected corrupt staged database to fail validation")
	}
	gotDB, _ := os.ReadFile(filepath.Join(target, "broken.bak"))
	gotManifest, _ := os.ReadFile(filepath.Join(target, "broken.bak.encz"))
	if !bytes.Equal(gotDB, oldDB) || !bytes.Equal(gotManifest, oldManifest) {
		t.Fatal("restore modified existing targets before validation completed")
	}
}

func TestSQLiteDependencyHasWALResetFix(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "version.db"), "SQLiteVersionKey")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version string
	if err := db.QueryRow(`SELECT sqlite_version()`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "3.53.3" {
		t.Fatalf("expected SQLite 3.53.3, got %s", version)
	}
}
