package encz

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
)

// dummyDriver is a minimal sql driver for testing type assertion failure in copyDatabasePages.
type dummyDriver struct{}

func (dummyDriver) Open(name string) (driver.Conn, error) {
	return &dummyConn{}, nil
}

type dummyConn struct{}

func (dummyConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (dummyConn) Close() error {
	return nil
}

func (dummyConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

var dummyDriverRegistered bool

func registerDummyDriver() {
	if !dummyDriverRegistered {
		sql.Register("dummy-driver-test", &dummyDriver{})
		dummyDriverRegistered = true
	}
}

func TestOpenCloseNilDB(t *testing.T) {
	var db *DB
	if db.SQLDB() != nil {
		t.Error("expected SQLDB() on nil DB to return nil")
	}
	if err := db.Close(); err != nil {
		t.Errorf("expected Close() on nil DB to return nil, got: %v", err)
	}
}

func TestDoubleCloseDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "double_close.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("OpenEncz failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestDirectKeyConfigUnsupported(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "direct_key.db")
	opts := Options{
		Key: "Pass123",
		URIParameters: map[string]string{
			"crypto_key": "somekey",
		},
	}
	_, err := OpenWithOptions(dbPath, opts)
	if !errors.Is(err, ErrDirectKeyUnsupported) {
		t.Errorf("expected ErrDirectKeyUnsupported, got %v", err)
	}
}

func TestMemoryPathUnsupported(t *testing.T) {
	_, err := OpenWithOptions(":memory:", Options{Key: "Pass123"})
	if !errors.Is(err, ErrFileBackedRequired) {
		t.Errorf("expected ErrFileBackedRequired for :memory:, got %v", err)
	}

	_, err = OpenWithOptions("test.db", Options{
		Key: "Pass123",
		URIParameters: map[string]string{
			"mode": "memory",
		},
	})
	if !errors.Is(err, ErrFileBackedRequired) {
		t.Errorf("expected ErrFileBackedRequired for mode=memory, got %v", err)
	}
}

func TestFileExistsErrors(t *testing.T) {
	// A path with null byte should cause os.Stat to fail with an invalid argument.
	_, err := OpenWithOptions("invalid\x00path.db", Options{Key: "Pass123"})
	if err == nil {
		t.Fatal("expected error for path with null byte, got nil")
	}
}

func TestNormalizeCreateRotationPolicyErrors(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy_err.db")
	p1 := RotationPolicy{KEKRotationDays: -5}
	_, err := OpenWithOptions(dbPath, Options{Key: "Pass123", RotationPolicy: &p1})
	if !errors.Is(err, ErrRotationPolicyInvalid) {
		t.Errorf("expected ErrRotationPolicyInvalid for negative KEK days, got %v", err)
	}

	p2 := RotationPolicy{DEKRotationHours: -5}
	_, err = OpenWithOptions(dbPath, Options{Key: "Pass123", RotationPolicy: &p2})
	if !errors.Is(err, ErrRotationPolicyInvalid) {
		t.Errorf("expected ErrRotationPolicyInvalid for negative DEK hours, got %v", err)
	}
}

func TestSaveManifestWriteError(t *testing.T) {
	// Try creating a DB in a path where writing manifest will fail.
	_, err := OpenWithOptions("/invalid-dir-no-perm/test.db", Options{Key: "Pass123"})
	if err == nil {
		t.Fatal("expected error saving manifest in unwritable directory")
	}
}

func TestManifestMismatchAndMissing(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "mismatch.db")

	// 1. Manifest exists but DB does not.
	manifestPath := dbPath + ".encz"
	if err := os.WriteFile(manifestPath, []byte("fake manifest"), 0600); err != nil {
		t.Fatalf("failed to write fake manifest: %v", err)
	}

	_, err := OpenEncz(dbPath, "Pass123")
	if !errors.Is(err, ErrManifestMismatch) {
		t.Errorf("expected ErrManifestMismatch, got %v", err)
	}

	// Clean up manifest
	os.Remove(manifestPath)

	// 2. DB exists but manifest does not.
	if err := os.WriteFile(dbPath, []byte("fake db"), 0600); err != nil {
		t.Fatalf("failed to write fake db: %v", err)
	}

	_, err = OpenEncz(dbPath, "Pass123")
	if !errors.Is(err, ErrManifestMissing) {
		t.Errorf("expected ErrManifestMissing, got %v", err)
	}
}

func TestAutoRewrapKekRotationOnOpen(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "autorewrap.db")
	key := "Pass123"

	// Create DB
	db, err := OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()

	// Modify manifest to trigger rotation
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	manifestPath := dbPath + ".encz"
	payload, policy, err := loadManifest(manifestPath, keyBuf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Backdate the dates
	now := timeNowUTC()
	payload.LastKEKRotationAt = now.Add(-30 * 24 * time.Hour)
	payload.NextKEKRotationDueAt = now.Add(-20 * 24 * time.Hour)
	policy.AutoRewrap = true

	if err := saveManifest(manifestPath, keyBuf, payload); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Reopen DB, triggering auto rewrap
	db, err = OpenWithOptions(dbPath, Options{
		Key:            key,
		RotationPolicy: &policy,
	})
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer db.Close()

	// Verify dates updated
	reloaded, _, err := loadManifest(manifestPath, keyBuf)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.LastKEKRotationAt.After(payload.LastKEKRotationAt) {
		t.Error("expected KEK rotation date to update after auto-rewrap")
	}

}

func TestParseManifestErrors(t *testing.T) {
	// Short blob
	_, _, err := parseManifest([]byte("short"))
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}

	// Wrong magic
	badMagic := make([]byte, manifestHeaderSize()+20)
	copy(badMagic, "WRONGM")
	_, _, err = parseManifest(badMagic)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}

	// Wrong version
	badVersion := make([]byte, manifestHeaderSize()+20)
	copy(badVersion, manifestMagic)
	badVersion[len(manifestMagic)] = 99 // version 99
	_, _, err = parseManifest(badVersion)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestDecryptManifestPayloadAuthFailed(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "auth_failed.db")
	db, err := OpenEncz(dbPath, "CorrectKey123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()

	// Try loading with wrong key
	keyBuf := memguard.NewBufferFromBytes([]byte("WrongKey123"))
	defer keyBuf.Destroy()
	_, _, err = loadManifest(dbPath+".encz", keyBuf)
	if !errors.Is(err, ErrManifestAuthFailed) {
		t.Errorf("expected ErrManifestAuthFailed, got %v", err)
	}
}

func TestRotationStatusDeletedOrCorruptedManifest(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rot_status.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Delete manifest
	if err := os.Remove(db.manifestPath); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	status, err := db.RotationStatus()
	if !errors.Is(err, ErrManifestMissing) {
		t.Errorf("expected ErrManifestMissing, got %v", err)
	}
	if status.ManifestPath != db.manifestPath {
		t.Errorf("expected manifest path in status, got %s", status.ManifestPath)
	}

	// Corrupt manifest
	if err := os.WriteFile(db.manifestPath, []byte("corrupted_data"), 0600); err != nil {
		t.Fatalf("write corrupted manifest: %v", err)
	}

	_, err = db.RotationStatus()
	if err == nil || errors.Is(err, ErrManifestMissing) {
		t.Errorf("expected decryption/parse error, got %v", err)
	}
}

func TestCloneLockedBufferNil(t *testing.T) {
	if cloneLockedBuffer(nil) != nil {
		t.Error("expected cloneLockedBuffer(nil) to return nil")
	}
}

func TestKeyRegistryInvalidOperations(t *testing.T) {
	destroyKeyRegistry(999999) // should be noop and not panic

	updateKeyRegistryMasterKey(999999, nil) // should be noop and not panic

	err := updateKeyRegistryManifest(999999, manifestPayload{}, RotationPolicy{})
	if err != nil {
		t.Errorf("expected no error updating nonexistent registry manifest, got %v", err)
	}
}

func TestBuildRegistryKeyBuffersErrors(t *testing.T) {
	// 1. Invalid hex string in DEK
	p1 := manifestPayload{
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "invalid-hex"},
		},
	}
	_, err := buildRegistryKeyBuffers(p1)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}

	// 2. ActiveDEKKeyID not in DEKs
	p2 := manifestPayload{
		ActiveDEKKeyID: 99,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	_, err = buildRegistryKeyBuffers(p2)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestRotateActiveDEKLockedErrors(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "rot_dek_err.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	payload := manifestPayload{
		ActiveDEKKeyID: 0,
		DEKs: []manifestDEK{
			{KeyID: 0, DEKHex: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	policy := RotationPolicy{DEKRotationHours: 24}

	handle, err := registerKeyRegistry(manifestPath, masterKey, payload, policy, true)
	if err != nil {
		t.Fatalf("registerKeyRegistry: %v", err)
	}
	defer destroyKeyRegistry(handle)

	reg, ok := getKeyRegistry(handle)
	if !ok {
		t.Fatal("failed to get registry")
	}

	// 2. Save manifest error in rotateActiveDEKLocked
	reg.manifestPath = "/nonexistent-dir/manifest.encz"
	reg.mu.Lock()
	err = reg.rotateActiveDEKLocked(timeNowUTC())
	reg.mu.Unlock()
	if err == nil {
		t.Fatal("expected rotateActiveDEKLocked to fail when manifest cannot be saved")
	}
}

// Reflection helpers to invoke cgo-dependent Go functions without importing "C" in the test file.

func callEnczGoFillKey(handle uint64, keyID uint32, out *byte) int {
	fn := reflect.ValueOf(enczGoFillKey)
	fnType := fn.Type()
	arg0 := reflect.ValueOf(handle).Convert(fnType.In(0))
	arg1 := reflect.ValueOf(keyID).Convert(fnType.In(1))
	var arg2 reflect.Value
	if out == nil {
		arg2 = reflect.Zero(fnType.In(2))
	} else {
		arg2 = reflect.ValueOf(out).Convert(fnType.In(2))
	}
	ret := fn.Call([]reflect.Value{arg0, arg1, arg2})
	return int(ret[0].Convert(reflect.TypeOf(int(0))).Int())
}

func callEnczGoFillActiveKey(handle uint64, outKeyID *uint32, out *byte) int {
	fn := reflect.ValueOf(enczGoFillActiveKey)
	fnType := fn.Type()
	arg0 := reflect.ValueOf(handle).Convert(fnType.In(0))
	var arg1 reflect.Value
	if outKeyID == nil {
		arg1 = reflect.Zero(fnType.In(1))
	} else {
		arg1 = reflect.ValueOf(outKeyID).Convert(fnType.In(1))
	}
	var arg2 reflect.Value
	if out == nil {
		arg2 = reflect.Zero(fnType.In(2))
	} else {
		arg2 = reflect.ValueOf(out).Convert(fnType.In(2))
	}
	ret := fn.Call([]reflect.Value{arg0, arg1, arg2})
	return int(ret[0].Convert(reflect.TypeOf(int(0))).Int())
}

func callEnczGoFillDBUUID(handle uint64, out *byte) int {
	fn := reflect.ValueOf(enczGoFillDBUUID)
	fnType := fn.Type()
	arg0 := reflect.ValueOf(handle).Convert(fnType.In(0))
	var arg1 reflect.Value
	if out == nil {
		arg1 = reflect.Zero(fnType.In(1))
	} else {
		arg1 = reflect.ValueOf(out).Convert(fnType.In(1))
	}
	ret := fn.Call([]reflect.Value{arg0, arg1})
	return int(ret[0].Convert(reflect.TypeOf(int(0))).Int())
}

func TestEnczKeysExportedFunctions(t *testing.T) {
	var buf [32]byte
	var keyID uint32

	if callEnczGoFillKey(0, 0, nil) != 0 {
		t.Error("expected to return 0 for invalid handle")
	}
	if callEnczGoFillKey(9999, 0, nil) != 0 {
		t.Error("expected to return 0 for nil out pointer")
	}

	if callEnczGoFillActiveKey(0, &keyID, &buf[0]) != 0 {
		t.Error("expected to return 0 for invalid handle")
	}
	if callEnczGoFillActiveKey(9999, nil, &buf[0]) != 0 {
		t.Error("expected to return 0 for nil keyID")
	}
	if callEnczGoFillActiveKey(9999, &keyID, nil) != 0 {
		t.Error("expected to return 0 for nil out pointer")
	}

	if callEnczGoFillDBUUID(0, &buf[0]) != 0 {
		t.Error("expected to return 0 for invalid handle")
	}
	if callEnczGoFillDBUUID(9999, nil) != 0 {
		t.Error("expected to return 0 for nil out pointer")
	}

	// Register a registry and test success and keyID not found paths
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "keys.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	payload := manifestPayload{
		DBUUID:         "0102030405060708090a0b0c0d0e0f10",
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	policy := RotationPolicy{}
	handle, err := registerKeyRegistry(manifestPath, masterKey, payload, policy, false)
	if err != nil {
		t.Fatalf("registerKeyRegistry: %v", err)
	}
	defer destroyKeyRegistry(handle)

	// Call fill key for valid key ID
	if callEnczGoFillKey(handle, 1, &buf[0]) != 1 {
		t.Error("expected callEnczGoFillKey to return 1 for valid keyID")
	}
	if buf[31] != 1 {
		t.Errorf("expected filled key to end with 1, got %v", buf)
	}

	// Call fill key for invalid key ID
	if callEnczGoFillKey(handle, 99, &buf[0]) != 0 {
		t.Error("expected callEnczGoFillKey to return 0 for invalid keyID")
	}

	// Call fill active key
	var activeID uint32
	if callEnczGoFillActiveKey(handle, &activeID, &buf[0]) != 1 {
		t.Error("expected callEnczGoFillActiveKey to return 1")
	}
	if activeID != 1 {
		t.Errorf("expected activeID to be 1, got %d", activeID)
	}

	// Call fill DB UUID
	var uuidBuf [16]byte
	if callEnczGoFillDBUUID(handle, &uuidBuf[0]) != 1 {
		t.Error("expected callEnczGoFillDBUUID to return 1")
	}
	expectedUUID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if !bytes.Equal(uuidBuf[:], expectedUUID) {
		t.Errorf("expected uuid %v, got %v", expectedUUID, uuidBuf)
	}
}

func TestBackupTargetRequiredAndClosed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "backup_test.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = db.Backup("", BackupOptions{})
	if !errors.Is(err, ErrBackupTargetRequired) {
		t.Errorf("expected ErrBackupTargetRequired, got %v", err)
	}

	db.Close()
	err = db.Backup("backup.zip", BackupOptions{})
	if !errors.Is(err, ErrDBClosed) {
		t.Errorf("expected ErrDBClosed, got %v", err)
	}
}

func TestBackupManifestErrors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "backup_manifest.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// 1. Manifest fileExists error
	db.manifestPath = "invalid\x00manifest"
	err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
	if err == nil {
		t.Fatal("expected error with null byte in manifest path")
	}

	// 2. Load manifest error
	db.manifestPath = filepath.Join(tempDir, "corrupted.encz")
	if err := os.WriteFile(db.manifestPath, []byte("corrupt manifest content"), 0600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}
	err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
	if err == nil || errors.Is(err, ErrManifestMissing) {
		t.Errorf("expected load manifest error, got %v", err)
	}
}

func TestBackupDirCreationAndFileExistsErrors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "backup_dir.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// 1. Directory creation fails (unwritable path)
	err = db.Backup("/invalid-dir-no-perm/backup.zip", BackupOptions{})
	if err == nil {
		t.Fatal("expected error when target folder cannot be created")
	}

	// 2. Target file fileExists fails due to null byte
	err = db.Backup("backup.zip\x00", BackupOptions{})
	if err == nil {
		t.Fatal("expected error with null byte in target file path")
	}
}

func TestBackupOutputExistsPreTemp(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "backup_exists.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Pre-create the temp zip file path to trigger ErrBackupOutputExists inside the loop
	toFile := filepath.Join(tempDir, "exists.zip")
	zipTempPath := toFile + ".plainzip"
	if err := os.WriteFile(zipTempPath, []byte("tempzip"), 0600); err != nil {
		t.Fatalf("write temp zip: %v", err)
	}

	err = db.Backup(toFile, BackupOptions{})
	if !errors.Is(err, ErrBackupOutputExists) {
		t.Errorf("expected ErrBackupOutputExists for temp zip path, got %v", err)
	}
}

func TestBackupOpenSQLDBFailure(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "backup_sql.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	toFile := filepath.Join(tempDir, "backup_sql.zip")

	// Pre-create the backup temp DB path as a directory.
	// SQLite will fail to open a directory as a database file.
	backupDBPath := backupTempDBPath(db.path, toFile)
	if err := os.MkdirAll(backupDBPath, 0755); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	defer os.RemoveAll(backupDBPath)

	err = db.Backup(toFile, BackupOptions{})
	if err == nil {
		t.Fatal("expected error when SQLite cannot open the backup temp DB")
	}
}

func TestNormalizeBackupCompressionDefault(t *testing.T) {
	comp, err := normalizeBackupCompression(BackupCompression("invalid-comp"))
	if !errors.Is(err, ErrBackupCompressionUnsupported) {
		t.Errorf("expected ErrBackupCompressionUnsupported, got %v", err)
	}
	if comp != "" {
		t.Errorf("expected empty string, got %s", comp)
	}
}

func TestBackupTempDBPathEmptyName(t *testing.T) {
	// Call backupTempDBPath with empty base name for archivePath (e.g. ".zip").
	path := backupTempDBPath("/foo/bar.db", ".zip")
	if !strings.Contains(path, "backup.bak") {
		t.Errorf("expected fallback to backup.bak, got %s", path)
	}
}

func TestTestBackupHelperErrors(t *testing.T) {
	// 1. Empty arguments
	if err := TestBackup("", "key", "dir"); !errors.Is(err, ErrBackupTargetRequired) {
		t.Errorf("expected ErrBackupTargetRequired, got %v", err)
	}
	if err := TestBackup("file", "", "dir"); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("expected ErrKeyRequired, got %v", err)
	}
	if err := TestBackup("file", "key", ""); err == nil {
		t.Error("expected error for empty tempFolder")
	}

	// 2. Nonexistent file
	if err := TestBackup("nonexistent.zip", "key", "dir"); err == nil {
		t.Error("expected error decrypting nonexistent file")
	}
}

func TestRestoreBackupHelperErrors(t *testing.T) {
	// 1. Empty arguments
	if err := RestoreBackup("", "key", "dir", true); !errors.Is(err, ErrBackupTargetRequired) {
		t.Errorf("expected ErrBackupTargetRequired, got %v", err)
	}
	if err := RestoreBackup("file", "", "dir", true); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("expected ErrKeyRequired, got %v", err)
	}
	if err := RestoreBackup("file", "key", "", true); err == nil {
		t.Error("expected error for empty toFolder")
	}

	// 2. Nonexistent file
	if err := RestoreBackup("nonexistent.zip", "key", "dir", true); err == nil {
		t.Error("expected error decrypting nonexistent file")
	}

	// 3. os.MkdirTemp fails
	t.Setenv("TMPDIR", "/nonexistent-dir-for-temp")
	if err := RestoreBackup("file", "key", "dir", true); err == nil {
		t.Error("expected error when os.MkdirTemp fails")
	}
}

func TestRestoreBackupMissingFiles(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a zip with no files, encrypt it, and try to restore.
	zipPath := filepath.Join(tempDir, "empty.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create empty zip: %v", err)
	}
	zw := zip.NewWriter(f)
	zw.Close()
	f.Close()

	key := "Pass123"
	encZipPath := filepath.Join(tempDir, "empty.zip.enc")
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	if err := encryptBackupArchive(zipPath, encZipPath, keyBuf); err != nil {
		t.Fatalf("encryptBackupArchive: %v", err)
	}

	err = RestoreBackup(encZipPath, key, filepath.Join(tempDir, "restore"), true)
	if err == nil {
		t.Fatal("expected error restoring from empty zip")
	}

	// 2. Create a zip with only the database (missing manifest), encrypt it, and try to restore.
	zipPathDbOnly := filepath.Join(tempDir, "dbonly.zip")
	f, err = os.Create(zipPathDbOnly)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw = zip.NewWriter(f)
	w, err := zw.Create("test.bak")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	w.Write([]byte("fake database content"))
	zw.Close()
	f.Close()

	encZipPathDbOnly := filepath.Join(tempDir, "dbonly.zip.enc")
	if err := encryptBackupArchive(zipPathDbOnly, encZipPathDbOnly, keyBuf); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	err = RestoreBackup(encZipPathDbOnly, key, filepath.Join(tempDir, "restore_dbonly"), true)
	if !errors.Is(err, ErrManifestMissing) {
		t.Errorf("expected ErrManifestMissing, got %v", err)
	}
}

func TestExtractZipEntryErrors(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "extract_err.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("test.txt")
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	w.Write([]byte("hello"))
	zw.Close()
	f.Close()

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer r.Close()

	// Try extracting to an unwritable location
	err = extractZipEntry(r.File[0], "/invalid-dir-no-perm/test.txt")
	if err == nil {
		t.Fatal("expected extractZipEntry to fail in unwritable directory")
	}
}

func TestDecryptBackupArchiveMkdirError(t *testing.T) {
	_, err := decryptBackupArchive("file", "key", "/invalid-dir-no-perm/dir")
	if err == nil {
		t.Fatal("expected decryptBackupArchive to fail when mkdir fails")
	}
}

func TestEncryptDecryptArchiveFileErrors(t *testing.T) {
	keyBuf := memguard.NewBufferFromBytes([]byte("key"))
	defer keyBuf.Destroy()

	// 1. encryptBackupArchive fails to read plain zip
	err := encryptBackupArchive("/nonexistent/file.zip", "dest.zip", keyBuf)
	if err == nil {
		t.Fatal("expected encryptBackupArchive to fail for nonexistent plain zip path")
	}

	// 2. decryptBackupArchiveToFile fails to read encrypted file
	err = decryptBackupArchiveToFile("/nonexistent/encrypted.zip", "dest.zip", keyBuf)
	if err == nil {
		t.Fatal("expected decryptBackupArchiveToFile to fail for nonexistent encrypted file")
	}
}

func TestParseBackupArchiveErrors(t *testing.T) {
	// Short blob
	_, _, err := parseBackupArchive([]byte("short"))
	if !errors.Is(err, ErrBackupArchiveInvalid) {
		t.Errorf("expected ErrBackupArchiveInvalid, got %v", err)
	}

	// Wrong magic
	badMagic := make([]byte, backupArchiveHeaderSize()+20)
	copy(badMagic, "WRONGM")
	_, _, err = parseBackupArchive(badMagic)
	if !errors.Is(err, ErrBackupArchiveInvalid) {
		t.Errorf("expected ErrBackupArchiveInvalid, got %v", err)
	}

	// Wrong version
	badVersion := make([]byte, backupArchiveHeaderSize()+20)
	copy(badVersion, backupArchiveMagic)
	badVersion[len(backupArchiveMagic)] = 99 // version 99
	_, _, err = parseBackupArchive(badVersion)
	if !errors.Is(err, ErrBackupArchiveInvalid) {
		t.Errorf("expected ErrBackupArchiveInvalid, got %v", err)
	}
}

func TestCopyDatabasePagesErrors(t *testing.T) {
	registerDummyDriver()

	srcDB, err := sql.Open("dummy-driver-test", "src")
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer srcDB.Close()

	destDB, err := sql.Open("dummy-driver-test", "dest")
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	defer destDB.Close()

	ctx := context.Background()

	// 1. Type assertion failure on srcRaw (*sqlite3.SQLiteConn)
	err = copyDatabasePages(ctx, srcDB, destDB)
	if err == nil || !strings.Contains(err.Error(), "unexpected source SQLite connection type") {
		t.Errorf("expected type assertion error, got: %v", err)
	}

	// 2. Connection failure due to closed DB (covers Conn error path)
	closedDB, _ := sql.Open("dummy-driver-test", "closed")
	closedDB.Close()
	err = copyDatabasePages(ctx, closedDB, destDB)
	if err == nil {
		t.Fatal("expected error on closed source DB")
	}

	err = copyDatabasePages(ctx, srcDB, closedDB)
	if err == nil {
		t.Fatal("expected error on closed destination DB")
	}
}

func TestAddPathToZipErrors(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	defer zw.Close()

	// nonexistent file
	err := addPathToZip(zw, "/nonexistent/file", BackupCompressionDeflate)
	if err == nil {
		t.Fatal("expected addPathToZip to fail for nonexistent file")
	}
}

func TestOptionsManifestPath(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "opts_manifest.db")
	manifestPath := filepath.Join(tempDir, "custom_manifest.encz")
	db, err := OpenWithOptions(dbPath, Options{
		Key:          "Pass123",
		ManifestPath: manifestPath,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions with ManifestPath: %v", err)
	}
	db.Close()
	
	// Check that the manifest was created at the custom path
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("expected manifest at custom path, got: %v", err)
	}
}

func TestNormalizeCreateRotationPolicyValid(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "policy_valid.db")
	policy := RotationPolicy{
		KEKRotationDays:  12,
		DEKRotationHours: 36,
		AutoRewrap:       true,
		KeepPreviousKey:  true,
	}
	db, err := OpenWithOptions(dbPath, Options{
		Key:            "Pass123",
		RotationPolicy: &policy,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions with custom policy: %v", err)
	}
	defer db.Close()
	
	status, err := db.RotationStatus()
	if err != nil {
		t.Fatalf("RotationStatus: %v", err)
	}
	if status.KEKRotationDays != 12 || status.DEKRotationHours != 36 {
		t.Errorf("unexpected status: %+v", status)
	}
}

func TestApplyKEKRotationEdgeCases(t *testing.T) {
	// 1. KeepPreviousKey is true, but no active DEK in payload
	payload := manifestPayload{
		ActiveDEKKeyID: 99,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	policy := RotationPolicy{KeepPreviousKey: true}
	applyKEKRotation(&payload, policy, time.Now())
	if payload.PreviousKeySlot != nil {
		t.Error("expected PreviousKeySlot to be nil since active DEK was missing")
	}

	// 2. KeepPreviousKey is false
	policyFalse := RotationPolicy{KeepPreviousKey: false}
	applyKEKRotation(&payload, policyFalse, time.Now())
	if payload.PreviousKeySlot != nil {
		t.Error("expected PreviousKeySlot to be nil")
	}
}

func createCustomEncryptedManifest(t *testing.T, path string, key *memguard.LockedBuffer, plain []byte, modifyFn func(*manifestPayload)) {
	t.Helper()
	hdr := manifestHeader{
		Version:      manifestVersion,
		ArgonTime:    1,
		ArgonMemory:  1024,
		ArgonThreads: 1,
	}
	// generate dummy salt and nonce
	for i := range hdr.Salt {
		hdr.Salt[i] = byte(i)
	}
	for i := range hdr.Nonce {
		hdr.Nonce[i] = byte(i)
	}

	var sealed []byte
	var err error
	if plain != nil {
		kek := deriveKEK(key, hdr)
		sealed, err = encryptManifestPayload(kek, hdr, plain)
		if err != nil {
			t.Fatalf("encryptManifestPayload: %v", err)
		}
	} else {
		payload := manifestPayload{
			DBUUID:               "0102030405060708090a0b0c0d0e0f10",
			ActiveDEKKeyID:       1,
			DEKs:                 []manifestDEK{{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"}},
			CreatedAt:            time.Now(),
			LastKEKRotationAt:    time.Time{}, // zero
			NextKEKRotationDueAt: time.Time{}, // zero
			LastDEKRotationAt:    time.Time{}, // zero
			NextDEKRotationDueAt: time.Time{}, // zero
			KEKRotationDays:      10,
			DEKRotationHours:     24,
		}
		if modifyFn != nil {
			modifyFn(&payload)
		}
		plainBytes, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}
		kek := deriveKEK(key, hdr)
		sealed, err = encryptManifestPayload(kek, hdr, plainBytes)
		if err != nil {
			t.Fatalf("encryptManifestPayload: %v", err)
		}
	}

	buf := make([]byte, 0, manifestHeaderSize()+len(sealed))
	buf = append(buf, []byte(manifestMagic)...)
	buf = append(buf, hdr.Version)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonTime)
	buf = binary.LittleEndian.AppendUint32(buf, hdr.ArgonMemory)
	buf = append(buf, hdr.ArgonThreads)
	buf = append(buf, hdr.Salt[:]...)
	buf = append(buf, hdr.Nonce[:]...)
	buf = append(buf, sealed...)
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestLoadManifestEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	key := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer key.Destroy()

	// 1. JSON unmarshal failure
	p1 := filepath.Join(tempDir, "unmarshal.encz")
	createCustomEncryptedManifest(t, p1, key, []byte("invalid json"), nil)
	_, _, err := loadManifest(p1, key)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on bad JSON, got %v", err)
	}

	// 2. len(payload.DEKs) == 0
	p2 := filepath.Join(tempDir, "empty_deks.encz")
	createCustomEncryptedManifest(t, p2, key, nil, func(p *manifestPayload) {
		p.DEKs = nil
	})
	_, _, err = loadManifest(p2, key)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on empty DEKs, got %v", err)
	}

	// 3. payload.KEKRotationDays <= 0
	p3 := filepath.Join(tempDir, "zero_days.encz")
	createCustomEncryptedManifest(t, p3, key, nil, func(p *manifestPayload) {
		p.KEKRotationDays = 0
	})
	_, _, err = loadManifest(p3, key)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on zero rotation days, got %v", err)
	}

	// 4. activeDEKFromPayload returns false
	p4 := filepath.Join(tempDir, "bad_active_dek.encz")
	createCustomEncryptedManifest(t, p4, key, nil, func(p *manifestPayload) {
		p.ActiveDEKKeyID = 99 // not in DEKs list
	})
	_, _, err = loadManifest(p4, key)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on bad active DEK, got %v", err)
	}

	// 5. Zero time fields initialized correctly
	p5 := filepath.Join(tempDir, "zero_times.encz")
	createCustomEncryptedManifest(t, p5, key, nil, nil) // creates payload with zero times
	payload, _, err := loadManifest(p5, key)
	if err != nil {
		t.Fatalf("loadManifest: %v", err)
	}
	if payload.LastKEKRotationAt.IsZero() || payload.NextKEKRotationDueAt.IsZero() ||
		payload.LastDEKRotationAt.IsZero() || payload.NextDEKRotationDueAt.IsZero() {
		t.Errorf("expected zero times to be resolved, got: %+v", payload)
	}
}

func TestActiveDEKFromPayloadEdgeCase(t *testing.T) {
	payload := manifestPayload{
		ActiveDEKKeyID: 99,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "abc"},
		},
	}
	_, ok := activeDEKFromPayload(&payload)
	if ok {
		t.Error("expected activeDEKFromPayload to return false")
	}
}

func TestNextManifestKeyIDEdgeCase(t *testing.T) {
	payload := manifestPayload{
		DEKs: []manifestDEK{
			{KeyID: 5},
			{KeyID: 3},
		},
	}
	nextID := nextManifestKeyID(payload)
	if nextID != 6 {
		t.Errorf("expected nextManifestKeyID to be 6, got %d", nextID)
	}
}

func TestAtomicWriteFileRenameFailure(t *testing.T) {
	// Pass directory path as target file name so Rename fails
	dir := t.TempDir()
	err := atomicWriteFile(dir, []byte("data"), 0600)
	if err == nil {
		t.Fatal("expected atomicWriteFile to fail when target is a directory")
	}
}

func TestFillActiveKeyErrors(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "fill_active.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	payload := manifestPayload{
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	policy := RotationPolicy{}
	handle, err := registerKeyRegistry(manifestPath, masterKey, payload, policy, true)
	if err != nil {
		t.Fatalf("registerKeyRegistry: %v", err)
	}
	defer destroyKeyRegistry(handle)

	// Call fillActiveKey with a small buffer size to trigger size error
	reg, ok := getKeyRegistry(handle)
	if !ok {
		t.Fatal("failed to get registry")
	}

	buf := make([]byte, 10)
	_, ok = reg.fillActiveKey(buf)
	if ok {
		t.Error("expected fillActiveKey to return false for small buffer")
	}

	// Make active DEK rotation fail during fillActiveKey
	reg.allowDEKRotation = true
	reg.payload.NextDEKRotationDueAt = time.Now().Add(-time.Hour)
	reg.manifestPath = "/nonexistent-dir/manifest.encz" // causes rotate to fail to save manifest
	_, ok = reg.fillActiveKey(make([]byte, 32))
	if ok {
		t.Error("expected fillActiveKey to fail when active DEK rotation fails")
	}
}

func TestEnczKeysExportedFunctionsActiveKeyNotFound(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "fill_active_nf.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	payload := manifestPayload{
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	policy := RotationPolicy{}
	handle, err := registerKeyRegistry(manifestPath, masterKey, payload, policy, false)
	if err != nil {
		t.Fatalf("registerKeyRegistry: %v", err)
	}
	defer destroyKeyRegistry(handle)

	reg, ok := getKeyRegistry(handle)
	if !ok {
		t.Fatal("failed to get registry")
	}

	// Delete active key from registry map to trigger key not found path
	reg.mu.Lock()
	delete(reg.keys, reg.payload.ActiveDEKKeyID)
	reg.mu.Unlock()

	var activeID uint32
	var buf [32]byte
	if callEnczGoFillActiveKey(handle, &activeID, &buf[0]) != 0 {
		t.Error("expected callEnczGoFillActiveKey to fail when active DEK is missing from registry keys")
	}
}

func TestReKeySaveManifestError(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rekey_save_err.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Make manifest path unwritable right before rekey
	db.manifestPath = "/nonexistent-dir/manifest.encz"
	err = db.ReKey("Pass123", "NewPass123")
	if err == nil {
		t.Fatal("expected ReKey to fail when manifest cannot be saved")
	}
}

func TestSetRotationPolicyErrors(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "policy_errs.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// 1. loadManifest failure
	if err := os.Remove(db.manifestPath); err != nil {
		t.Fatalf("remove: %v", err)
	}
	err = db.SetRotationPolicy(RotationPolicy{KEKRotationDays: 10})
	if err == nil {
		t.Fatal("expected SetRotationPolicy to fail when manifest is missing")
	}

	// 2. saveManifest failure
	// Re-create a valid DB first
	dbPath2 := filepath.Join(tempDir, "policy_errs2.db")
	db2, err := OpenEncz(dbPath2, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db2.Close()

	db2.manifestPath = "/nonexistent-dir/manifest.encz"
	err = db2.SetRotationPolicy(RotationPolicy{KEKRotationDays: 10})
	if err == nil {
		t.Fatal("expected SetRotationPolicy to fail when manifest cannot be saved")
	}
}

func TestDriverRegisterErrors(t *testing.T) {
	// Save original bridge state
	origDriverOnce := registerDriverOnce
	origEnczOnce := registerEnczOnce
	origDriverErr := registerDriverErr
	origEnczErr := registerEnczErr

	defer func() {
		registerDriverOnce = origDriverOnce
		registerEnczOnce = origEnczOnce
		registerDriverErr = origDriverErr
		registerEnczErr = origEnczErr
	}()

	// Force Register to call registerEncz again and return simulated error
	registerDriverOnce = sync.Once{}
	registerEnczOnce = sync.Once{}
	registerDriverErr = nil
	registerEnczErr = errors.New("simulated bridge registration error")

	err := Register()
	if err == nil || !strings.Contains(err.Error(), "simulated bridge registration error") {
		t.Errorf("expected simulated bridge registration error, got %v", err)
	}

	// Verify mustRegister propagates the error
	err = mustRegister()
	if err == nil || !strings.Contains(err.Error(), "simulated bridge registration error") {
		t.Errorf("expected mustRegister to propagate error, got %v", err)
	}

	// Verify OpenWithOptions also fails immediately at mustRegister
	_, err = OpenWithOptions("test.db", Options{Key: "Pass123"})
	if err == nil || !strings.Contains(err.Error(), "simulated bridge registration error") {
		t.Errorf("expected OpenWithOptions to fail when mustRegister fails, got %v", err)
	}
}

func TestReKeyEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rekey_edge.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// 1. Empty keys
	if err := db.ReKey("", "newkey"); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("expected ErrKeyRequired, got %v", err)
	}
	if err := db.ReKey("oldkey", ""); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("expected ErrKeyRequired, got %v", err)
	}

	// 2. Wrong old key
	if err := db.ReKey("WrongOldKey123", "NewKey123"); !errors.Is(err, ErrCurrentKeyMismatch) {
		t.Errorf("expected ErrCurrentKeyMismatch, got %v", err)
	}
}

func TestFileExistsManifestError(t *testing.T) {
	// A path with null byte in ManifestPath should cause os.Stat(manifestPath) to fail.
	// We use a valid dbPath to bypass the dbExists check.
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "valid.db")
	if err := os.WriteFile(dbPath, []byte("fake db"), 0600); err != nil {
		t.Fatalf("failed to write db: %v", err)
	}

	_, err := OpenWithOptions(dbPath, Options{
		Key:          "Pass123",
		ManifestPath: "invalid\x00manifest",
	})
	if err == nil {
		t.Fatal("expected error due to null byte in manifest path, got nil")
	}
}

func TestRegisterKeyRegistryBuildKeyBuffersError(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "reg_err.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	// ActiveDEKKeyID not in DEKs list -> causes buildRegistryKeyBuffers to fail
	payload := manifestPayload{
		ActiveDEKKeyID: 99,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	_, err := registerKeyRegistry(manifestPath, masterKey, payload, RotationPolicy{}, false)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestUpdateKeyRegistryManifestBuildKeyBuffersError(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "reg_upd_err.encz")
	masterKey := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer masterKey.Destroy()

	payload := manifestPayload{
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	handle, err := registerKeyRegistry(manifestPath, masterKey, payload, RotationPolicy{}, false)
	if err != nil {
		t.Fatalf("registerKeyRegistry: %v", err)
	}
	defer destroyKeyRegistry(handle)

	// Call updateKeyRegistryManifest with invalid payload
	invalidPayload := manifestPayload{
		ActiveDEKKeyID: 99,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
		},
	}
	err = updateKeyRegistryManifest(handle, invalidPayload, RotationPolicy{})
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestBuildRegistryKeyBuffersLoopDestroy(t *testing.T) {
	// First DEK is valid, second DEK has invalid hex -> triggers the cleanup loop inside buildRegistryKeyBuffers
	payload := manifestPayload{
		ActiveDEKKeyID: 1,
		DEKs: []manifestDEK{
			{KeyID: 1, DEKHex: "0000000000000000000000000000000000000000000000000000000000000001"},
			{KeyID: 2, DEKHex: "invalid-hex"},
		},
	}
	_, err := buildRegistryKeyBuffers(payload)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestBackupInternalErrors(t *testing.T) {
	// 1. TestBackup_CopyPagesError
	t.Run("CopyPagesError", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "copy_pages.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		// Close underlying sql.DB pool directly, leaving db.closed = false
		db.DB.Close()

		err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
		if err == nil {
			t.Fatal("expected error when source sql.DB is closed")
		}
	})

	// 2. TestBackup_VacuumError
	t.Run("VacuumError", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "vacuum.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		if _, err := db.Exec("CREATE TABLE t(x); INSERT INTO t VALUES(randomblob(10000));"); err != nil {
			t.Fatalf("insert: %v", err)
		}

		srcFi, err := os.Stat(dbPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		srcSize := srcFi.Size()

		toFile := filepath.Join(tempDir, "backup.zip")
		backupDBPath := backupTempDBPath(db.path, toFile)
		backupManifestPath := backupDBPath + ".encz"

		// Start polling goroutine to acquire exclusive lock on backup DB to force VACUUM failure
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var backupHandle uint64
			for {
				keyRegistryMu.RLock()
				for handle, reg := range keyRegistries {
					if reg.manifestPath == backupManifestPath {
						backupHandle = handle
					}
				}
				keyRegistryMu.RUnlock()
				if backupHandle != 0 {
					break
				}
				time.Sleep(1 * time.Millisecond)
			}

			// Wait for copyDatabasePages to complete
			for {
				if fi, err := os.Stat(backupDBPath); err == nil && fi.Size() >= srcSize {
					os.Rename(backupDBPath, backupDBPath+".moved")
					break
				}
				time.Sleep(1 * time.Millisecond)
			}

			time.Sleep(100 * time.Millisecond)
		}()

		err = db.Backup(toFile, BackupOptions{})
		wg.Wait()
		if err == nil {
			t.Fatal("expected error during VACUUM on locked backup DB")
		} else {
			t.Logf("ACTUAL VACUUM TEST ERROR: %v", err)
		}
	})

	// 3. TestBackup_ReadManifestError
	t.Run("ReadManifestError", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "read_manifest.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		toFile := filepath.Join(tempDir, "backup.zip")
		backupDBPath := backupTempDBPath(db.path, toFile)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := os.Stat(backupDBPath); err == nil {
					os.Remove(db.manifestPath) // delete source manifest
					break
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()

		err = db.Backup(toFile, BackupOptions{})
		wg.Wait()
		if err == nil {
			t.Fatal("expected error when source manifest is deleted during backup")
		}
	})

	// 4. TestBackup_WriteManifestError
	t.Run("WriteManifestError", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "write_manifest.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		toFile := filepath.Join(tempDir, "backup.zip")
		backupDBPath := backupTempDBPath(db.path, toFile)
		backupManifestPath := backupDBPath + ".encz"

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := os.Stat(backupDBPath); err == nil {
					os.MkdirAll(backupManifestPath, 0755) // block manifest file creation
					break
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()

		err = db.Backup(toFile, BackupOptions{})
		wg.Wait()
		os.RemoveAll(backupManifestPath)
		if err == nil {
			t.Fatal("expected error when backup manifest path is blocked by a directory")
		}
	})

	// 5. TestBackup_WriteArchiveError
	t.Run("WriteArchiveError", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "write_archive.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		toFile := filepath.Join(tempDir, "backup.zip")
		backupDBPath := backupTempDBPath(db.path, toFile)
		zipTempPath := toFile + ".plainzip"

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if _, err := os.Stat(backupDBPath); err == nil {
					os.MkdirAll(zipTempPath, 0755) // block zip creation
					break
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()

		err = db.Backup(toFile, BackupOptions{})
		wg.Wait()
		os.RemoveAll(zipTempPath)
		if err == nil {
			t.Fatal("expected error when temp DB is deleted before archiving")
		} else {
			t.Logf("WRITE ARCHIVE ERROR: %v", err)
		}
	})
	
	// 6. TestBackup_OpenSQLDBFailure (updated version)
	t.Run("OpenSQLDBFailure", func(t *testing.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "backup_sql_fail.db")
		db, err := OpenEncz(dbPath, "Pass123")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		// Temporarily change db.path to point to a nonexistent directory
		origPath := db.path
		db.path = "/nonexistent-dir-for-backup/db.db"
		defer func() { db.path = origPath }()

		err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
		if err == nil {
			t.Fatal("expected error opening SQL DB in nonexistent directory")
		}
	})
}

func TestAutoRewrapSaveManifestError(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "autorewrap_err.db")
	key := "Pass123"

	db, err := OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()

	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	manifestPath := dbPath + ".encz"
	payload, policy, err := loadManifest(manifestPath, keyBuf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	now := timeNowUTC()
	payload.LastKEKRotationAt = now.Add(-30 * 24 * time.Hour)
	payload.NextKEKRotationDueAt = now.Add(-20 * 24 * time.Hour)
	policy.AutoRewrap = true

	if err := saveManifest(manifestPath, keyBuf, payload); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Make parent directory read-only (no-write) so saveManifest fails during auto-rewrap
	dir := filepath.Dir(manifestPath)
	os.Chmod(dir, 0500)
	defer os.Chmod(dir, 0755)

	_, err = OpenWithOptions(dbPath, Options{
		Key:            key,
		RotationPolicy: &policy,
	})
	if err == nil {
		t.Fatal("expected error when manifest save fails during auto-rewrap")
	} else {
		t.Logf("AUTO-REWRAP ERROR: %v", err)
	}
}

func TestResolveOpenOptionsRegisterKeyRegistryError(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "reg_fail.db")
	key := "Pass123"

	// Create valid DB
	db, err := OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()

	// Corrupt manifest's DEKHex to invalid hex, so buildRegistryKeyBuffers fails inside resolveOpenOptions
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	manifestPath := dbPath + ".encz"
	
	createCustomEncryptedManifest(t, manifestPath, keyBuf, nil, func(p *manifestPayload) {
		p.DEKs[0].DEKHex = "invalid-hex-chars!!"
	})

	_, err = OpenEncz(dbPath, key)
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestTestBackupHelperMoreErrors(t *testing.T) {
	tempDir := t.TempDir()
	key := "Pass123"

	// 1. Missing db file in zip
	zipPath := filepath.Join(tempDir, "missing_db.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("test.bak.encz")
	w.Write([]byte("fake manifest content"))
	zw.Close()
	f.Close()

	encZipPath := filepath.Join(tempDir, "missing_db.zip.enc")
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	encryptBackupArchive(zipPath, encZipPath, keyBuf)

	err := TestBackup(encZipPath, key, filepath.Join(tempDir, "extract_missing_db"))
	if err == nil {
		t.Fatal("expected TestBackup to fail when database is missing from zip")
	}

	// 2. Corrupt database in zip (fails integrity check)
	zipPathCorrupt := filepath.Join(tempDir, "corrupt_db.zip")
	f2, _ := os.Create(zipPathCorrupt)
	zw2 := zip.NewWriter(f2)
	
	// Create a real manifest
	dbPath := filepath.Join(tempDir, "src.db")
	db, _ := OpenEncz(dbPath, key)
	db.Exec("CREATE TABLE t(x)")
	db.Close()
	
	mBytes, _ := os.ReadFile(dbPath + ".encz")
	wm, _ := zw2.Create("test.bak.encz")
	wm.Write(mBytes)

	// Write corrupted database bytes (corrupt page 2, keeping page 1 intact)
	dbBytes, _ := os.ReadFile(dbPath)
	if len(dbBytes) > 4096 {
		for i := 4096; i < 4096+100 && i < len(dbBytes); i++ {
			dbBytes[i] ^= 0xFF
		}
	} else {
		for i := 100; i < 200 && i < len(dbBytes); i++ {
			dbBytes[i] ^= 0xFF
		}
	}
	wd, _ := zw2.Create("test.bak")
	wd.Write(dbBytes)
	
	zw2.Close()
	f2.Close()

	encZipPathCorrupt := filepath.Join(tempDir, "corrupt_db.zip.enc")
	encryptBackupArchive(zipPathCorrupt, encZipPathCorrupt, keyBuf)

	err = TestBackup(encZipPathCorrupt, key, filepath.Join(tempDir, "extract_corrupt_db"))
	if err == nil {
		t.Fatal("expected TestBackup to fail when database integrity check fails")
	}
}

func TestBackupNullByteDbPath(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "null_db.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Set db.path to contain a null byte in the directory portion.
	// This will bypass fileExists(toFile) check but fail fileExists(backupDBPath) at line 108.
	db.path = "invalid\x00dir/db.db"
	err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
	if err == nil {
		t.Fatal("expected error with null byte in db.path")
	}
}

func TestBackupRegisterKeyRegistryError(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "reg_fail_backup.db")
	key := "Pass123"
	db, err := OpenEncz(dbPath, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Overwrite the manifest file on disk with invalid DEKHex chars.
	// loadManifest will succeed, but registerKeyRegistry in Backup will fail.
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	createCustomEncryptedManifest(t, db.manifestPath, keyBuf, nil, func(p *manifestPayload) {
		p.DEKs[0].DEKHex = "invalid-hex-chars!!"
	})

	err = db.Backup(filepath.Join(tempDir, "backup.zip"), BackupOptions{})
	if !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid, got %v", err)
	}
}

func TestTestBackupHelperManifestCorrupt(t *testing.T) {
	tempDir := t.TempDir()
	key := "Pass123"

	// 1. Manifest is corrupted (fails loadManifest)
	zipPath := filepath.Join(tempDir, "corrupt_manifest.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("test.bak.encz")
	w.Write([]byte("invalid encrypted manifest content"))
	w2, _ := zw.Create("test.bak")
	w2.Write([]byte("dummy db content"))
	zw.Close()
	f.Close()

	encZipPath := filepath.Join(tempDir, "corrupt_manifest.zip.enc")
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	encryptBackupArchive(zipPath, encZipPath, keyBuf)

	err := TestBackup(encZipPath, key, filepath.Join(tempDir, "extract_corrupt_manifest"))
	if err == nil {
		t.Fatal("expected TestBackup to fail when manifest is corrupted")
	}

	// 2. Manifest has invalid DEKHex (fails registerKeyRegistry)
	zipPathRegFail := filepath.Join(tempDir, "reg_fail_zip.zip")
	f2, _ := os.Create(zipPathRegFail)
	zw2 := zip.NewWriter(f2)
	
	// Create manifest with invalid DEKHex
	mPath := filepath.Join(tempDir, "invalid_dek.encz")
	createCustomEncryptedManifest(t, mPath, keyBuf, nil, func(p *manifestPayload) {
		p.DEKs[0].DEKHex = "invalid-hex!!"
	})
	mBytes, _ := os.ReadFile(mPath)
	wm, _ := zw2.Create("test.bak.encz")
	wm.Write(mBytes)
	
	// Write dummy database bytes
	wd, _ := zw2.Create("test.bak")
	wd.Write([]byte("dummy db"))
	
	zw2.Close()
	f2.Close()

	encZipPathRegFail := filepath.Join(tempDir, "reg_fail_zip.zip.enc")
	encryptBackupArchive(zipPathRegFail, encZipPathRegFail, keyBuf)

	err = TestBackup(encZipPathRegFail, key, filepath.Join(tempDir, "extract_reg_fail"))
	if err == nil {
		t.Fatal("expected TestBackup to fail when manifest has invalid DEKHex")
	}
}

func TestRestoreBackupErrors(t *testing.T) {
	tempDir := t.TempDir()
	key := "Pass123"

	// 1. zip.OpenReader(zipPath) error
	// Create an encrypted archive containing invalid zip bytes
	plainPath := filepath.Join(tempDir, "not_a_zip.zip")
	os.WriteFile(plainPath, []byte("not a zip file at all"), 0600)
	encZipPath := filepath.Join(tempDir, "invalid_zip.zip.enc")
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	if err := encryptBackupArchive(plainPath, encZipPath, keyBuf); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	err := RestoreBackup(encZipPath, key, filepath.Join(tempDir, "restore_fail"), true)
	if err == nil {
		t.Fatal("expected RestoreBackup to fail with invalid zip reader")
	}

	// 2. os.MkdirAll(toFolder) error
	// Pass unwritable folder path
	zipPath := filepath.Join(tempDir, "valid.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	zw.Close()
	f.Close()
	encZipPathValid := filepath.Join(tempDir, "valid.zip.enc")
	keyBuf2 := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf2.Destroy()
	encryptBackupArchive(zipPath, encZipPathValid, keyBuf2)

	err = RestoreBackup(encZipPathValid, key, "/invalid-dir-no-perm/folder", true)
	if err == nil {
		t.Fatal("expected RestoreBackup to fail when target folder cannot be created")
	}
}

func TestExtractBackupArchiveErrors(t *testing.T) {
	tempDir := t.TempDir()

	// 1. os.MkdirAll(tempFolder) error
	_, _, err := extractBackupArchive("zipfile", "/invalid-dir-no-perm/folder")
	if err == nil {
		t.Fatal("expected extractBackupArchive to fail when tempFolder cannot be created")
	}

	// 2. zip.OpenReader error
	_, _, err = extractBackupArchive("invalidzip", tempDir)
	if err == nil {
		t.Fatal("expected extractBackupArchive to fail with invalid zip file")
	}

	// 3. os.MkdirAll(filepath.Dir(target)) error
	zipPath := filepath.Join(tempDir, "dir_err.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	// Create entry with folder structure
	zw.Create("subdir/test.bak")
	zw.Close()
	f.Close()

	// Pre-create "subdir" as a regular file so MkdirAll fails
	os.WriteFile(filepath.Join(tempDir, "subdir"), []byte("file"), 0600)
	_, _, err = extractBackupArchive(zipPath, tempDir)
	if err == nil {
		t.Fatal("expected extractBackupArchive to fail when subdirectory creation is blocked by a file")
	}
	os.Remove(filepath.Join(tempDir, "subdir"))

	// 4. extractZipEntry fails due to target blocked by directory
	zipPath2 := filepath.Join(tempDir, "extract_block.zip")
	f2, _ := os.Create(zipPath2)
	zw2 := zip.NewWriter(f2)
	zw2.Create("test.bak")
	zw2.Close()
	f2.Close()

	// Pre-create "test.bak" as a directory
	os.MkdirAll(filepath.Join(tempDir, "test.bak"), 0755)
	_, _, err = extractBackupArchive(zipPath2, tempDir)
	if err == nil {
		t.Fatal("expected extractBackupArchive to fail when target file is blocked by a directory")
	}
	os.RemoveAll(filepath.Join(tempDir, "test.bak"))
}

func TestDecryptBackupArchiveErrors(t *testing.T) {
	// 1. tempFolder is empty
	_, err := decryptBackupArchive("file", "key", "")
	if err == nil {
		t.Fatal("expected decryptBackupArchive to fail for empty tempFolder")
	}
}

func TestDecryptBackupArchiveToFileParseError(t *testing.T) {
	tempDir := t.TempDir()
	keyBuf := memguard.NewBufferFromBytes([]byte("key"))
	defer keyBuf.Destroy()

	// Write file with invalid header (short file)
	filePath := filepath.Join(tempDir, "short.enc")
	os.WriteFile(filePath, []byte("short"), 0600)

	err := decryptBackupArchiveToFile(filePath, filepath.Join(tempDir, "out.zip"), keyBuf)
	if !errors.Is(err, ErrBackupArchiveInvalid) {
		t.Errorf("expected ErrBackupArchiveInvalid, got %v", err)
	}
}

func TestAddPathToZipOpenError(t *testing.T) {
	tempDir := t.TempDir()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	defer zw.Close()

	filePath := filepath.Join(tempDir, "noread.txt")
	os.WriteFile(filePath, []byte("secret"), 0600)
	os.Chmod(filePath, 0000) // no read/write permissions
	defer os.Chmod(filePath, 0600)

	err := addPathToZip(zw, filePath, BackupCompressionDeflate)
	if err == nil {
		t.Fatal("expected addPathToZip to fail for unreadable file")
	}
}

func TestBuildDSNAllOptions(t *testing.T) {
	timeout := 5000
	opts := Options{
		Key: "somekey",
		URIParameters: map[string]string{
			"custom_param": "custom_val",
		},
		JournalMode: "WAL",
		BusyTimeoutMillis: &timeout,
	}
	dsn := BuildDSN("/path/to/db.db", opts)
	if !strings.Contains(dsn, "_busy_timeout=5000") {
		t.Errorf("expected DSN to contain _busy_timeout=5000, got %s", dsn)
	}
	if !strings.Contains(dsn, "_journal_mode=WAL") {
		t.Errorf("expected DSN to contain _journal_mode=WAL, got %s", dsn)
	}
	if !strings.Contains(dsn, "custom_param=custom_val") {
		t.Errorf("expected DSN to contain custom_param=custom_val, got %s", dsn)
	}
}

func TestSQLDBNonNil(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sql_db_non_nil.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("OpenEncz failed: %v", err)
	}
	defer db.Close()
	if db.SQLDB() == nil {
		t.Error("expected SQLDB() on non-nil DB to return sql.DB")
	}
}

func TestReKeySaveManifestErrorCorrected(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "rekey_save_err_corr.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if err := os.Chmod(tempDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(tempDir, 0755)

	err = db.ReKey("Pass123", "NewPass123")
	if err == nil {
		t.Fatal("expected ReKey to fail when saveManifest fails")
	}
}

func TestSetRotationPolicyInvalid(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "set_policy_inv.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	err = db.SetRotationPolicy(RotationPolicy{KEKRotationDays: -1})
	if !errors.Is(err, ErrRotationPolicyInvalid) {
		t.Errorf("expected ErrRotationPolicyInvalid, got %v", err)
	}
}

func TestSetRotationPolicySaveManifestErrorCorrected(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "set_policy_save_err.db")
	db, err := OpenEncz(dbPath, "Pass123")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if err := os.Chmod(tempDir, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(tempDir, 0755)

	err = db.SetRotationPolicy(RotationPolicy{KEKRotationDays: 10})
	if err == nil {
		t.Fatal("expected SetRotationPolicy to fail when saveManifest fails")
	}
}

func TestSQLOpenError(t *testing.T) {
	_, err := openSQLDB("file:test.db?%zz")
	if err == nil {
		t.Fatal("expected openSQLDB to fail with invalid DSN")
	}
}

func TestGetArgonParamsDefault(t *testing.T) {
	origCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("dummy", flag.ContinueOnError)
	defer func() {
		flag.CommandLine = origCommandLine
	}()

	timeParam, memParam, threadsParam := getArgonParams()
	if timeParam != defaultArgonTime || memParam != defaultArgonMemory || threadsParam != defaultArgonThreads {
		t.Errorf("expected default Argon parameters, got: time=%d, mem=%d, threads=%d", timeParam, memParam, threadsParam)
	}
}

func TestSaveManifestJSONMarshalError(t *testing.T) {
	tempDir := t.TempDir()
	mPath := filepath.Join(tempDir, "marshal_err.encz")
	keyBuf := memguard.NewBufferFromBytes([]byte("Pass123"))
	defer keyBuf.Destroy()

	badPayload := manifestPayload{
		CreatedAt: time.Date(15000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	err := saveManifest(mPath, keyBuf, badPayload)
	if err == nil {
		t.Fatal("expected saveManifest to fail due to time JSON marshalling error")
	}
}

func TestEncryptDecryptManifestPayloadErrors(t *testing.T) {
	// 1. aes.NewCipher error in encrypt
	_, err := encryptManifestPayload(make([]byte, 5), manifestHeader{}, []byte("plain"))
	if err == nil {
		t.Error("expected aes.NewCipher failure for invalid key size in encrypt")
	}

	// 2. aes.NewCipher error in decrypt
	_, err = decryptManifestPayload(make([]byte, 5), manifestHeader{}, []byte("cipher"))
	if err == nil {
		t.Error("expected aes.NewCipher failure for invalid key size in decrypt")
	}
}

func TestSyncParentDirOpenError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not sync directory handles")
	}

	tempDir := t.TempDir()
	subDir := filepath.Join(tempDir, "noread_dir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Change permission of subDir to 0300 (write/execute only, no read)
	if err := os.Chmod(subDir, 0300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(subDir, 0755)

	err := syncParentDir(subDir)
	if err == nil {
		t.Fatal("expected syncParentDir to fail when directory cannot be opened")
	}
}

func TestSyncParentDirWindowsIsNoop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only behavior")
	}

	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	if err := syncParentDir(missingDir); err != nil {
		t.Fatalf("syncParentDir(%q): %v; Windows directory sync must be a no-op", missingDir, err)
	}
}

func TestRestoreBackupExtractErrors(t *testing.T) {
	tempDir := t.TempDir()
	key := "Pass123"

	// 1. MkdirAll error in RestoreBackup
	zipPath := filepath.Join(tempDir, "mkdir_err.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	zw.Create("subdir/test.bak")
	zw.Close()
	f.Close()
	encZipPath := filepath.Join(tempDir, "mkdir_err.zip.enc")
	keyBuf := memguard.NewBufferFromBytes([]byte(key))
	defer keyBuf.Destroy()
	encryptBackupArchive(zipPath, encZipPath, keyBuf)

	restoreDir := filepath.Join(tempDir, "restore_mkdir")
	os.MkdirAll(restoreDir, 0755)
	// Block "subdir" by writing a file
	os.WriteFile(filepath.Join(restoreDir, "subdir"), []byte("blocker"), 0600)

	err := RestoreBackup(encZipPath, key, restoreDir, true)
	if err == nil {
		t.Fatal("expected RestoreBackup to fail when directory creation is blocked")
	}

	// 2. extractZipEntry error in RestoreBackup
	zipPath2 := filepath.Join(tempDir, "extract_err.zip")
	f2, _ := os.Create(zipPath2)
	zw2 := zip.NewWriter(f2)
	zw2.Create("test.bak")
	zw2.Close()
	f2.Close()
	encZipPath2 := filepath.Join(tempDir, "extract_err.zip.enc")
	encryptBackupArchive(zipPath2, encZipPath2, keyBuf)

	restoreDir2 := filepath.Join(tempDir, "restore_extract")
	os.MkdirAll(restoreDir2, 0755)
	// Block "test.bak" by creating a directory
	os.MkdirAll(filepath.Join(restoreDir2, "test.bak"), 0755)

	err = RestoreBackup(encZipPath2, key, restoreDir2, true)
	if err == nil {
		t.Fatal("expected RestoreBackup to fail when target file is blocked by a directory")
	}
}





