package tests

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

// TestCryptoKeyHex validates setting the raw 32-byte key directly as a hex-encoded string.
func TestCryptoKeyHex(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexkey.db")
	hexKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" // 32 bytes

	// 1. Open and write using crypto_key_hex in URI parameters
	opts := encz.Options{
		URIParameters: map[string]string{
			"vfs":                "encz",
			"crypto_key_hex":     hexKey,
			"crypto_compression": "none",
		},
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open database with hex key: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE hex_test (val TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO hex_test VALUES ("hex-success")`)
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	// 2. Reopen with same key, read should succeed
	dbReopen, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to reopen: %v", err)
	}
	defer dbReopen.Close()

	var val string
	err = dbReopen.QueryRow(`SELECT val FROM hex_test`).Scan(&val)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val != "hex-success" {
		t.Errorf("expected 'hex-success', got %q", val)
	}

	// 3. Reopen with a different hex key, read should fail
	wrongHexKey := "9999999999999999999999999999999999999999999999999999999999999999"
	wrongOpts := encz.Options{
		URIParameters: map[string]string{
			"vfs":                "encz",
			"crypto_key_hex":     wrongHexKey,
			"crypto_compression": "none",
		},
	}
	dbWrong, err := encz.OpenWithOptions(dbPath, wrongOpts)
	if err == nil {
		defer dbWrong.Close()
		err = dbWrong.QueryRow(`SELECT val FROM hex_test`).Scan(&val)
		if err == nil {
			t.Error("expected decryption failure with wrong hex key, but it succeeded")
		}
	}
}

// TestCryptoKeyEnv validates fetching the encryption passphrase from an environment variable.
func TestCryptoKeyEnv(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "envkey.db")
	envVarName := "TEST_DATABASE_CRYPTO_PASSPHRASE"
	passphrase := "SecurePassphraseViaEnv123!!!"

	// Set env variable
	os.Setenv(envVarName, passphrase)
	defer os.Unsetenv(envVarName)

	// 1. Open and write using crypto_key_env
	opts := encz.Options{
		URIParameters: map[string]string{
			"vfs":                "encz",
			"crypto_key_env":     envVarName,
			"crypto_compression": "none",
		},
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open database with env key: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE env_test (val TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO env_test VALUES ("env-success")`)
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	// 2. Reopen and verify read succeeds
	dbReopen, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer dbReopen.Close()

	var val string
	err = dbReopen.QueryRow(`SELECT val FROM env_test`).Scan(&val)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val != "env-success" {
		t.Errorf("expected 'env-success', got %q", val)
	}

	// 3. Clear or change the environment variable, read should fail
	os.Setenv(envVarName, "IncorrectPassphrase!!!")
	dbWrong, err := encz.OpenWithOptions(dbPath, opts)
	if err == nil {
		defer dbWrong.Close()
		err = dbWrong.QueryRow(`SELECT val FROM env_test`).Scan(&val)
		if err == nil {
			t.Error("expected decryption failure when environment variable passphrase was changed, but it succeeded")
		}
	}
}

// TestCryptoPragmas verifies setting keys and compression modes via custom VFS PRAGMAs.
func TestCryptoPragmas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragmakey.db")

	// Helper to execute pragma and return result
	runPragma := func(db *sql.DB, pragma string) (string, error) {
		var res string
		err := db.QueryRow(pragma).Scan(&res)
		return res, err
	}

	// 0. Pre-initialize the database container with the target key.
	// New database container files cannot be initialized keyless due to VFS structure requirements.
	initDB, err := encz.OpenEncz(dbPath, "MyPragmaSecret", "none")
	if err != nil {
		t.Fatalf("failed to initialize DB: %v", err)
	}
	initDB.Close()

	// 1. Open existing database with VFS enabled but NO key configured in URI.
	// We call sql.Open directly instead of OpenWithOptions to bypass the automatic Ping() checks,
	// allowing us to configure the passphrase using PRAGMA before any page reads occur.
	dsn := encz.BuildDSN(dbPath, encz.Options{
		URIParameters: map[string]string{"vfs": "encz"},
	})
	db, err := sql.Open(encz.DriverName, dsn)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}

	// Run PRAGMA crypto_key to configure key BEFORE database I/O
	res, err := runPragma(db, `PRAGMA crypto_key = "MyPragmaSecret"`)
	if err != nil || res != "ok" {
		db.Close()
		t.Fatalf("PRAGMA crypto_key failed: %s, err=%v", res, err)
	}

	// Set compression and level via PRAGMA
	res, err = runPragma(db, `PRAGMA crypto_compression = "zstd"`)
	if err != nil || res != "zstd" {
		db.Close()
		t.Fatalf("PRAGMA crypto_compression failed: %s, err=%v", res, err)
	}

	res, err = runPragma(db, `PRAGMA crypto_compression_level = "5"`)
	if err != nil || res != "5" {
		db.Close()
		t.Fatalf("PRAGMA crypto_compression_level failed: %s, err=%v", res, err)
	}

	// Perform database I/O to lock configuration
	_, err = db.Exec(`CREATE TABLE pragma_table (val TEXT)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	_, err = db.Exec(`INSERT INTO pragma_table VALUES ("pragma-success")`)
	if err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}

	// 2. Query PRAGMA crypto_status
	var status string
	err = db.QueryRow(`PRAGMA crypto_status`).Scan(&status)
	if err != nil {
		db.Close()
		t.Fatalf("PRAGMA crypto_status failed: %v", err)
	}

	t.Logf("crypto_status: %q", status)
	// Parse status fields
	if !strings.Contains(status, "cipher=aes-256-gcm") ||
		!strings.Contains(status, "key=set") ||
		!strings.Contains(status, "compression=zstd") ||
		!strings.Contains(status, "level=5") {
		t.Errorf("crypto_status output does not contain expected values: %q", status)
	}

	// 3. Verify PRAGMA configuration locking: attempting to change configuration after I/O should fail
	res, err = runPragma(db, `PRAGMA crypto_key = "NewSecret"`)
	if err == nil {
		t.Error("expected setting crypto_key via PRAGMA after database IO to fail, but it succeeded")
	} else if !strings.Contains(err.Error(), "must run before database IO") {
		t.Errorf("unexpected error message for locked pragma config: %v", err)
	}

	db.Close()

	// 4. Reopen and set key via PRAGMA before querying
	dbReopen, err := sql.Open(encz.DriverName, dsn)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer dbReopen.Close()

	res, err = runPragma(dbReopen, `PRAGMA crypto_key = "MyPragmaSecret"`)
	if err != nil || res != "ok" {
		t.Fatalf("reopen PRAGMA crypto_key failed: %s, err=%v", res, err)
	}

	var val string
	err = dbReopen.QueryRow(`SELECT val FROM pragma_table`).Scan(&val)
	if err != nil {
		t.Fatalf("reopen read failed: %v", err)
	}
	if val != "pragma-success" {
		t.Errorf("expected 'pragma-success', got %q", val)
	}
}
