package tests

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

func TestCryptoKeyHex(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "hexkey.db")
	hexKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	opts := encz.Options{
		URIParameters: map[string]string{
			"vfs":            "encz",
			"crypto_key_hex": hexKey,
		},
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open database with hex key: %v", err)
	}

	if _, err := db.Exec(`CREATE TABLE hex_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO hex_test VALUES ("hex-success")`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	dbReopen, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to reopen: %v", err)
	}
	defer dbReopen.Close()

	var val string
	if err := dbReopen.QueryRow(`SELECT val FROM hex_test`).Scan(&val); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val != "hex-success" {
		t.Errorf("expected 'hex-success', got %q", val)
	}

	wrongHexKey := "9999999999999999999999999999999999999999999999999999999999999999"
	wrongOpts := encz.Options{
		URIParameters: map[string]string{
			"vfs":            "encz",
			"crypto_key_hex": wrongHexKey,
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

func TestCryptoKeyEnv(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "envkey.db")
	envVarName := "TEST_DATABASE_CRYPTO_PASSPHRASE"
	passphrase := "SecurePassphraseViaEnv123!!!"

	os.Setenv(envVarName, passphrase)
	defer os.Unsetenv(envVarName)

	opts := encz.Options{
		URIParameters: map[string]string{
			"vfs":            "encz",
			"crypto_key_env": envVarName,
		},
	}
	db, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("failed to open database with env key: %v", err)
	}

	if _, err := db.Exec(`CREATE TABLE env_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO env_test VALUES ("env-success")`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	dbReopen, err := encz.OpenWithOptions(dbPath, opts)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer dbReopen.Close()

	var val string
	if err := dbReopen.QueryRow(`SELECT val FROM env_test`).Scan(&val); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val != "env-success" {
		t.Errorf("expected 'env-success', got %q", val)
	}

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

func TestCryptoPragmas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragmakey.db")

	runPragma := func(db *sql.DB, pragma string) (string, error) {
		var res string
		err := db.QueryRow(pragma).Scan(&res)
		return res, err
	}

	initDB, err := encz.OpenEncz(dbPath, "MyPragmaSecret")
	if err != nil {
		t.Fatalf("failed to initialize DB: %v", err)
	}
	initDB.Close()

	dsn := encz.BuildDSN(dbPath, encz.Options{
		URIParameters: map[string]string{"vfs": "encz"},
	})
	db, err := sql.Open(encz.DriverName, dsn)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}

	res, err := runPragma(db, `PRAGMA crypto_key = "MyPragmaSecret"`)
	if err != nil || res != "ok" {
		db.Close()
		t.Fatalf("PRAGMA crypto_key failed: %s, err=%v", res, err)
	}

	if _, err := db.Exec(`CREATE TABLE pragma_table (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO pragma_table VALUES ("pragma-success")`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}

	var status string
	if err := db.QueryRow(`PRAGMA crypto_status`).Scan(&status); err != nil {
		db.Close()
		t.Fatalf("PRAGMA crypto_status failed: %v", err)
	}
	if !strings.Contains(status, "cipher=aes-256-gcm") || !strings.Contains(status, "key=set") {
		t.Errorf("crypto_status output does not contain expected values: %q", status)
	}

	res, err = runPragma(db, `PRAGMA crypto_key = "NewSecret"`)
	if err == nil {
		t.Error("expected setting crypto_key via PRAGMA after database IO to fail, but it succeeded")
	} else if !strings.Contains(err.Error(), "must run before database IO") {
		t.Errorf("unexpected error message for locked pragma config: %v", err)
	}

	db.Close()

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
	if err := dbReopen.QueryRow(`SELECT val FROM pragma_table`).Scan(&val); err != nil {
		t.Fatalf("reopen read failed: %v", err)
	}
	if val != "pragma-success" {
		t.Errorf("expected 'pragma-success', got %q", val)
	}
}
