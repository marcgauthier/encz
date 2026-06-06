package tests

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

func TestReKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rekey.db")
	db, err := encz.OpenEncz(dbPath, "OldSecret")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE rekey_test (val TEXT)`); err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO rekey_test VALUES ("rekey-success")`); err != nil {
		db.Close()
		t.Fatalf("insert: %v", err)
	}
	if err := db.ReKey("OldSecret", "NewSecret"); err != nil {
		db.Close()
		t.Fatalf("ReKey: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := encz.OpenEncz(dbPath, "OldSecret"); err == nil {
		t.Fatal("expected old key to fail after rekey")
	}
	reopened, err := encz.OpenEncz(dbPath, "NewSecret")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var val string
	if err := reopened.QueryRow(`SELECT val FROM rekey_test`).Scan(&val); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if val != "rekey-success" {
		t.Fatalf("unexpected value %q", val)
	}
}

func TestSetRotationPolicy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	db, err := encz.OpenEncz(dbPath, "MyRotationSecret")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	policy := encz.RotationPolicy{KEKRotationDays: 30, AutoRewrap: false, KeepPreviousKey: false}
	if err := db.SetRotationPolicy(policy); err != nil {
		db.Close()
		t.Fatalf("SetRotationPolicy: %v", err)
	}
	status, err := db.RotationStatus()
	if err != nil {
		db.Close()
		t.Fatalf("RotationStatus: %v", err)
	}
	if status.KEKRotationDays != 30 {
		db.Close()
		t.Fatalf("expected KEKRotationDays=30, got %d", status.KEKRotationDays)
	}
	if status.AutoRewrap {
		db.Close()
		t.Fatal("expected AutoRewrap=false")
	}
	if status.KeepPreviousKey {
		db.Close()
		t.Fatal("expected KeepPreviousKey=false")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := encz.OpenEncz(dbPath, "MyRotationSecret")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	status, err = reopened.RotationStatus()
	if err != nil {
		t.Fatalf("RotationStatus after reopen: %v", err)
	}
	if status.KEKRotationDays != 30 || status.AutoRewrap || status.KeepPreviousKey {
		t.Fatalf("unexpected reopened status: %+v", status)
	}
}

func TestSetRotationPolicyRejectsInvalidDays(t *testing.T) {
	db, err := encz.OpenEncz(filepath.Join(t.TempDir(), "invalid-policy.db"), "InvalidPolicySecret")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.SetRotationPolicy(encz.RotationPolicy{KEKRotationDays: 0}); !errors.Is(err, encz.ErrRotationPolicyInvalid) {
		t.Fatalf("expected ErrRotationPolicyInvalid, got %v", err)
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
