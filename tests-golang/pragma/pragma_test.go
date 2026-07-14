package pragma

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcgauthier/encz"
)

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
	if !strings.Contains(status, "cipher=chacha20-poly1305") || !strings.Contains(status, "key=set") {
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
