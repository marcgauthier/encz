package pragma

import (
	"database/sql"
	"errors"
	"path/filepath"
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
	dsn, err := encz.BuildDSN(dbPath, encz.Options{URIParameters: map[string]string{"vfs": "encz"}})
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	db, err := sql.Open(encz.DriverName, dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA crypto_key = "MyPragmaSecret"`); err == nil {
		t.Fatal("expected direct-key pragma to be rejected")
	}
}
