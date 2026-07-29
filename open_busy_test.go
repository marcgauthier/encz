package sqliteseal

import (
	"path/filepath"
	"testing"
)

func TestOpenUsesReplicationSafeBusyTimeoutByDefault(t *testing.T) {
	db, err := OpenWithOptions(filepath.Join(t.TempDir(), "default-busy.db"), Options{Key: "default-busy-key", Replication: &ReplicationRuntimeOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var timeout int
	if err = db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != defaultReplicationBusyTimeoutMillis {
		t.Fatalf("busy_timeout=%d want %d", timeout, defaultReplicationBusyTimeoutMillis)
	}
}

func TestOpenPreservesExplicitBusyTimeout(t *testing.T) {
	configured := 1234
	db, err := OpenWithOptions(filepath.Join(t.TempDir(), "explicit-busy.db"), Options{
		Key:               "explicit-busy-key",
		BusyTimeoutMillis: &configured,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var timeout int
	if err = db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != configured {
		t.Fatalf("busy_timeout=%d want %d", timeout, configured)
	}
}
