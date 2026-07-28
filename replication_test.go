package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplicationCaptureLifecycle(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "replication.db"), "test-key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,quantity INTEGER)`); err != nil {
		t.Fatal(err)
	}
	cfg := LocalNodeConfig{NodeUUID: "00000000-0000-4000-8000-000000000001", NodeName: "one", ReplicationDomain: "test", AuthMode: ReplicationAuthPSK, CredentialName: "local"}
	if err = db.InitializeReplication(context.Background(), cfg, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO items VALUES('a','alpha',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE items SET quantity=2 WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM items WHERE id='a'`); err != nil {
		t.Fatal(err)
	}
	var changes, counter int
	if err = db.QueryRow(`SELECT count(*),max(origin_counter) FROM replication_changes`).Scan(&changes, &counter); err != nil {
		t.Fatal(err)
	}
	if changes != 3 || counter != 3 {
		t.Fatalf("changes=%d counter=%d", changes, counter)
	}
	s, err := db.ReplicationStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Initialized || s.LastOriginCounter != 3 {
		t.Fatalf("status=%+v", s)
	}
}
func TestReplicationRejectsTableWithoutPrimaryKey(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "bad.db"), "test-key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(`CREATE TABLE bad(value TEXT)`)
	err = db.InitializeReplication(context.Background(), LocalNodeConfig{NodeName: "one", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "bad"}})
	if err == nil {
		t.Fatal("expected error")
	}
}
