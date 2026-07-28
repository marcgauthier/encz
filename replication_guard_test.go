package sqliteseal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReplicationIdentityGuardFencesRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	db, e := OpenSQLiteSeal(path, "key")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY)`)
	if e = db.InitializeReplication(t.Context(), LocalNodeConfig{NodeName: "n", ReplicationDomain: "d"}, []ReplicatedTable{{Name: "items"}}); e != nil {
		t.Fatal(e)
	}
	var g replicationIdentityGuard
	if e = db.QueryRow(`SELECT local_node_uuid,local_incarnation_uuid,database_generation,last_origin_counter FROM replication_local_state`).Scan(&g.NodeUUID, &g.IncarnationUUID, &g.DatabaseGeneration, &g.Counter); e != nil {
		t.Fatal(e)
	}
	g.Counter += 10
	key, e := db.replication.guardKey()
	if e != nil {
		t.Fatal(e)
	}
	g.MAC = guardMAC(key, g)
	wipeBytes(key)
	raw, _ := json.Marshal(g)
	if e = os.WriteFile(db.replication.guardPath(), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = OpenSQLiteSeal(path, "key")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s, e := db.ReplicationStatus(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if s.NetworkEnabled || s.BlockedReason == "" {
		t.Fatalf("rollback was not fenced: %+v", s)
	}
}

func TestReplicationIdentityGuardAdvancesWithLocalTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard-commit.db")
	db, err := OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(t.Context(), LocalNodeConfig{NodeName: "commit", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO items VALUES('one')`); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(db.replication.guardPath())
	if err != nil {
		t.Fatal(err)
	}
	var guard replicationIdentityGuard
	if err = json.Unmarshal(raw, &guard); err != nil {
		t.Fatal(err)
	}
	if guard.Counter != 1 {
		t.Fatalf("guard counter=%d", guard.Counter)
	}
}
