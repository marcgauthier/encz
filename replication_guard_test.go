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
