package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplicationDuplicateReplayRepairsCursorAndRejectsConflict(t *testing.T) {
	ctx := context.Background()
	openNode := func(name, id string) *DB {
		t.Helper()
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
			t.Fatal(err)
		}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{
			NodeUUID:          id,
			NodeName:          name,
			ReplicationDomain: "test",
		}, []ReplicatedTable{{Name: "items"}}); err != nil {
			t.Fatal(err)
		}
		return db
	}

	sourceID := "00000000-0000-4000-8000-000000000011"
	source := openNode("source", sourceID)
	target := openNode("target", "00000000-0000-4000-8000-000000000012")
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first')`); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = target.Exec(`DELETE FROM replication_origin_cursors`); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatalf("duplicate replay: %v", err)
	}
	var cursor int64
	if err = target.QueryRow(`SELECT contiguous_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, sourceID).Scan(&cursor); err != nil || cursor != 1 {
		t.Fatalf("cursor=%d err=%v", cursor, err)
	}

	conflict := events[0]
	conflict.Values["name"] = encodeWireValue("different", true)
	conflict.PayloadHash, _, err = replicationEventHash(conflict)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, conflict); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
	var rejected int
	if err = target.QueryRow(`SELECT count(*) FROM replication_rejected_events WHERE reason_code='conflicting_duplicate'`).Scan(&rejected); err != nil || rejected != 1 {
		t.Fatalf("rejected=%d err=%v", rejected, err)
	}
}
