package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReplicationMaterializesUpdateBeforeBaseRowArrives(t *testing.T) {
	ctx := context.Background()
	openNode := func(name, id string) *DB {
		t.Helper()
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,note TEXT)`); err != nil {
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

	baseID := "00000000-0000-4000-8000-000000000031"
	updateID := "00000000-0000-4000-8000-000000000032"
	targetID := "00000000-0000-4000-8000-000000000033"
	base := openNode("base", baseID)
	updater := openNode("updater", updateID)
	target := openNode("target", targetID)

	if _, err := base.Exec(`INSERT INTO items VALUES('one','base','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := base.Exec(`UPDATE items SET name='older' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	baseEvents, err := base.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(baseEvents) != 2 {
		t.Fatalf("base events=%d err=%v", len(baseEvents), err)
	}
	for _, event := range baseEvents {
		if err = updater.replication.applyRemoteEvent(ctx, baseID, event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = updater.Exec(`UPDATE items SET name='newest' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	updateEvents, err := updater.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(updateEvents) != 1 {
		t.Fatalf("update events=%d err=%v", len(updateEvents), err)
	}

	// Deliver the cross-origin update before the insert that created its row.
	if err = target.replication.applyRemoteEvent(ctx, updateID, updateEvents[0]); err != nil {
		t.Fatal(err)
	}
	var state, reason, name string
	if err = target.QueryRow(`SELECT apply_state,coalesce(quarantine_reason,'') FROM replication_changes WHERE change_uuid=?`, updateEvents[0].ChangeUUID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "applied" || reason != "" {
		t.Fatalf("state=%q reason=%q", state, reason)
	}
	var rows, contiguous, highest int64
	if err = target.QueryRow(`SELECT count(*),name FROM items WHERE id='one'`).Scan(&rows, &name); err != nil || rows != 1 || name != "newest" {
		t.Fatalf("rows=%d name=%q err=%v", rows, name, err)
	}
	if err = target.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, updateID).Scan(&contiguous, &highest); err != nil {
		t.Fatal(err)
	}
	if contiguous != 1 || highest != 1 {
		t.Fatalf("update cursor=%d/%d want 1/1", contiguous, highest)
	}

	if err = target.replication.applyRemoteEvent(ctx, baseID, baseEvents[0]); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.applyRemoteEvent(ctx, baseID, baseEvents[1]); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.recoverDeferredEvents(ctx); err != nil {
		t.Fatal(err)
	}

	if err = target.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name); err != nil || name != "newest" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	if err = target.QueryRow(`SELECT apply_state,coalesce(quarantine_reason,'') FROM replication_changes WHERE change_uuid=?`, updateEvents[0].ChangeUUID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "applied" || reason != "" {
		t.Fatalf("state=%q reason=%q", state, reason)
	}
	if err = target.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, updateID).Scan(&contiguous, &highest); err != nil {
		t.Fatal(err)
	}
	if contiguous != 1 || highest != 1 {
		t.Fatalf("update cursor=%d/%d want 1/1", contiguous, highest)
	}
}
