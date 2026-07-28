package sqliteseal

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func setupEventValidationNodes(t *testing.T) (context.Context, *DB, *DB, string) {
	t.Helper()
	ctx := context.Background()
	open := func(name, id string) *DB {
		db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), name+".db"), "key")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,note TEXT)`); err != nil {
			t.Fatal(err)
		}
		if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: id, NodeName: name, ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
			t.Fatal(err)
		}
		return db
	}
	sourceID := "00000000-0000-4000-8000-000000000021"
	return ctx, open("source-validation", sourceID), open("target-validation", "00000000-0000-4000-8000-000000000022"), sourceID
}

func TestReplicationRejectsTamperedEventBeforePersistence(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','original','note')`); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	tampered := events[0]
	tampered.Values["name"] = encodeWireValue("tampered", true)
	if err = target.replication.applyRemoteEvent(ctx, sourceID, tampered); err == nil || !strings.Contains(err.Error(), "payload hash mismatch") {
		t.Fatalf("tampered event result: %v", err)
	}
	var changes, rejected int
	if err = target.QueryRow(`SELECT count(*) FROM replication_changes`).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT count(*) FROM replication_rejected_events WHERE reason_code='invalid_event'`).Scan(&rejected); err != nil {
		t.Fatal(err)
	}
	if changes != 0 || rejected != 1 {
		t.Fatalf("changes=%d rejected=%d", changes, rejected)
	}
}

func TestReplicationExplicitNullAndNFCValidation(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','original','note')`); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(`UPDATE items SET note=NULL WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	events, err = source.replication.loadOriginEvents(ctx, 1, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatal(err)
	}
	var note any
	if err = target.QueryRow(`SELECT note FROM items WHERE id='one'`).Scan(&note); err != nil || note != nil {
		t.Fatalf("note=%v err=%v", note, err)
	}
	if _, err = source.Exec(`UPDATE items SET name=? WHERE id='one'`, "e\u0301"); err == nil {
		t.Fatal("non-NFC replicated text accepted")
	}
}
