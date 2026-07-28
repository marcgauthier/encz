package sqliteseal

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReplicationStartupFencesApplicationSchemaDrift(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "drift.db")
	db, err := OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: "00000000-0000-4000-8000-000000000041", NodeName: "drift", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`ALTER TABLE items ADD COLUMN extra TEXT`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status, err := db.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.NetworkEnabled || !strings.Contains(status.BlockedReason, "schema mismatch") {
		t.Fatalf("status=%+v", status)
	}
}

func TestReplicationStartupReplaysEligibleQuarantine(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	if _, err := target.Exec(`UPDATE replication_local_state SET maximum_future_skew_us=10000`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`INSERT INTO items VALUES('restart','recovered','note')`); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	event := events[0]
	event.HLCPhysicalUS = time.Now().Add(60 * time.Millisecond).UnixMicro()
	event.PayloadHash, _, err = replicationEventHash(event)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, event); err == nil {
		t.Fatal("future event was not quarantined")
	}
	path := target.path
	if err = target.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(90 * time.Millisecond)
	reopened, err := OpenSQLiteSeal(path, "key")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var name, state string
	if err = reopened.QueryRow(`SELECT name FROM items WHERE id='restart'`).Scan(&name); err != nil || name != "recovered" {
		t.Fatalf("name=%s err=%v", name, err)
	}
	if err = reopened.QueryRow(`SELECT apply_state FROM replication_changes WHERE change_uuid=?`, event.ChangeUUID).Scan(&state); err != nil || state != "applied" {
		t.Fatalf("state=%s err=%v", state, err)
	}
}
