package sqliteseal

import (
	"context"
	"testing"
)

func prepareSnapshotDestination(t *testing.T, ctx context.Context, source, target *DB, sourceID string) {
	t.Helper()
	status, err := source.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.UpsertReplicationPeer(ctx, PeerConfig{
		NodeUUID: sourceID, IncarnationUUID: status.IncarnationUUID, NodeName: "snapshot-source",
		Address: "127.0.0.1:1", Role: ReplicationAccept, AuthMode: ReplicationAuthPSK,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReplicationSnapshotRoundTrip(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	prepareSnapshotDestination(t, ctx, source, target, sourceID)
	if _, err := source.Exec(`INSERT INTO items VALUES('live','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='second',note=NULL WHERE id='live'`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`INSERT INTO items VALUES('gone','delete-me','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`DELETE FROM items WHERE id='gone'`); err != nil {
		t.Fatal(err)
	}
	info, err := source.CreateReplicationSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.SnapshotUUID == "" || info.ContentHash == "" || info.SizeBytes <= 0 {
		t.Fatalf("invalid snapshot info: %+v", info)
	}
	manifest, raw, err := source.replication.latestSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.installSessionSnapshot(ctx, sourceID, manifest, raw); err != nil {
		t.Fatal(err)
	}
	var name string
	var note any
	if err = target.QueryRow(`SELECT name,note FROM items WHERE id='live'`).Scan(&name, &note); err != nil {
		t.Fatal(err)
	}
	if name != "second" || note != nil {
		t.Fatalf("row name=%q note=%v", name, note)
	}
	var rows, tombstones int
	if err = target.QueryRow(`SELECT count(*) FROM items WHERE id='gone'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT count(*) FROM replication_row_versions WHERE row_key_json='{"id":"gone"}' AND row_state='deleted'`).Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if rows != 0 || tombstones != 1 {
		t.Fatalf("deleted row=%d tombstones=%d", rows, tombstones)
	}
	var baseline string
	var requires, contiguous int64
	if err = target.QueryRow(`SELECT baseline_snapshot_uuid,requires_snapshot,contiguous_counter FROM replication_origin_cursors WHERE tracking_node_uuid=(SELECT local_node_uuid FROM replication_local_state) AND origin_node_uuid=?`, sourceID).Scan(&baseline, &requires, &contiguous); err != nil {
		t.Fatal(err)
	}
	if baseline != info.SnapshotUUID || requires != 0 || contiguous != 4 {
		t.Fatalf("baseline=%q requires=%d contiguous=%d", baseline, requires, contiguous)
	}
}

func TestReplicationSnapshotRejectsTamperingAndLocalHistory(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	prepareSnapshotDestination(t, ctx, source, target, sourceID)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','value','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateReplicationSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	manifest, raw, err := source.replication.latestSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 1
	if err = target.replication.installSessionSnapshot(ctx, sourceID, manifest, tampered); err == nil {
		t.Fatal("tampered snapshot installed")
	}
	if _, err = target.Exec(`INSERT INTO items VALUES('local','value','note')`); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.installSessionSnapshot(ctx, sourceID, manifest, raw); err == nil {
		t.Fatal("snapshot overwrote local-origin history")
	}
}
