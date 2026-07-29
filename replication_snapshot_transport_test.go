package sqliteseal

import (
	"context"
	"net"
	"testing"
)

func registerSnapshotPeers(t *testing.T, ctx context.Context, a, b *DB) (string, string) {
	t.Helper()
	statusA, err := a.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	statusB, err := b.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: statusB.NodeUUID, IncarnationUUID: statusB.IncarnationUUID, NodeName: "snapshot-b", Address: "127.0.0.1:1", Role: ReplicationDial, AuthMode: ReplicationAuthPSK}); err != nil {
		t.Fatal(err)
	}
	if err = b.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: statusA.NodeUUID, IncarnationUUID: statusA.IncarnationUUID, NodeName: "snapshot-a", Address: "127.0.0.1:1", Role: ReplicationAccept, AuthMode: ReplicationAuthPSK}); err != nil {
		t.Fatal(err)
	}
	return statusA.NodeUUID, statusB.NodeUUID
}

func compactFirstLocalEvent(t *testing.T, ctx context.Context, db *DB, origin string) {
	t.Helper()
	var changeUUID, tableName string
	if err := db.QueryRow(`SELECT change_uuid,table_name FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=1`, origin).Scan(&changeUUID, &tableName); err != nil {
		t.Fatal(err)
	}
	descriptor, err := db.replication.descriptor(ctx, tableName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM `+quoteReplicationIdent(descriptor.DescriptorID+"__replication_changes")+` WHERE change_uuid=?`, changeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM replication_changes WHERE change_uuid=?`, changeUUID); err != nil {
		t.Fatal(err)
	}
}

func runSnapshotSyncCycle(t *testing.T, dialer, acceptor *DB, dialerID, acceptorID string) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- acceptor.replication.serveSession(server, wireHello{NodeUUID: dialerID})
	}()
	config := peerRuntimeConfig{MaxCompressed: 8 << 20, MaxUncompressed: 32 << 20, MaxBatch: 500}
	if err := dialer.replication.syncCycle(client, acceptorID, config); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = server.Close()
	<-done
}

func TestReplicationSyncCycleDownloadsSnapshot(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	targetID, gotSourceID := registerSnapshotPeers(t, ctx, target, source)
	if gotSourceID != sourceID {
		t.Fatal("unexpected source identity")
	}
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='from-snapshot' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	compactFirstLocalEvent(t, ctx, source, sourceID)
	runSnapshotSyncCycle(t, target, source, targetID, sourceID)
	var name string
	if err := target.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name); err != nil || name != "from-snapshot" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}

func TestReplicationSyncCycleUploadsSnapshot(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	gotSourceID, targetID := registerSnapshotPeers(t, ctx, source, target)
	if gotSourceID != sourceID {
		t.Fatal("unexpected source identity")
	}
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='uploaded-snapshot' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	compactFirstLocalEvent(t, ctx, source, sourceID)
	runSnapshotSyncCycle(t, source, target, sourceID, targetID)
	var name string
	if err := target.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name); err != nil || name != "uploaded-snapshot" {
		t.Fatalf("name=%q err=%v", name, err)
	}
}
