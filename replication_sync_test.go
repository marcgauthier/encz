package sqliteseal

import "testing"

func TestReplicationPersistsMonotonicPeerCursorVector(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='second' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	status, err := source.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.UpsertReplicationPeer(ctx, PeerConfig{
		NodeUUID: sourceID, IncarnationUUID: status.IncarnationUUID, NodeName: "source",
		Address: "127.0.0.1:1", Role: ReplicationAccept, AuthMode: ReplicationAuthPSK,
	}); err != nil {
		t.Fatal(err)
	}
	vector, err := source.replication.buildCursorVector(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = target.replication.persistPeerCursorVector(ctx, sourceID, vector); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.persistPeerCursorVector(ctx, sourceID, []wireCursor{{OriginNodeUUID: sourceID, ContiguousCounter: 1, HighestSeenCounter: 1}}); err != nil {
		t.Fatal(err)
	}
	var contiguous, highest int64
	if err = target.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE tracking_node_uuid=? AND origin_node_uuid=?`, sourceID, sourceID).Scan(&contiguous, &highest); err != nil {
		t.Fatal(err)
	}
	if contiguous != 2 || highest != 2 {
		t.Fatalf("peer cursor regressed to %d/%d", contiguous, highest)
	}
	peerStatus, err := target.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peerStatus.Peers) != 1 || peerStatus.Peers[0].NodeUUID != sourceID {
		t.Fatalf("duplicate or missing peer status rows: %+v", peerStatus.Peers)
	}
}

func TestReplicationSignalsSnapshotWhenRequestedHistoryWasRemoved(t *testing.T) {
	ctx, source, _, sourceID := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='second' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	var changeUUID string
	if err := source.QueryRow(`SELECT change_uuid FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=1`, sourceID).Scan(&changeUUID); err != nil {
		t.Fatal(err)
	}
	descriptor, err := source.replication.descriptor(ctx, "items")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(`DELETE FROM `+quoteReplicationIdent(descriptor.DescriptorID+"__replication_changes")+` WHERE change_uuid=?`, changeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err = source.Exec(`DELETE FROM replication_changes WHERE change_uuid=?`, changeUUID); err != nil {
		t.Fatal(err)
	}
	unavailable, err := source.replication.localHistoryUnavailable(ctx, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !unavailable {
		t.Fatal("compacted requested history did not require a snapshot")
	}
}
