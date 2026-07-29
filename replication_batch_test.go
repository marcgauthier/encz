package sqliteseal

import (
	"fmt"
	"testing"
)

func TestReplicationAppliesContiguousEventsInTransactionChunks(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	const eventCount = replicationApplyTransactionBatchSize*2 + 7
	tx, err := source.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < eventCount; i++ {
		if _, err = tx.ExecContext(ctx, `INSERT INTO items VALUES(?,?,?)`,
			fmt.Sprintf("id-%03d", i), fmt.Sprintf("name-%03d", i), "note"); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	events, err := source.replication.loadOriginEvents(ctx, 0, eventCount+1)
	if err != nil || len(events) != eventCount {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err = target.replication.applyRemoteEvents(ctx, sourceID, events); err != nil {
		t.Fatal(err)
	}

	var rows, applied, contiguous, highest int
	if err = target.QueryRow(`SELECT count(*) FROM items`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT count(*) FROM replication_changes WHERE apply_state='applied'`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, sourceID).Scan(&contiguous, &highest); err != nil {
		t.Fatal(err)
	}
	if rows != eventCount || applied != eventCount || contiguous != eventCount || highest != eventCount {
		t.Fatalf("rows=%d applied=%d cursor=%d/%d want %d", rows, applied, contiguous, highest, eventCount)
	}
}
