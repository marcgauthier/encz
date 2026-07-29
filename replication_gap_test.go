package sqliteseal

import "testing"

func TestReplicationDefersAboveGapEventsUntilContiguous(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','first','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='second' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`UPDATE items SET name='third' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	events, err := source.replication.loadOriginEvents(ctx, 0, 10)
	if err != nil || len(events) != 3 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[2]); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = target.QueryRow(`SELECT apply_state FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=3`, sourceID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("state=%q err=%v", state, err)
	}
	var rows int
	if err = target.QueryRow(`SELECT count(*) FROM items`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("materialized rows=%d err=%v", rows, err)
	}
	assertReplicationCursorAndGap(t, target, sourceID, 0, 3, 1, 2)

	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[0]); err != nil {
		t.Fatal(err)
	}
	var name string
	if err = target.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name); err != nil || name != "first" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	assertReplicationCursorAndGap(t, target, sourceID, 1, 3, 2, 2)

	if err = target.replication.applyRemoteEvent(ctx, sourceID, events[1]); err != nil {
		t.Fatal(err)
	}
	if err = target.replication.recoverDeferredEvents(ctx); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name); err != nil || name != "third" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	var contiguous, highest, gaps int64
	if err = target.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, sourceID).Scan(&contiguous, &highest); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT count(*) FROM replication_origin_gaps WHERE origin_node_uuid=?`, sourceID).Scan(&gaps); err != nil {
		t.Fatal(err)
	}
	if contiguous != 3 || highest != 3 || gaps != 0 {
		t.Fatalf("cursor=%d/%d gaps=%d", contiguous, highest, gaps)
	}
}

func assertReplicationCursorAndGap(t *testing.T, db *DB, origin string, contiguous, highest, start, end int64) {
	t.Helper()
	var gotContiguous, gotHighest, gotStart, gotEnd int64
	if err := db.QueryRow(`SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE origin_node_uuid=?`, origin).Scan(&gotContiguous, &gotHighest); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT gap_start_counter,gap_end_counter FROM replication_origin_gaps WHERE origin_node_uuid=?`, origin).Scan(&gotStart, &gotEnd); err != nil {
		t.Fatal(err)
	}
	if gotContiguous != contiguous || gotHighest != highest || gotStart != start || gotEnd != end {
		t.Fatalf("cursor=%d/%d gap=%d-%d, want %d/%d gap=%d-%d", gotContiguous, gotHighest, gotStart, gotEnd, contiguous, highest, start, end)
	}
}
