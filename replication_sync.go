package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	maxGapRangesPerRequest = 64
	maxCursorVectorEntries = 4096
)

func cursorFromVector(vector []wireCursor, origin string) wireCursor {
	for _, cursor := range vector {
		if cursor.OriginNodeUUID == origin {
			return cursor
		}
	}
	return wireCursor{OriginNodeUUID: origin}
}

func (r *replicationRuntime) buildCursorVector(ctx context.Context) ([]wireCursor, error) {
	var local string
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT c.origin_node_uuid,c.contiguous_counter,c.highest_seen_counter,c.baseline_snapshot_uuid,c.requires_snapshot,
		coalesce((SELECT min(ch.origin_counter) FROM replication_changes ch WHERE ch.origin_node_uuid=c.origin_node_uuid AND ch.apply_state IN('applied','ignored')),0)
		FROM replication_origin_cursors c WHERE c.tracking_node_uuid=? ORDER BY c.origin_node_uuid`, local)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vector []wireCursor
	for rows.Next() {
		var cursor wireCursor
		var baseline sql.NullString
		var snapshot int
		if err = rows.Scan(&cursor.OriginNodeUUID, &cursor.ContiguousCounter, &cursor.HighestSeenCounter, &baseline, &snapshot, &cursor.EarliestRetainedCounter); err != nil {
			return nil, err
		}
		cursor.BaselineSnapshotUUID = baseline.String
		cursor.RequiresSnapshot = snapshot == 1
		vector = append(vector, cursor)
	}
	return vector, rows.Err()
}

func (r *replicationRuntime) persistPeerCursorVector(ctx context.Context, peer string, vector []wireCursor) error {
	r.writer.Lock()
	defer r.writer.Unlock()
	return retryReplicationBusy(ctx, func() error {
		return r.persistPeerCursorVectorOnce(ctx, peer, vector)
	})
}

func (r *replicationRuntime) persistPeerCursorVectorOnce(ctx context.Context, peer string, vector []wireCursor) error {
	if len(vector) > maxCursorVectorEntries {
		return errors.New("replication: cursor vector exceeds entry limit")
	}
	seen := make(map[string]struct{}, len(vector))
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	for _, cursor := range vector {
		if cursor.OriginNodeUUID == "" || cursor.ContiguousCounter < 0 || cursor.HighestSeenCounter < cursor.ContiguousCounter {
			return errors.New("replication: invalid cursor advertisement")
		}
		if _, duplicate := seen[cursor.OriginNodeUUID]; duplicate {
			return errors.New("replication: duplicate cursor origin")
		}
		seen[cursor.OriginNodeUUID] = struct{}{}
		var known int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_nodes WHERE node_uuid=?`, cursor.OriginNodeUUID).Scan(&known); err != nil {
			return err
		}
		if known == 0 {
			return errors.New("replication: cursor origin is not a domain member")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors(tracking_node_uuid,origin_node_uuid,contiguous_counter,highest_seen_counter,baseline_snapshot_uuid,requires_snapshot,updated_at_utc)
			VALUES(?,?,?,?,?,?,?) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET
			contiguous_counter=max(replication_origin_cursors.contiguous_counter,excluded.contiguous_counter),highest_seen_counter=max(replication_origin_cursors.highest_seen_counter,excluded.highest_seen_counter),
			baseline_snapshot_uuid=coalesce(excluded.baseline_snapshot_uuid,replication_origin_cursors.baseline_snapshot_uuid),requires_snapshot=max(replication_origin_cursors.requires_snapshot,excluded.requires_snapshot),updated_at_utc=excluded.updated_at_utc`,
			peer, cursor.OriginNodeUUID, cursor.ContiguousCounter, cursor.HighestSeenCounter, nullableString(cursor.BaselineSnapshotUUID), boolInt(cursor.RequiresSnapshot), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (r *replicationRuntime) localGapRequests(ctx context.Context, origin string) ([]wireGap, error) {
	r.writer.Lock()
	defer r.writer.Unlock()
	return r.localGapRequestsLocked(ctx, origin)
}

func (r *replicationRuntime) localGapRequestsLocked(ctx context.Context, origin string) ([]wireGap, error) {
	var local string
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT gap_start_counter,gap_end_counter FROM replication_origin_gaps
		WHERE tracking_node_uuid=? AND origin_node_uuid=? ORDER BY gap_start_counter LIMIT ?`, local, origin, maxGapRangesPerRequest)
	if err != nil {
		return nil, err
	}
	var gaps []wireGap
	for rows.Next() {
		var gap wireGap
		gap.OriginNodeUUID = origin
		if err = rows.Scan(&gap.StartCounter, &gap.EndCounter); err != nil {
			rows.Close()
			return nil, err
		}
		gaps = append(gaps, gap)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for _, gap := range gaps {
		err = retryReplicationBusy(ctx, func() error {
			_, updateErr := r.db.ExecContext(ctx, `UPDATE replication_origin_gaps SET last_requested_at_utc=sqliteseal_utc_now(),request_count=request_count+1
				WHERE tracking_node_uuid=? AND origin_node_uuid=? AND gap_start_counter=?`, local, origin, gap.StartCounter)
			return updateErr
		})
		if err != nil {
			return nil, err
		}
	}
	return gaps, nil
}

func (r *replicationRuntime) localHistoryUnavailable(ctx context.Context, cursor int64, gaps []wireGap) (bool, error) {
	var local string
	var last int64
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,last_origin_counter FROM replication_local_state`).Scan(&local, &last); err != nil {
		return false, err
	}
	if cursor < 0 {
		return false, errors.New("replication: invalid synchronization cursor")
	}
	var earliest sql.NullInt64
	if err := r.db.QueryRowContext(ctx, `SELECT min(origin_counter) FROM replication_changes WHERE origin_node_uuid=? AND apply_state IN('applied','ignored')`, local).Scan(&earliest); err != nil {
		return false, err
	}
	if cursor < last && (!earliest.Valid || cursor+1 < earliest.Int64) {
		return true, nil
	}
	if len(gaps) > maxGapRangesPerRequest {
		return false, errors.New("replication: too many gap ranges")
	}
	for _, gap := range gaps {
		if gap.OriginNodeUUID != local || gap.StartCounter <= 0 || gap.EndCounter < gap.StartCounter {
			return false, errors.New("replication: invalid gap request")
		}
		end := gap.EndCounter
		if end > last {
			end = last
		}
		if end < gap.StartCounter {
			continue
		}
		var retained int64
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes WHERE origin_node_uuid=? AND origin_counter BETWEEN ? AND ? AND apply_state IN('applied','ignored')`, local, gap.StartCounter, end).Scan(&retained); err != nil {
			return false, err
		}
		if retained != end-gap.StartCounter+1 {
			return true, nil
		}
	}
	return false, nil
}

func (r *replicationRuntime) markSnapshotRequired(ctx context.Context, origin string) error {
	var local string
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO replication_origin_cursors(tracking_node_uuid,origin_node_uuid,contiguous_counter,highest_seen_counter,baseline_snapshot_uuid,requires_snapshot,updated_at_utc) VALUES(?,?,0,0,NULL,1,sqliteseal_utc_now()) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET requires_snapshot=1,updated_at_utc=excluded.updated_at_utc`, local, origin)
	return err
}

func moreOriginEvents(events []wireEvent, vector []wireCursor, local string) bool {
	if len(events) == 0 {
		return false
	}
	return events[len(events)-1].OriginCounter < cursorFromVector(vector, local).ContiguousCounter
}
