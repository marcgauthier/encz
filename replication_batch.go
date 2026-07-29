package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var errReplicationBatchFallback = errors.New("replication: batch requires individual application")

const replicationApplyTransactionBatchSize = 100

type preparedRemoteEvent struct {
	event      wireEvent
	descriptor replicationTableDescriptor
}

// applyRemoteEvents commits the normal contiguous transport batch once. Events
// requiring special handling fall back to the fully general per-event path.
func (r *replicationRuntime) applyRemoteEvents(ctx context.Context, peer string, events []wireEvent) error {
	for start := 0; start < len(events); start += replicationApplyTransactionBatchSize {
		end := start + replicationApplyTransactionBatchSize
		if end > len(events) {
			end = len(events)
		}
		r.writer.Lock()
		err := r.applyRemoteEventChunk(ctx, peer, events[start:end])
		r.writer.Unlock()
		if err != nil {
			return err
		}
		if end < len(events) {
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return context.Cause(ctx)
			case <-timer.C:
			}
		}
	}
	return nil
}

func (r *replicationRuntime) applyRemoteEventChunk(ctx context.Context, peer string, events []wireEvent) error {
	err := retryReplicationBusy(ctx, func() error {
		return r.applyRemoteEventsOnce(ctx, peer, events)
	})
	if !errors.Is(err, errReplicationBatchFallback) {
		return err
	}
	for i := range events {
		if err = retryReplicationBusy(ctx, func() error {
			return r.applyRemoteEventOnce(ctx, peer, events[i])
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *replicationRuntime) applyRemoteEventsOnce(ctx context.Context, peer string, events []wireEvent) error {
	if len(events) == 1 {
		return r.applyRemoteEventOnce(ctx, peer, events[0])
	}

	var domain, schema, local string
	var version int64
	if err := r.db.QueryRowContext(ctx, `SELECT replication_domain,schema_hash,schema_version,local_node_uuid FROM replication_local_state`).Scan(&domain, &schema, &version, &local); err != nil {
		return err
	}
	skew, err := r.maximumFutureSkew(ctx)
	if err != nil {
		return err
	}
	contiguous, err := r.cursorFor(peer)
	if err != nil {
		return err
	}

	prepared := make([]preparedRemoteEvent, len(events))
	descriptors := make(map[string]replicationTableDescriptor)
	for i := range events {
		event := events[i]
		if event.OriginNodeUUID != peer || event.Domain != domain {
			return errors.New("replication: origin authorization failed")
		}
		if event.SchemaHash != schema || event.SchemaVersion != version {
			return ErrReplicationSchemaMismatch
		}
		if event.OriginCounter != contiguous+int64(i)+1 {
			return errReplicationBatchFallback
		}
		if event.HLCPhysicalUS > time.Now().UTC().Add(skew).UnixMicro() {
			return errReplicationBatchFallback
		}
		descriptor, found := descriptors[event.TableName]
		if !found {
			var descriptorErr error
			descriptor, descriptorErr = r.descriptor(ctx, event.TableName)
			if descriptorErr != nil {
				_ = r.recordRejectedEvent(ctx, peer, event, "unknown_table", "")
				return descriptorErr
			}
			descriptors[event.TableName] = descriptor
		}
		if validationErr := validateWireEvent(descriptor, event, domain, schema, version, defaultMaximumEventBytes); validationErr != nil {
			_ = r.recordRejectedEvent(ctx, peer, event, "invalid_event", "")
			return validationErr
		}
		prepared[i] = preparedRemoteEvent{event: event, descriptor: descriptor}
	}

	var existing int
	if err = r.db.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes
		WHERE origin_node_uuid=? AND origin_counter BETWEEN ? AND ?`,
		peer, events[0].OriginCounter, events[len(events)-1].OriginCounter).Scan(&existing); err != nil {
		return err
	}
	if existing != 0 {
		return errReplicationBatchFallback
	}

	conn, err := r.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var restore func()
	if err = conn.Raw(func(raw any) error {
		sqlite, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return ErrReplicationNotReady
		}
		var modeErr error
		restore, modeErr = setReplicationConnectionMode(sqlite, "remote")
		return modeErr
	}); err != nil {
		return err
	}
	defer restore()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := range prepared {
		if err = applyNewRemoteEventInBatch(ctx, tx, peer, prepared[i]); err != nil {
			return err
		}
	}
	last := events[len(events)-1]
	maximumHLC := events[0]
	for i := 1; i < len(events); i++ {
		if events[i].HLCPhysicalUS > maximumHLC.HLCPhysicalUS ||
			(events[i].HLCPhysicalUS == maximumHLC.HLCPhysicalUS && events[i].HLCLogical > maximumHLC.HLCLogical) {
			maximumHLC = events[i]
		}
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	if err = mergeRemoteHLC(ctx, tx, maximumHLC.HLCPhysicalUS, maximumHLC.HLCLogical, time.Now().UTC().UnixMicro(), now); err != nil {
		return err
	}
	if err = advanceRemoteCursor(ctx, tx, local, last.OriginNodeUUID, last.OriginCounter, now); err != nil {
		return err
	}
	return tx.Commit()
}

func applyNewRemoteEventInBatch(ctx context.Context, tx *sql.Tx, peer string, prepared preparedRemoteEvent) error {
	event := prepared.event
	descriptor := prepared.descriptor
	_, keyArgs, err := wireKey(descriptor, event)
	if err != nil {
		return err
	}
	where := make([]string, 0, len(descriptor.Table.PrimaryKeyColumns))
	for _, column := range descriptor.Table.PrimaryKeyColumns {
		where = append(where, quoteReplicationIdent(column)+"=?")
	}
	whereSQL := strings.Join(where, " AND ")

	var rowPhysical, rowLogical int64
	var rowOrigin, rowState string
	rowErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,row_state
		FROM replication_row_versions WHERE table_name=? AND row_key_json=?`,
		event.TableName, event.RowKeyJSON).Scan(&rowPhysical, &rowLogical, &rowOrigin, &rowState)
	rowComparison := 1
	if rowErr == nil {
		rowComparison = compareReplicationVersion(event.HLCPhysicalUS, event.HLCLogical, event.OriginNodeUUID, rowPhysical, rowLogical, rowOrigin)
	} else if rowErr != sql.ErrNoRows {
		return rowErr
	}

	exists := 0
	tombstoneBlocks := rowState == "deleted" && (rowComparison <= 0 || !event.ExplicitRecreation)
	if event.Operation != "delete" && !tombstoneBlocks {
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM `+quoteReplicationIdent(event.TableName)+` WHERE `+whereSQL, keyArgs...).Scan(&exists); err != nil {
			return err
		}
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,source_node_uuid,payload_hash,apply_state)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`,
		event.ChangeUUID, event.OriginNodeUUID, event.OriginCounter, event.Operation, event.TableName,
		event.RowKeyJSON, event.ChangedFieldsJSON, boolInt(event.ExplicitRecreation), event.HLCPhysicalUS,
		event.HLCLogical, event.SchemaVersion, event.SchemaHash, event.Domain, event.CreatedAtUTC, now,
		peer, event.PayloadHash); err != nil {
		return err
	}
	if err = persistWirePayload(ctx, tx, descriptor, event); err != nil {
		return err
	}

	applied := false
	if event.Operation == "delete" {
		if rowComparison > 0 {
			if _, err = tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(event.TableName)+` WHERE `+whereSQL, keyArgs...); err != nil {
				return err
			}
			applied = true
		}
	} else if tombstoneBlocks {
		rowComparison = -1
	} else {
		inserted := false
		if exists == 0 && (event.Operation == "insert" || event.Operation == "update") {
			if err = insertRemoteWireRow(ctx, tx, descriptor, event); err != nil {
				if event.Operation == "update" && isReplicationConstraint(err) {
					return errReplicationBatchFallback
				}
				return err
			}
			exists = 1
			inserted = true
			applied = true
		}
		if exists > 0 {
			for _, column := range descriptor.Table.Columns {
				wire := event.Values[column]
				if !wire.Present {
					continue
				}
				if !inserted {
					var fieldPhysical, fieldLogical int64
					var fieldOrigin string
					fieldErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid
						FROM replication_field_versions WHERE table_name=? AND row_key_json=? AND field_name=?`,
						event.TableName, event.RowKeyJSON, column).Scan(&fieldPhysical, &fieldLogical, &fieldOrigin)
					if fieldErr != nil && fieldErr != sql.ErrNoRows {
						return fieldErr
					}
					if fieldErr == nil && compareReplicationVersion(event.HLCPhysicalUS, event.HLCLogical, event.OriginNodeUUID, fieldPhysical, fieldLogical, fieldOrigin) <= 0 {
						continue
					}
				}
				value, decodeErr := decodeWireValue(wire)
				if decodeErr != nil {
					return decodeErr
				}
				if !inserted {
					if _, err = tx.ExecContext(ctx, `UPDATE `+quoteReplicationIdent(event.TableName)+` SET `+quoteReplicationIdent(column)+`=? WHERE `+whereSQL, append([]any{value}, keyArgs...)...); err != nil {
						return err
					}
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO replication_field_versions VALUES(?,?,?,?,?,?,?,?,?,?)
					ON CONFLICT(table_name,row_key_json,field_name) DO UPDATE SET
					winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,
					winner_hlc_logical=excluded.winner_hlc_logical,
					winner_origin_node_uuid=excluded.winner_origin_node_uuid,
					winner_change_uuid=excluded.winner_change_uuid,
					winner_changed_at_utc=excluded.winner_changed_at_utc,
					updated_at_utc=excluded.updated_at_utc`,
					event.TableName, event.RowKeyJSON, column, event.HLCPhysicalUS, event.HLCLogical,
					event.OriginNodeUUID, event.ChangeUUID, event.CreatedAtUTC, nil, now); err != nil {
					return err
				}
				applied = true
			}
		}
	}

	if rowComparison > 0 {
		state := "live"
		if event.Operation == "delete" {
			state = "deleted"
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(table_name,row_key_json) DO UPDATE SET
			row_state=excluded.row_state,
			winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,
			winner_hlc_logical=excluded.winner_hlc_logical,
			winner_origin_node_uuid=excluded.winner_origin_node_uuid,
			winner_change_uuid=excluded.winner_change_uuid,
			winner_changed_at_utc=excluded.winner_changed_at_utc,
			updated_at_utc=excluded.updated_at_utc`,
			event.TableName, event.RowKeyJSON, state, event.HLCPhysicalUS, event.HLCLogical,
			event.OriginNodeUUID, event.ChangeUUID, event.CreatedAtUTC, now); err != nil {
			return err
		}
	}
	applyState := "ignored"
	if applied {
		applyState = "applied"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=NULL WHERE change_uuid=?`, applyState, event.ChangeUUID); err != nil {
		return err
	}
	return nil
}
