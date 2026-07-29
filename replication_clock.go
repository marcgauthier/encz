package sqliteseal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func (r *replicationRuntime) ensureReplicationMetadataCompatibility(ctx context.Context) error {
	columns := []struct {
		table string
		name  string
		ddl   string
	}{
		{"replication_local_state", "maximum_future_skew_us", `ALTER TABLE replication_local_state ADD COLUMN maximum_future_skew_us INTEGER NOT NULL DEFAULT 300000000`},
		{"replication_snapshots", "baseline_cursors_uncompressed_bytes", `ALTER TABLE replication_snapshots ADD COLUMN baseline_cursors_uncompressed_bytes INTEGER NOT NULL DEFAULT 0`},
		{"replication_snapshots", "snapshot_auth_mode", `ALTER TABLE replication_snapshots ADD COLUMN snapshot_auth_mode TEXT NOT NULL DEFAULT 'session'`},
		{"replication_snapshots", "creator_signing_key_id", `ALTER TABLE replication_snapshots ADD COLUMN creator_signing_key_id TEXT`},
		{"replication_snapshots", "creator_signature", `ALTER TABLE replication_snapshots ADD COLUMN creator_signature BLOB`},
		{"replication_snapshots", "storage_uri", `ALTER TABLE replication_snapshots ADD COLUMN storage_uri TEXT`},
		{"replication_snapshots", "installed_by_node_uuid", `ALTER TABLE replication_snapshots ADD COLUMN installed_by_node_uuid TEXT`},
		{"replication_snapshots", "verified_at_utc", `ALTER TABLE replication_snapshots ADD COLUMN verified_at_utc TEXT`},
	}
	for _, column := range columns {
		found, err := replicationColumnExists(ctx, r.db, column.table, column.name)
		if err != nil {
			return err
		}
		if !found {
			if _, err = r.db.ExecContext(ctx, column.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

func replicationColumnExists(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+quoteReplicationIdent(table)+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (r *replicationRuntime) maximumFutureSkew(ctx context.Context) (time.Duration, error) {
	var microseconds int64
	if err := r.db.QueryRowContext(ctx, `SELECT maximum_future_skew_us FROM replication_local_state`).Scan(&microseconds); err != nil {
		return 0, err
	}
	if microseconds <= 0 {
		microseconds = (5 * time.Minute).Microseconds()
	}
	return time.Duration(microseconds) * time.Microsecond, nil
}

func mergeRemoteHLC(ctx context.Context, tx *sql.Tx, physical, logical, nowUS int64, storedAt string) error {
	var localPhysical, localLogical int64
	if err := tx.QueryRowContext(ctx, `SELECT last_hlc_physical_utc_us,last_hlc_logical FROM replication_local_state`).Scan(&localPhysical, &localLogical); err != nil {
		return err
	}
	maximum := nowUS
	if localPhysical > maximum {
		maximum = localPhysical
	}
	if physical > maximum {
		maximum = physical
	}
	var nextLogical int64
	switch {
	case maximum == localPhysical && maximum == physical:
		if localLogical > logical {
			nextLogical = localLogical
		} else {
			nextLogical = logical
		}
	case maximum == localPhysical:
		nextLogical = localLogical
	case maximum == physical:
		nextLogical = logical
	default:
		nextLogical = -1
	}
	if nextLogical == math.MaxInt64 {
		return errors.New("replication: HLC logical overflow")
	}
	nextLogical++
	_, err := tx.ExecContext(ctx, `UPDATE replication_local_state SET last_hlc_physical_utc_us=?,last_hlc_logical=?,updated_at_utc=?`, maximum, nextLogical, storedAt)
	return err
}

func (r *replicationRuntime) withRemoteTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
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
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *replicationRuntime) storeDeferredRemoteEvent(ctx context.Context, peer, local string, d replicationTableDescriptor, event wireEvent, state, reason string) error {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	_, size, err := replicationEventHash(event)
	if err != nil {
		return err
	}
	return r.withRemoteTransaction(ctx, func(tx *sql.Tx) error {
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,source_node_uuid,payload_hash,payload_uncompressed_bytes,apply_state,quarantine_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.ChangeUUID, event.OriginNodeUUID, event.OriginCounter, event.Operation, event.TableName, event.RowKeyJSON, event.ChangedFieldsJSON, boolInt(event.ExplicitRecreation), event.HLCPhysicalUS, event.HLCLogical, event.SchemaVersion, event.SchemaHash, event.Domain, event.CreatedAtUTC, now, peer, event.PayloadHash, size, state, reason)
		if insertErr != nil {
			return insertErr
		}
		if insertErr = persistWirePayload(ctx, tx, d, event); insertErr != nil {
			return insertErr
		}
		return advanceRemoteCursor(ctx, tx, local, event.OriginNodeUUID, event.OriginCounter, now)
	})
}

func (r *replicationRuntime) quarantineRemoteEvent(ctx context.Context, peer, local string, d replicationTableDescriptor, event wireEvent, reason string) error {
	if err := r.storeDeferredRemoteEvent(ctx, peer, local, d, event, "quarantined", reason); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrReplicationEventQuarantined, reason)
}

func (r *replicationRuntime) deferOutOfOrderEvent(ctx context.Context, peer, local string, d replicationTableDescriptor, event wireEvent) error {
	return r.storeDeferredRemoteEvent(ctx, peer, local, d, event, "pending", "origin_gap")
}

func (r *replicationRuntime) loadStoredWireEvent(ctx context.Context, changeUUID string) (wireEvent, replicationTableDescriptor, error) {
	var event wireEvent
	var recreation int
	err := r.db.QueryRowContext(ctx, `SELECT change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,payload_hash FROM replication_changes WHERE change_uuid=?`, changeUUID).Scan(&event.ChangeUUID, &event.OriginNodeUUID, &event.OriginCounter, &event.Operation, &event.TableName, &event.RowKeyJSON, &event.ChangedFieldsJSON, &recreation, &event.HLCPhysicalUS, &event.HLCLogical, &event.SchemaVersion, &event.SchemaHash, &event.Domain, &event.CreatedAtUTC, &event.PayloadHash)
	if err != nil {
		return event, replicationTableDescriptor{}, err
	}
	event.ExplicitRecreation = recreation == 1
	descriptor, err := r.descriptor(ctx, event.TableName)
	if err != nil {
		return event, descriptor, err
	}
	columns := []string{}
	for _, name := range descriptor.Table.Columns {
		columns = append(columns, quoteReplicationIdent(name+"__value"), quoteReplicationIdent(name+"__present"))
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(values))
	for index := range values {
		pointers[index] = &values[index]
	}
	if err = r.db.QueryRowContext(ctx, `SELECT `+joinReplicationSQL(columns)+` FROM `+quoteReplicationIdent(descriptor.DescriptorID+"__replication_changes")+` WHERE change_uuid=?`, changeUUID).Scan(pointers...); err != nil {
		return event, descriptor, err
	}
	event.Values = map[string]wireValue{}
	for index, name := range descriptor.Table.Columns {
		present, ok := values[index*2+1].(int64)
		if !ok {
			return event, descriptor, errors.New("replication: invalid stored presence marker")
		}
		event.Values[name] = encodeWireValue(values[index*2], present == 1)
	}
	return event, descriptor, nil
}

func joinReplicationSQL(parts []string) string {
	result := ""
	for index, part := range parts {
		if index > 0 {
			result += ","
		}
		result += part
	}
	return result
}

func (r *replicationRuntime) recoverDeferredEvents(ctx context.Context) error {
	rows, err := r.db.QueryContext(ctx, `SELECT change_uuid FROM replication_changes WHERE apply_state IN('pending','quarantined') ORDER BY origin_node_uuid,origin_counter`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		event, _, loadErr := r.loadStoredWireEvent(ctx, id)
		if loadErr != nil {
			return loadErr
		}
		if applyErr := r.applyRemoteEvent(ctx, event.OriginNodeUUID, event); applyErr != nil && !errors.Is(applyErr, ErrReplicationEventQuarantined) {
			return applyErr
		}
	}
	return nil
}
