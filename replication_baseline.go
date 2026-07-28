package sqliteseal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

func captureExistingRows(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor) error {
	columns := make([]string, len(d.Table.Columns))
	for i, n := range d.Table.Columns {
		columns[i] = quoteReplicationIdent(n)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+strings.Join(columns, ",")+` FROM `+quoteReplicationIdent(d.Table.Name))
	if err != nil {
		return err
	}
	var existing [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		ptr := make([]any, len(columns))
		for i := range values {
			ptr[i] = &values[i]
		}
		if err = rows.Scan(ptr...); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, values)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(existing) == 0 {
		return nil
	}
	byIndex := map[string]int{}
	for i, n := range d.Table.Columns {
		byIndex[n] = i
	}
	changedRaw, _ := json.Marshal(d.Table.Columns)
	for _, values := range existing {
		key := map[string]any{}
		for _, n := range d.Table.PrimaryKeyColumns {
			key[n] = values[byIndex[n]]
		}
		rowKey, err := json.Marshal(key)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET last_origin_counter=last_origin_counter+1,last_hlc_logical=CASE WHEN sqliteseal_time_us()>last_hlc_physical_utc_us THEN 0 ELSE last_hlc_logical+1 END,last_hlc_physical_utc_us=max(last_hlc_physical_utc_us,sqliteseal_time_us()),updated_at_utc=sqliteseal_utc_now()`); err != nil {
			return err
		}
		var node, domain, schema string
		var counter, physical, logical, version int64
		if err = tx.QueryRowContext(ctx, `SELECT local_node_uuid,replication_domain,schema_hash,last_origin_counter,last_hlc_physical_utc_us,last_hlc_logical,schema_version FROM replication_local_state`).Scan(&node, &domain, &schema, &counter, &physical, &logical, &version); err != nil {
			return err
		}
		eventID := replicationEventUUID(node, counter)
		created := replicationTimeFromUS(physical)
		wireValues := make(map[string]wireValue, len(d.Table.Columns))
		for i, name := range d.Table.Columns {
			wireValues[name] = encodeWireValue(values[i], true)
		}
		event := wireEvent{
			ChangeUUID: eventID, OriginNodeUUID: node, OriginCounter: counter,
			Operation: "insert", TableName: d.Table.Name, RowKeyJSON: string(rowKey),
			ChangedFieldsJSON: string(changedRaw), HLCPhysicalUS: physical,
			HLCLogical: logical, SchemaVersion: version, SchemaHash: schema,
			Domain: domain, CreatedAtUTC: created, Values: wireValues,
		}
		payloadHash, _, err := replicationEventHash(event)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,payload_hash) VALUES(?,?,?,'insert',?,?,?,?,?,?,?,?,?,?,?)`, eventID, node, counter, d.Table.Name, string(rowKey), string(changedRaw), physical, logical, version, schema, domain, created, created, payloadHash); err != nil {
			return fmt.Errorf("capture existing %s row: %w", d.Table.Name, err)
		}
		payloadColumns := []string{"change_uuid", "field_versions_json"}
		marks := []string{"?", "?"}
		args := []any{eventID, "{}"}
		for i, n := range d.Table.Columns {
			payloadColumns = append(payloadColumns, n+"__value", n+"__present")
			marks = append(marks, "?", "?")
			args = append(args, values[i], 1)
		}
		for i := range payloadColumns {
			payloadColumns[i] = quoteReplicationIdent(payloadColumns[i])
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(d.DescriptorID+"__replication_changes")+`(`+strings.Join(payloadColumns, ",")+`) VALUES(`+strings.Join(marks, ",")+`)`, args...); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,'live',?,?,?,?,?,?)`, d.Table.Name, string(rowKey), physical, logical, node, eventID, created, created); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?, ?,NULL,0,?) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET contiguous_counter=excluded.contiguous_counter,highest_seen_counter=excluded.highest_seen_counter,updated_at_utc=excluded.updated_at_utc`, node, node, counter, counter, created); err != nil {
			return err
		}
	}
	return nil
}
