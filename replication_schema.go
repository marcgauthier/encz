package sqliteseal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const replicationMetadataDDL = `
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS replication_nodes(node_uuid TEXT PRIMARY KEY,incarnation_uuid TEXT NOT NULL UNIQUE,node_name TEXT NOT NULL UNIQUE,replication_domain TEXT NOT NULL,node_level INTEGER NOT NULL DEFAULT 0 CHECK(node_level>=0),is_local INTEGER NOT NULL CHECK(is_local IN(0,1)),membership_state TEXT NOT NULL CHECK(membership_state IN('joining','active','retired')),membership_epoch INTEGER NOT NULL,listen_enabled INTEGER NOT NULL CHECK(listen_enabled IN(0,1)),address TEXT,auth_mode TEXT NOT NULL CHECK(auth_mode IN('psk','mtls')),credential_name TEXT,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),rebootstrap_required INTEGER NOT NULL DEFAULT 1,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_replication_nodes_local ON replication_nodes(is_local) WHERE is_local=1;
CREATE TABLE IF NOT EXISTS replication_local_state(state_id INTEGER PRIMARY KEY CHECK(state_id=1),local_node_uuid TEXT NOT NULL,local_incarnation_uuid TEXT NOT NULL,replication_domain TEXT NOT NULL,last_origin_counter INTEGER NOT NULL DEFAULT 0,last_hlc_physical_utc_us INTEGER NOT NULL DEFAULT 0,last_hlc_logical INTEGER NOT NULL DEFAULT 0,membership_epoch INTEGER NOT NULL DEFAULT 1,membership_manifest_hash TEXT NOT NULL,database_generation INTEGER NOT NULL DEFAULT 1,network_enabled INTEGER NOT NULL DEFAULT 0,schema_version INTEGER NOT NULL,schema_hash TEXT NOT NULL,schema_revision INTEGER NOT NULL DEFAULT 1,blocked_reason TEXT,maximum_future_skew_us INTEGER NOT NULL DEFAULT 300000000,created_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replication_changes(change_seq INTEGER PRIMARY KEY AUTOINCREMENT,change_uuid TEXT NOT NULL UNIQUE,origin_node_uuid TEXT NOT NULL,origin_counter INTEGER NOT NULL,transaction_uuid TEXT,operation TEXT NOT NULL CHECK(operation IN('insert','update','delete')),table_name TEXT NOT NULL,row_key_json TEXT NOT NULL,changed_fields_json TEXT NOT NULL,is_explicit_recreation INTEGER NOT NULL DEFAULT 0,hlc_physical_utc_us INTEGER NOT NULL,hlc_logical INTEGER NOT NULL,schema_version INTEGER NOT NULL,schema_hash TEXT NOT NULL,canonicalization_version INTEGER NOT NULL DEFAULT 1,merge_policy_version INTEGER NOT NULL DEFAULT 1,replication_domain TEXT NOT NULL,created_at_utc TEXT NOT NULL,stored_at_utc TEXT NOT NULL,source_node_uuid TEXT,payload_hash TEXT NOT NULL,wire_values_json TEXT,payload_uncompressed_bytes INTEGER NOT NULL DEFAULT 0,apply_state TEXT NOT NULL DEFAULT 'applied',quarantine_reason TEXT,payload_state TEXT NOT NULL DEFAULT 'retained',UNIQUE(origin_node_uuid,origin_counter));
CREATE INDEX IF NOT EXISTS ix_replication_changes_origin ON replication_changes(origin_node_uuid,origin_counter);
CREATE TABLE IF NOT EXISTS replication_change_acks(change_uuid TEXT NOT NULL,acknowledging_node_uuid TEXT NOT NULL,ack_state TEXT NOT NULL,acknowledged_at_utc TEXT NOT NULL,PRIMARY KEY(change_uuid,acknowledging_node_uuid));
CREATE TABLE IF NOT EXISTS replication_field_versions(table_name TEXT NOT NULL,row_key_json TEXT NOT NULL,field_name TEXT NOT NULL,winner_hlc_physical_utc_us INTEGER NOT NULL,winner_hlc_logical INTEGER NOT NULL,winner_origin_node_uuid TEXT NOT NULL,winner_change_uuid TEXT NOT NULL,winner_changed_at_utc TEXT NOT NULL,value_hash TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(table_name,row_key_json,field_name));
CREATE TABLE IF NOT EXISTS replication_row_versions(table_name TEXT NOT NULL,row_key_json TEXT NOT NULL,row_state TEXT NOT NULL,winner_hlc_physical_utc_us INTEGER NOT NULL,winner_hlc_logical INTEGER NOT NULL,winner_origin_node_uuid TEXT NOT NULL,winner_change_uuid TEXT NOT NULL,winner_changed_at_utc TEXT NOT NULL,updated_at_utc TEXT NOT NULL,PRIMARY KEY(table_name,row_key_json));
CREATE TABLE IF NOT EXISTS replication_origin_cursors(tracking_node_uuid TEXT NOT NULL,origin_node_uuid TEXT NOT NULL,contiguous_counter INTEGER NOT NULL DEFAULT 0,highest_seen_counter INTEGER NOT NULL DEFAULT 0,baseline_snapshot_uuid TEXT,requires_snapshot INTEGER NOT NULL DEFAULT 0,updated_at_utc TEXT NOT NULL,PRIMARY KEY(tracking_node_uuid,origin_node_uuid));
CREATE TABLE IF NOT EXISTS replication_origin_gaps(tracking_node_uuid TEXT NOT NULL,origin_node_uuid TEXT NOT NULL,gap_start_counter INTEGER NOT NULL,gap_end_counter INTEGER NOT NULL,detected_at_utc TEXT NOT NULL,last_requested_at_utc TEXT,request_count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(tracking_node_uuid,origin_node_uuid,gap_start_counter));
CREATE TABLE IF NOT EXISTS replication_snapshots(snapshot_uuid TEXT PRIMARY KEY,created_by_node_uuid TEXT NOT NULL,replication_domain TEXT NOT NULL,membership_epoch INTEGER NOT NULL,membership_manifest_hash TEXT NOT NULL,schema_version INTEGER NOT NULL,schema_hash TEXT NOT NULL,baseline_cursors_gzip BLOB NOT NULL,baseline_cursors_uncompressed_bytes INTEGER NOT NULL DEFAULT 0,content_hash TEXT NOT NULL,snapshot_auth_mode TEXT NOT NULL DEFAULT 'session',creator_signing_key_id TEXT,creator_signature BLOB,content_size_bytes INTEGER NOT NULL,snapshot_state TEXT NOT NULL,storage_uri TEXT,installed_by_node_uuid TEXT,created_at_utc TEXT NOT NULL,verified_at_utc TEXT,installed_at_utc TEXT);
CREATE TABLE IF NOT EXISTS replication_peer_connections(peer_node_uuid TEXT PRIMARY KEY,connection_role TEXT NOT NULL CHECK(connection_role IN('dial','accept')),enabled INTEGER NOT NULL,reconnect_enabled INTEGER NOT NULL,address TEXT,connect_timeout_ms INTEGER NOT NULL,heartbeat_interval_ms INTEGER NOT NULL,heartbeat_timeout_ms INTEGER NOT NULL,reconnect_initial_ms INTEGER NOT NULL,reconnect_max_ms INTEGER NOT NULL,reconnect_jitter_percent INTEGER NOT NULL DEFAULT 20,max_snapshot_bytes INTEGER NOT NULL DEFAULT 268435456,max_compressed_frame_bytes INTEGER NOT NULL,max_uncompressed_message_bytes INTEGER NOT NULL,max_events_per_batch INTEGER NOT NULL,max_inflight_events INTEGER NOT NULL,max_inflight_bytes INTEGER NOT NULL,session_state TEXT NOT NULL,last_session_uuid TEXT,connected_at_utc TEXT,next_retry_at_utc TEXT,consecutive_failures INTEGER NOT NULL DEFAULT 0,last_error TEXT,updated_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replication_rejected_events(rejection_uuid TEXT PRIMARY KEY,received_from_node_uuid TEXT,claimed_change_uuid TEXT,claimed_origin_node_uuid TEXT,claimed_origin_counter INTEGER,evidence_hash TEXT NOT NULL,bounded_evidence BLOB,reason_code TEXT NOT NULL,recorded_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replication_table_descriptors(table_name TEXT PRIMARY KEY,descriptor_id TEXT NOT NULL UNIQUE,descriptor_json TEXT NOT NULL,schema_hash TEXT NOT NULL,allow_recreation INTEGER NOT NULL DEFAULT 0,created_at_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replication_schema_declarations(origin_node_uuid TEXT NOT NULL,schema_revision INTEGER NOT NULL,table_name TEXT NOT NULL,table_json TEXT NOT NULL,descriptor_json TEXT,updated_at_utc TEXT NOT NULL,PRIMARY KEY(origin_node_uuid,table_name));
CREATE TABLE IF NOT EXISTS replication_schema_conflicts(table_name TEXT NOT NULL,column_name TEXT NOT NULL,authority_level INTEGER NOT NULL,declared_types_json TEXT NOT NULL,origin_nodes_json TEXT NOT NULL,updated_at_utc TEXT NOT NULL,PRIMARY KEY(table_name,column_name));
`

type replicationColumn struct {
	Name, DeclaredType  string
	PK, Hidden, NotNull int
	DefaultSQL          string
}
type replicationForeignKey struct {
	ID, Sequence                      int
	ParentTable, FromColumn, ToColumn string
	OnUpdate, OnDelete, Match         string
}
type replicationIndexColumn struct {
	Sequence, ColumnID, Descending, Key int
	Name, Collation                     string
}
type replicationIndex struct {
	Name, Origin, SQL string
	Unique, Partial   int
	Columns           []replicationIndexColumn
}
type replicationTrigger struct{ Name, SQL string }
type replicationTableDescriptor struct {
	Table        ReplicatedTable         `json:"table"`
	Columns      []replicationColumn     `json:"columns"`
	ForeignKeys  []replicationForeignKey `json:"foreign_keys,omitempty"`
	Indexes      []replicationIndex      `json:"indexes,omitempty"`
	Triggers     []replicationTrigger    `json:"triggers,omitempty"`
	TableSQL     string                  `json:"table_sql"`
	DescriptorID string                  `json:"descriptor_id"`
}

func quoteReplicationIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func tableDescriptor(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, table ReplicatedTable) (replicationTableDescriptor, error) {
	if table.Name == "" || strings.HasPrefix(table.Name, "replication_") {
		return replicationTableDescriptor{}, ErrReplicationInvalidConfig
	}
	rows, err := q.QueryContext(ctx, "PRAGMA table_xinfo("+quoteReplicationIdent(table.Name)+")")
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	defer rows.Close()
	var cols []replicationColumn
	for rows.Next() {
		var cid, notnull, pk, hidden int
		var name, typ string
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk, &hidden); err != nil {
			return replicationTableDescriptor{}, err
		}
		defaultSQL := ""
		if def != nil {
			defaultSQL = fmt.Sprint(def)
		}
		cols = append(cols, replicationColumn{Name: name, DeclaredType: typ, PK: pk, Hidden: hidden, NotNull: notnull, DefaultSQL: defaultSQL})
	}
	if len(cols) == 0 {
		return replicationTableDescriptor{}, fmt.Errorf("%w: table %q does not exist", ErrReplicationInvalidConfig, table.Name)
	}
	by := map[string]replicationColumn{}
	for _, c := range cols {
		by[c.Name] = c
	}
	if len(table.PrimaryKeyColumns) == 0 {
		for _, c := range cols {
			if c.PK > 0 {
				table.PrimaryKeyColumns = append(table.PrimaryKeyColumns, c.Name)
			}
		}
		sort.Slice(table.PrimaryKeyColumns, func(i, j int) bool { return by[table.PrimaryKeyColumns[i]].PK < by[table.PrimaryKeyColumns[j]].PK })
	}
	if len(table.PrimaryKeyColumns) == 0 {
		return replicationTableDescriptor{}, fmt.Errorf("%w: %s has no primary key", ErrReplicationSchemaUnsupported, table.Name)
	}
	if len(table.Columns) == 0 {
		for _, c := range cols {
			if c.Hidden == 0 {
				table.Columns = append(table.Columns, c.Name)
			}
		}
	}
	for _, n := range append(append([]string{}, table.PrimaryKeyColumns...), table.Columns...) {
		c, ok := by[n]
		if !ok || c.Hidden != 0 {
			return replicationTableDescriptor{}, fmt.Errorf("%w: invalid column %s.%s", ErrReplicationSchemaUnsupported, table.Name, n)
		}
	}
	if table.ConstraintPolicy != ReplicationConstraintsReject && table.ConstraintPolicy != ReplicationConstraintsManaged {
		return replicationTableDescriptor{}, fmt.Errorf("%w: invalid constraint policy for %s", ErrReplicationInvalidConfig, table.Name)
	}
	fkRows, err := q.QueryContext(ctx, "PRAGMA foreign_key_list("+quoteReplicationIdent(table.Name)+")")
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	var foreignKeys []replicationForeignKey
	for fkRows.Next() {
		var item replicationForeignKey
		if err = fkRows.Scan(&item.ID, &item.Sequence, &item.ParentTable, &item.FromColumn, &item.ToColumn, &item.OnUpdate, &item.OnDelete, &item.Match); err != nil {
			fkRows.Close()
			return replicationTableDescriptor{}, err
		}
		foreignKeys = append(foreignKeys, item)
	}
	if err = fkRows.Close(); err != nil {
		return replicationTableDescriptor{}, err
	}
	if len(foreignKeys) > 0 && table.ConstraintPolicy != ReplicationConstraintsManaged {
		return replicationTableDescriptor{}, fmt.Errorf("%w: %s has a foreign key; use ReplicationConstraintsManaged", ErrReplicationSchemaUnsupported, table.Name)
	}
	indexSQL := map[string]string{}
	sqlRows, err := q.QueryContext(ctx, `SELECT name,coalesce(sql,'') FROM sqlite_master WHERE type='index' AND tbl_name=?`, table.Name)
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	for sqlRows.Next() {
		var name, statement string
		if err = sqlRows.Scan(&name, &statement); err != nil {
			sqlRows.Close()
			return replicationTableDescriptor{}, err
		}
		indexSQL[name] = statement
	}
	if err = sqlRows.Close(); err != nil {
		return replicationTableDescriptor{}, err
	}
	indexRows, err := q.QueryContext(ctx, "PRAGMA index_list("+quoteReplicationIdent(table.Name)+")")
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	var tableIndexes []replicationIndex
	for indexRows.Next() {
		var seq int
		var item replicationIndex
		if err = indexRows.Scan(&seq, &item.Name, &item.Unique, &item.Origin, &item.Partial); err != nil {
			indexRows.Close()
			return replicationTableDescriptor{}, err
		}
		if item.Unique == 1 && item.Origin != "pk" && table.ConstraintPolicy != ReplicationConstraintsManaged {
			indexRows.Close()
			return replicationTableDescriptor{}, fmt.Errorf("%w: %s has non-primary unique index %s; use ReplicationConstraintsManaged", ErrReplicationSchemaUnsupported, table.Name, item.Name)
		}
		item.SQL = indexSQL[item.Name]
		tableIndexes = append(tableIndexes, item)
	}
	if err = indexRows.Close(); err != nil {
		return replicationTableDescriptor{}, err
	}
	sort.Slice(tableIndexes, func(i, j int) bool { return tableIndexes[i].Name < tableIndexes[j].Name })
	for i := range tableIndexes {
		columnRows, columnErr := q.QueryContext(ctx, "PRAGMA index_xinfo("+quoteReplicationIdent(tableIndexes[i].Name)+")")
		if columnErr != nil {
			return replicationTableDescriptor{}, columnErr
		}
		for columnRows.Next() {
			var column replicationIndexColumn
			var name, collation sql.NullString
			if columnErr = columnRows.Scan(&column.Sequence, &column.ColumnID, &name, &column.Descending, &collation, &column.Key); columnErr != nil {
				columnRows.Close()
				return replicationTableDescriptor{}, columnErr
			}
			if name.Valid {
				column.Name = name.String
			}
			if collation.Valid {
				column.Collation = collation.String
			}
			tableIndexes[i].Columns = append(tableIndexes[i].Columns, column)
		}
		if columnErr = columnRows.Close(); columnErr != nil {
			return replicationTableDescriptor{}, columnErr
		}
		if tableIndexes[i].Unique == 1 && tableIndexes[i].Origin != "pk" {
			for _, column := range tableIndexes[i].Columns {
				if column.Key == 1 && column.ColumnID < 0 {
					return replicationTableDescriptor{}, fmt.Errorf("%w: %s has expression unique index %s", ErrReplicationSchemaUnsupported, table.Name, tableIndexes[i].Name)
				}
			}
		}
	}
	var tableSQL string
	schemaRows, err := q.QueryContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table.Name)
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	if schemaRows.Next() {
		if err = schemaRows.Scan(&tableSQL); err != nil {
			schemaRows.Close()
			return replicationTableDescriptor{}, err
		}
	}
	schemaRows.Close()
	triggerRows, err := q.QueryContext(ctx, `SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=? AND name NOT LIKE 'sqliteseal_%' ORDER BY name`, table.Name)
	if err != nil {
		return replicationTableDescriptor{}, err
	}
	var triggers []replicationTrigger
	for triggerRows.Next() {
		var item replicationTrigger
		if err = triggerRows.Scan(&item.Name, &item.SQL); err != nil {
			triggerRows.Close()
			return replicationTableDescriptor{}, err
		}
		triggers = append(triggers, item)
	}
	if err = triggerRows.Close(); err != nil {
		return replicationTableDescriptor{}, err
	}
	descriptor := replicationTableDescriptor{Table: table, Columns: cols, ForeignKeys: foreignKeys, Indexes: tableIndexes, Triggers: triggers, TableSQL: tableSQL}
	raw, _ := json.Marshal(descriptor)
	sum := sha256.Sum256(raw)
	descriptor.DescriptorID = hex.EncodeToString(sum[:8])
	return descriptor, nil
}
func descriptorsHash(ds []replicationTableDescriptor) (string, error) {
	sort.Slice(ds, func(i, j int) bool { return ds[i].Table.Name < ds[j].Table.Name })
	b, err := json.Marshal(ds)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}
