package sqliteseal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	replicationSnapshotFormatVersion = 1
	maximumReplicationSnapshotBytes  = 256 << 20
)

type replicationSnapshotDocument struct {
	FormatVersion          int                               `json:"format_version"`
	SnapshotUUID           string                            `json:"snapshot_uuid"`
	CreatedByNodeUUID      string                            `json:"created_by_node_uuid"`
	ReplicationDomain      string                            `json:"replication_domain"`
	MembershipEpoch        int64                             `json:"membership_epoch"`
	MembershipManifestHash string                            `json:"membership_manifest_hash"`
	SchemaVersion          int64                             `json:"schema_version"`
	SchemaHash             string                            `json:"schema_hash"`
	CreatedAtUTC           string                            `json:"created_at_utc"`
	BaselineCursors        []wireCursor                      `json:"baseline_cursors"`
	Tables                 []replicationSnapshotTable        `json:"tables"`
	FieldVersions          []replicationSnapshotFieldVersion `json:"field_versions"`
	RowVersions            []replicationSnapshotRowVersion   `json:"row_versions"`
}

type replicationSnapshotTable struct {
	Name string                   `json:"name"`
	Rows []replicationSnapshotRow `json:"rows"`
}

type replicationSnapshotRow struct {
	Values []replicationSnapshotValue `json:"values"`
}

type replicationSnapshotValue struct {
	Name  string    `json:"name"`
	Value wireValue `json:"value"`
}

type replicationSnapshotFieldVersion struct {
	TableName      string  `json:"table_name"`
	RowKeyJSON     string  `json:"row_key_json"`
	FieldName      string  `json:"field_name"`
	HLCPhysicalUS  int64   `json:"hlc_physical_utc_us"`
	HLCLogical     int64   `json:"hlc_logical"`
	OriginNodeUUID string  `json:"origin_node_uuid"`
	ChangeUUID     string  `json:"change_uuid"`
	ChangedAtUTC   string  `json:"changed_at_utc"`
	ValueHash      *string `json:"value_hash"`
	UpdatedAtUTC   string  `json:"updated_at_utc"`
}

type replicationSnapshotRowVersion struct {
	TableName      string `json:"table_name"`
	RowKeyJSON     string `json:"row_key_json"`
	RowState       string `json:"row_state"`
	HLCPhysicalUS  int64  `json:"hlc_physical_utc_us"`
	HLCLogical     int64  `json:"hlc_logical"`
	OriginNodeUUID string `json:"origin_node_uuid"`
	ChangeUUID     string `json:"change_uuid"`
	ChangedAtUTC   string `json:"changed_at_utc"`
	UpdatedAtUTC   string `json:"updated_at_utc"`
}

type replicationSnapshotManifest struct {
	SnapshotUUID           string `json:"snapshot_uuid"`
	CreatedByNodeUUID      string `json:"created_by_node_uuid"`
	ReplicationDomain      string `json:"replication_domain"`
	MembershipEpoch        int64  `json:"membership_epoch"`
	MembershipManifestHash string `json:"membership_manifest_hash"`
	SchemaVersion          int64  `json:"schema_version"`
	SchemaHash             string `json:"schema_hash"`
	ContentHash            string `json:"content_hash"`
	ContentSizeBytes       int64  `json:"content_size_bytes"`
	CreatedAtUTC           string `json:"created_at_utc"`
}

func canonicalSnapshotBytes(document replicationSnapshotDocument) ([]byte, error) {
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

func snapshotHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func gzipSnapshotJSON(raw []byte) ([]byte, error) {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func snapshotDescriptors(ctx context.Context, tx *sql.Tx) ([]replicationTableDescriptor, error) {
	rows, err := tx.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var descriptors []replicationTableDescriptor
	for rows.Next() {
		var raw string
		var descriptor replicationTableDescriptor
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &descriptor); err != nil {
			return nil, err
		}
		descriptors = append(descriptors, descriptor)
	}
	return descriptors, rows.Err()
}

func captureSnapshotCursors(ctx context.Context, tx *sql.Tx, local string) ([]wireCursor, error) {
	rows, err := tx.QueryContext(ctx, `SELECT origin_node_uuid,contiguous_counter,highest_seen_counter,coalesce(baseline_snapshot_uuid,''),requires_snapshot
		FROM replication_origin_cursors WHERE tracking_node_uuid=? ORDER BY origin_node_uuid`, local)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cursors []wireCursor
	for rows.Next() {
		var cursor wireCursor
		var requires int
		if err = rows.Scan(&cursor.OriginNodeUUID, &cursor.ContiguousCounter, &cursor.HighestSeenCounter, &cursor.BaselineSnapshotUUID, &requires); err != nil {
			return nil, err
		}
		cursor.RequiresSnapshot = requires == 1
		cursors = append(cursors, cursor)
	}
	return cursors, rows.Err()
}

func captureSnapshotTables(ctx context.Context, tx *sql.Tx, descriptors []replicationTableDescriptor) ([]replicationSnapshotTable, error) {
	tables := make([]replicationSnapshotTable, 0, len(descriptors))
	for _, descriptor := range descriptors {
		columns := make([]string, 0, len(descriptor.Table.Columns))
		for _, column := range descriptor.Table.Columns {
			columns = append(columns, quoteReplicationIdent(column))
		}
		order := make([]string, 0, len(descriptor.Table.PrimaryKeyColumns))
		for _, column := range descriptor.Table.PrimaryKeyColumns {
			order = append(order, quoteReplicationIdent(column))
		}
		query := `SELECT ` + strings.Join(columns, ",") + ` FROM ` + quoteReplicationIdent(descriptor.Table.Name) + ` ORDER BY ` + strings.Join(order, ",")
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		table := replicationSnapshotTable{Name: descriptor.Table.Name, Rows: []replicationSnapshotRow{}}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(values))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				rows.Close()
				return nil, err
			}
			row := replicationSnapshotRow{Values: make([]replicationSnapshotValue, len(values))}
			for i, value := range values {
				row.Values[i] = replicationSnapshotValue{Name: descriptor.Table.Columns[i], Value: encodeWireValue(value, true)}
			}
			table.Rows = append(table.Rows, row)
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func captureSnapshotVersions(ctx context.Context, tx *sql.Tx) ([]replicationSnapshotFieldVersion, []replicationSnapshotRowVersion, error) {
	fieldRows, err := tx.QueryContext(ctx, `SELECT table_name,row_key_json,field_name,winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,winner_change_uuid,winner_changed_at_utc,value_hash,updated_at_utc FROM replication_field_versions ORDER BY table_name,row_key_json,field_name`)
	if err != nil {
		return nil, nil, err
	}
	var fields []replicationSnapshotFieldVersion
	for fieldRows.Next() {
		var field replicationSnapshotFieldVersion
		var valueHash sql.NullString
		if err = fieldRows.Scan(&field.TableName, &field.RowKeyJSON, &field.FieldName, &field.HLCPhysicalUS, &field.HLCLogical, &field.OriginNodeUUID, &field.ChangeUUID, &field.ChangedAtUTC, &valueHash, &field.UpdatedAtUTC); err != nil {
			fieldRows.Close()
			return nil, nil, err
		}
		if valueHash.Valid {
			value := valueHash.String
			field.ValueHash = &value
		}
		fields = append(fields, field)
	}
	if err = fieldRows.Close(); err != nil {
		return nil, nil, err
	}
	rowRows, err := tx.QueryContext(ctx, `SELECT table_name,row_key_json,row_state,winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,winner_change_uuid,winner_changed_at_utc,updated_at_utc FROM replication_row_versions ORDER BY table_name,row_key_json`)
	if err != nil {
		return nil, nil, err
	}
	defer rowRows.Close()
	var versions []replicationSnapshotRowVersion
	for rowRows.Next() {
		var version replicationSnapshotRowVersion
		if err = rowRows.Scan(&version.TableName, &version.RowKeyJSON, &version.RowState, &version.HLCPhysicalUS, &version.HLCLogical, &version.OriginNodeUUID, &version.ChangeUUID, &version.ChangedAtUTC, &version.UpdatedAtUTC); err != nil {
			return nil, nil, err
		}
		versions = append(versions, version)
	}
	return fields, versions, rowRows.Err()
}

func (db *DB) CreateReplicationSnapshot(ctx context.Context) (ReplicationSnapshotInfo, error) {
	var info ReplicationSnapshotInfo
	if db.replication == nil {
		return info, ErrReplicationNotInitialized
	}
	r := db.replication
	r.writer.Lock()
	defer r.writer.Unlock()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return info, err
	}
	defer tx.Rollback()
	document := replicationSnapshotDocument{FormatVersion: replicationSnapshotFormatVersion, SnapshotUUID: replicationUUID(), CreatedAtUTC: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")}
	if err = tx.QueryRowContext(ctx, `SELECT local_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash FROM replication_local_state`).Scan(&document.CreatedByNodeUUID, &document.ReplicationDomain, &document.MembershipEpoch, &document.MembershipManifestHash, &document.SchemaVersion, &document.SchemaHash); err != nil {
		return info, err
	}
	descriptors, err := snapshotDescriptors(ctx, tx)
	if err != nil {
		return info, err
	}
	if document.BaselineCursors, err = captureSnapshotCursors(ctx, tx, document.CreatedByNodeUUID); err != nil {
		return info, err
	}
	for _, cursor := range document.BaselineCursors {
		if cursor.RequiresSnapshot || cursor.ContiguousCounter != cursor.HighestSeenCounter {
			return info, errors.New("replication: cannot snapshot incomplete origin history")
		}
	}
	var gapCount int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_origin_gaps WHERE tracking_node_uuid=?`, document.CreatedByNodeUUID).Scan(&gapCount); err != nil {
		return info, err
	}
	if gapCount != 0 {
		return info, errors.New("replication: cannot snapshot while origin gaps remain")
	}
	if document.Tables, err = captureSnapshotTables(ctx, tx, descriptors); err != nil {
		return info, err
	}
	if document.FieldVersions, document.RowVersions, err = captureSnapshotVersions(ctx, tx); err != nil {
		return info, err
	}
	raw, err := canonicalSnapshotBytes(document)
	if err != nil {
		return info, err
	}
	if len(raw) > maximumReplicationSnapshotBytes {
		return info, errors.New("replication: snapshot exceeds size limit")
	}
	cursorRaw, err := canonicalJSONMustMarshal(document.BaselineCursors)
	if err != nil {
		return info, err
	}
	cursorGzip, err := gzipSnapshotJSON(cursorRaw)
	if err != nil {
		return info, err
	}
	if err = tx.Commit(); err != nil {
		return info, err
	}
	storagePath, err := r.writeSnapshotFile(document.SnapshotUUID, raw)
	if err != nil {
		return info, err
	}
	contentHash := snapshotHash(raw)
	_, err = db.ExecContext(ctx, `INSERT INTO replication_snapshots(snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,baseline_cursors_gzip,baseline_cursors_uncompressed_bytes,content_hash,snapshot_auth_mode,content_size_bytes,snapshot_state,storage_uri,created_at_utc,verified_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,'session',?,'ready',?,?,?)`, document.SnapshotUUID, document.CreatedByNodeUUID, document.ReplicationDomain, document.MembershipEpoch, document.MembershipManifestHash, document.SchemaVersion, document.SchemaHash, cursorGzip, len(cursorRaw), contentHash, len(raw), storagePath, document.CreatedAtUTC, document.CreatedAtUTC)
	if err != nil {
		_ = os.Remove(storagePath)
		return info, err
	}
	created, _ := time.Parse("2006-01-02T15:04:05.000000Z", document.CreatedAtUTC)
	return ReplicationSnapshotInfo{SnapshotUUID: document.SnapshotUUID, SchemaHash: document.SchemaHash, ContentHash: contentHash, CreatedAt: created, SizeBytes: int64(len(raw))}, nil
}

func canonicalJSONMustMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

func (r *replicationRuntime) writeSnapshotFile(snapshotUUID string, raw []byte) (string, error) {
	directory := r.db.path + ".replication-snapshots"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, snapshotUUID+".json")
	temporary := filepath.Join(directory, "."+snapshotUUID+".tmp")
	if err := os.WriteFile(temporary, raw, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return path, nil
}

func (r *replicationRuntime) snapshotByUUID(ctx context.Context, snapshotUUID string) (replicationSnapshotManifest, []byte, error) {
	var manifest replicationSnapshotManifest
	var path string
	err := r.db.QueryRowContext(ctx, `SELECT snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,content_hash,content_size_bytes,created_at_utc,storage_uri FROM replication_snapshots WHERE snapshot_uuid=? AND snapshot_state IN('ready','installed')`, snapshotUUID).Scan(&manifest.SnapshotUUID, &manifest.CreatedByNodeUUID, &manifest.ReplicationDomain, &manifest.MembershipEpoch, &manifest.MembershipManifestHash, &manifest.SchemaVersion, &manifest.SchemaHash, &manifest.ContentHash, &manifest.ContentSizeBytes, &manifest.CreatedAtUTC, &path)
	if err != nil {
		return manifest, nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return manifest, nil, err
	}
	if int64(len(raw)) != manifest.ContentSizeBytes || snapshotHash(raw) != manifest.ContentHash {
		return manifest, nil, errors.New("replication: stored snapshot integrity failure")
	}
	return manifest, raw, nil
}

func (r *replicationRuntime) latestSnapshot(ctx context.Context) (replicationSnapshotManifest, []byte, error) {
	var snapshotUUID string
	err := r.db.QueryRowContext(ctx, `SELECT snapshot_uuid FROM replication_snapshots WHERE snapshot_state IN('ready','installed') ORDER BY created_at_utc DESC LIMIT 1`).Scan(&snapshotUUID)
	if err == sql.ErrNoRows {
		info, createErr := r.db.CreateReplicationSnapshot(ctx)
		if createErr != nil {
			return replicationSnapshotManifest{}, nil, createErr
		}
		snapshotUUID = info.SnapshotUUID
	} else if err != nil {
		return replicationSnapshotManifest{}, nil, err
	}
	return r.snapshotByUUID(ctx, snapshotUUID)
}

func (r *replicationRuntime) createTransferSnapshot(ctx context.Context) (replicationSnapshotManifest, []byte, error) {
	info, err := r.db.CreateReplicationSnapshot(ctx)
	if err != nil {
		return replicationSnapshotManifest{}, nil, err
	}
	return r.snapshotByUUID(ctx, info.SnapshotUUID)
}

func validateSnapshotDocument(raw []byte, manifest replicationSnapshotManifest, expectedCreator, domain, membershipHash, _ string, membershipEpoch, _ int64) (replicationSnapshotDocument, error) {
	var document replicationSnapshotDocument
	if len(raw) == 0 || len(raw) > maximumReplicationSnapshotBytes || int64(len(raw)) != manifest.ContentSizeBytes || snapshotHash(raw) != manifest.ContentHash {
		return document, errors.New("replication: snapshot content integrity failure")
	}
	canonical, err := canonicalJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return document, errors.New("replication: non-canonical snapshot")
	}
	if err = json.Unmarshal(raw, &document); err != nil {
		return document, err
	}
	if document.FormatVersion != replicationSnapshotFormatVersion || !isCanonicalUUID(document.SnapshotUUID) || document.SnapshotUUID != manifest.SnapshotUUID || document.CreatedByNodeUUID != expectedCreator || document.CreatedByNodeUUID != manifest.CreatedByNodeUUID {
		return document, errors.New("replication: invalid snapshot identity")
	}
	if document.ReplicationDomain != domain || document.ReplicationDomain != manifest.ReplicationDomain || document.MembershipEpoch != membershipEpoch || document.MembershipEpoch != manifest.MembershipEpoch || document.MembershipManifestHash != membershipHash || document.MembershipManifestHash != manifest.MembershipManifestHash || document.SchemaVersion != manifest.SchemaVersion || document.SchemaHash != manifest.SchemaHash || document.CreatedAtUTC != manifest.CreatedAtUTC {
		return document, ErrReplicationSchemaMismatch
	}
	if _, err = time.Parse("2006-01-02T15:04:05.000000Z", document.CreatedAtUTC); err != nil {
		return document, errors.New("replication: invalid snapshot timestamp")
	}
	return document, nil
}

func descriptorMap(descriptors []replicationTableDescriptor) map[string]replicationTableDescriptor {
	result := make(map[string]replicationTableDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		result[descriptor.Table.Name] = descriptor
	}
	return result
}

func validateSnapshotStructure(document replicationSnapshotDocument, descriptors []replicationTableDescriptor) error {
	byTable := descriptorMap(descriptors)
	columnsByTable := make(map[string]map[string]bool, len(descriptors))
	for _, descriptor := range descriptors {
		columns := make(map[string]bool, len(descriptor.Table.Columns))
		for _, column := range descriptor.Table.Columns {
			columns[column] = true
		}
		columnsByTable[descriptor.Table.Name] = columns
	}
	if len(document.Tables) != len(descriptors) {
		return errors.New("replication: incomplete snapshot table set")
	}
	seenTables := map[string]bool{}
	for _, table := range document.Tables {
		descriptor, ok := byTable[table.Name]
		if !ok || seenTables[table.Name] {
			return errors.New("replication: invalid snapshot table")
		}
		seenTables[table.Name] = true
		for _, row := range table.Rows {
			if len(row.Values) != len(descriptor.Table.Columns) {
				return errors.New("replication: incomplete snapshot row")
			}
			for i, value := range row.Values {
				if value.Name != descriptor.Table.Columns[i] || !value.Value.Present {
					return errors.New("replication: invalid snapshot column")
				}
				if _, err := decodeWireValue(value.Value); err != nil {
					return err
				}
			}
		}
	}
	seenOrigins := map[string]bool{}
	for _, cursor := range document.BaselineCursors {
		if !isCanonicalUUID(cursor.OriginNodeUUID) || cursor.ContiguousCounter < 0 || cursor.HighestSeenCounter != cursor.ContiguousCounter || cursor.RequiresSnapshot || seenOrigins[cursor.OriginNodeUUID] {
			return errors.New("replication: invalid snapshot cursor vector")
		}
		seenOrigins[cursor.OriginNodeUUID] = true
	}
	for _, field := range document.FieldVersions {
		canonicalKey, err := canonicalJSON([]byte(field.RowKeyJSON))
		if err != nil || string(canonicalKey) != field.RowKeyJSON || !columnsByTable[field.TableName][field.FieldName] || field.HLCPhysicalUS <= 0 || field.HLCLogical < 0 || !isCanonicalUUID(field.OriginNodeUUID) || !isCanonicalUUID(field.ChangeUUID) {
			return errors.New("replication: invalid snapshot field version")
		}
	}
	for _, version := range document.RowVersions {
		canonicalKey, err := canonicalJSON([]byte(version.RowKeyJSON))
		if err != nil || string(canonicalKey) != version.RowKeyJSON || byTable[version.TableName].Table.Name == "" || version.RowState != "live" && version.RowState != "deleted" && version.RowState != "unique_deleted" || version.HLCPhysicalUS <= 0 || version.HLCLogical < 0 || !isCanonicalUUID(version.OriginNodeUUID) || !isCanonicalUUID(version.ChangeUUID) {
			return errors.New("replication: invalid snapshot row version")
		}
	}
	return nil
}

func (r *replicationRuntime) installSessionSnapshot(ctx context.Context, expectedCreator string, manifest replicationSnapshotManifest, raw []byte) error {
	if err := manifest.validate(); err != nil {
		return err
	}
	var local, domain, membershipHash, schemaHash string
	var membershipEpoch, schemaVersion, lastCounter int64
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,last_origin_counter FROM replication_local_state`).Scan(&local, &domain, &membershipEpoch, &membershipHash, &schemaVersion, &schemaHash, &lastCounter); err != nil {
		return err
	}
	if lastCounter != 0 {
		return errors.New("replication: snapshot installation requires a node with no local-origin history")
	}
	document, err := validateSnapshotDocument(raw, manifest, expectedCreator, domain, membershipHash, schemaHash, membershipEpoch, schemaVersion)
	if err != nil {
		return err
	}
	descriptors := make([]replicationTableDescriptor, 0, len(document.Tables))
	for _, table := range document.Tables {
		descriptor, descriptorErr := r.descriptor(ctx, table.Name)
		if descriptorErr != nil {
			return descriptorErr
		}
		descriptors = append(descriptors, descriptor)
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Table.Name < descriptors[j].Table.Name })
	if err = validateSnapshotStructure(document, descriptors); err != nil {
		return err
	}
	cursorRaw, err := canonicalJSONMustMarshal(document.BaselineCursors)
	if err != nil {
		return err
	}
	cursorGzip, err := gzipSnapshotJSON(cursorRaw)
	if err != nil {
		return err
	}
	r.writer.Lock()
	defer r.writer.Unlock()
	storagePath, err := r.writeSnapshotFile(document.SnapshotUUID, raw)
	if err != nil {
		return err
	}
	err = r.withRemoteTransaction(ctx, func(tx *sql.Tx) error {
		var knownCreator int
		if queryErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_nodes WHERE node_uuid=?`, expectedCreator).Scan(&knownCreator); queryErr != nil || knownCreator != 1 {
			if queryErr != nil {
				return queryErr
			}
			return errors.New("replication: snapshot creator is not a domain member")
		}
		byTable := descriptorMap(descriptors)
		for _, descriptor := range descriptors {
			if _, deleteErr := tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(descriptor.Table.Name)); deleteErr != nil {
				return deleteErr
			}
			if _, deleteErr := tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(descriptor.DescriptorID+"__replication_changes")); deleteErr != nil {
				return deleteErr
			}
		}
		for _, statement := range []string{`DELETE FROM replication_change_acks`, `DELETE FROM replication_field_versions`, `DELETE FROM replication_row_versions`, `DELETE FROM replication_changes`} {
			if _, deleteErr := tx.ExecContext(ctx, statement); deleteErr != nil {
				return deleteErr
			}
		}
		if _, deleteErr := tx.ExecContext(ctx, `DELETE FROM replication_origin_gaps WHERE tracking_node_uuid=?`, local); deleteErr != nil {
			return deleteErr
		}
		for _, table := range document.Tables {
			descriptor := byTable[table.Name]
			columns := make([]string, len(descriptor.Table.Columns))
			marks := make([]string, len(columns))
			for i, column := range descriptor.Table.Columns {
				columns[i], marks[i] = quoteReplicationIdent(column), "?"
			}
			statement := `INSERT INTO ` + quoteReplicationIdent(table.Name) + `(` + strings.Join(columns, ",") + `) VALUES(` + strings.Join(marks, ",") + `)`
			for _, row := range table.Rows {
				args := make([]any, len(row.Values))
				for i, value := range row.Values {
					decoded, decodeErr := decodeWireValue(value.Value)
					if decodeErr != nil {
						return decodeErr
					}
					args[i] = decoded
				}
				if _, insertErr := tx.ExecContext(ctx, statement, args...); insertErr != nil {
					return insertErr
				}
			}
		}
		var maxPhysical, maxLogical int64
		for _, field := range document.FieldVersions {
			if _, ok := byTable[field.TableName]; !ok {
				return errors.New("replication: field version for unknown table")
			}
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO replication_field_versions VALUES(?,?,?,?,?,?,?,?,?,?)`, field.TableName, field.RowKeyJSON, field.FieldName, field.HLCPhysicalUS, field.HLCLogical, field.OriginNodeUUID, field.ChangeUUID, field.ChangedAtUTC, field.ValueHash, field.UpdatedAtUTC); insertErr != nil {
				return insertErr
			}
			if field.HLCPhysicalUS > maxPhysical || field.HLCPhysicalUS == maxPhysical && field.HLCLogical > maxLogical {
				maxPhysical, maxLogical = field.HLCPhysicalUS, field.HLCLogical
			}
		}
		for _, version := range document.RowVersions {
			if _, ok := byTable[version.TableName]; !ok || version.RowState != "live" && version.RowState != "deleted" && version.RowState != "unique_deleted" {
				return errors.New("replication: invalid row version")
			}
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?)`, version.TableName, version.RowKeyJSON, version.RowState, version.HLCPhysicalUS, version.HLCLogical, version.OriginNodeUUID, version.ChangeUUID, version.ChangedAtUTC, version.UpdatedAtUTC); insertErr != nil {
				return insertErr
			}
			if version.HLCPhysicalUS > maxPhysical || version.HLCPhysicalUS == maxPhysical && version.HLCLogical > maxLogical {
				maxPhysical, maxLogical = version.HLCPhysicalUS, version.HLCLogical
			}
		}
		if _, cursorErr := tx.ExecContext(ctx, `DELETE FROM replication_origin_cursors WHERE tracking_node_uuid=?`, local); cursorErr != nil {
			return cursorErr
		}
		now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
		for _, cursor := range document.BaselineCursors {
			var known int
			if cursorErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_nodes WHERE node_uuid=?`, cursor.OriginNodeUUID).Scan(&known); cursorErr != nil || known != 1 {
				if cursorErr != nil {
					return cursorErr
				}
				return errors.New("replication: snapshot cursor origin is not a domain member")
			}
			if _, cursorErr := tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?,?,?,0,?)`, local, cursor.OriginNodeUUID, cursor.ContiguousCounter, cursor.HighestSeenCounter, document.SnapshotUUID, now); cursorErr != nil {
				return cursorErr
			}
		}
		if _, updateErr := tx.ExecContext(ctx, `UPDATE replication_local_state SET last_hlc_physical_utc_us=max(last_hlc_physical_utc_us,?),last_hlc_logical=CASE WHEN ?>last_hlc_physical_utc_us THEN ? ELSE max(last_hlc_logical,?) END,blocked_reason=NULL,updated_at_utc=?`, maxPhysical, maxPhysical, maxLogical, maxLogical, now); updateErr != nil {
			return updateErr
		}
		if _, insertErr := tx.ExecContext(ctx, `INSERT INTO replication_snapshots(snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,baseline_cursors_gzip,baseline_cursors_uncompressed_bytes,content_hash,snapshot_auth_mode,content_size_bytes,snapshot_state,storage_uri,installed_by_node_uuid,created_at_utc,verified_at_utc,installed_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,'session',?,'installed',?,?,?,?,?) ON CONFLICT(snapshot_uuid) DO UPDATE SET snapshot_state='installed',storage_uri=excluded.storage_uri,installed_by_node_uuid=excluded.installed_by_node_uuid,verified_at_utc=excluded.verified_at_utc,installed_at_utc=excluded.installed_at_utc`, document.SnapshotUUID, document.CreatedByNodeUUID, document.ReplicationDomain, document.MembershipEpoch, document.MembershipManifestHash, document.SchemaVersion, document.SchemaHash, cursorGzip, len(cursorRaw), manifest.ContentHash, len(raw), storagePath, local, document.CreatedAtUTC, now, now); insertErr != nil {
			return insertErr
		}
		return nil
	})
	if err != nil {
		_ = os.Remove(storagePath)
	}
	return err
}

func isHexSnapshotHash(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func (manifest replicationSnapshotManifest) validate() error {
	if !isCanonicalUUID(manifest.SnapshotUUID) || !isCanonicalUUID(manifest.CreatedByNodeUUID) || manifest.ContentSizeBytes <= 0 || manifest.ContentSizeBytes > maximumReplicationSnapshotBytes || len(manifest.ContentHash) != 64 || manifest.ContentHash != strings.ToLower(manifest.ContentHash) || !isHexSnapshotHash(manifest.ContentHash) {
		return fmt.Errorf("replication: invalid snapshot manifest")
	}
	return nil
}
