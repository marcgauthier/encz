package sqliteseal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type replicationSnapshotVisitor interface {
	cursor(wireCursor) error
	fieldVersion(replicationSnapshotFieldVersion) error
	rowVersion(replicationSnapshotRowVersion) error
	startTable(string) error
	tableRow(string, replicationSnapshotRow) error
	endTable(string) error
}

type replicationSnapshotWalkResult struct {
	document    replicationSnapshotDocument
	maxPhysical int64
	maxLogical  int64
}

type replicationSnapshotCanonicalHash struct {
	hash hash.Hash
}

func newReplicationSnapshotCanonicalHash() *replicationSnapshotCanonicalHash {
	return &replicationSnapshotCanonicalHash{hash: sha256.New()}
}

func (h *replicationSnapshotCanonicalHash) write(value string) {
	_, _ = io.WriteString(h.hash, value)
}

func (h *replicationSnapshotCanonicalHash) writeRaw(raw []byte) error {
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return err
	}
	_, _ = h.hash.Write(canonical)
	return nil
}

func (h *replicationSnapshotCanonicalHash) sum() string {
	return hex.EncodeToString(h.hash.Sum(nil))
}

func decodeSnapshotRaw(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("replication: multiple snapshot JSON values")
		}
		return err
	}
	return nil
}

func snapshotToken(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != expected {
		return errors.New("replication: invalid snapshot structure")
	}
	return nil
}

func snapshotKey(decoder *json.Decoder, canonical *replicationSnapshotCanonicalHash, name string, first bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	key, ok := token.(string)
	if !ok || key != name {
		return errors.New("replication: invalid snapshot field order")
	}
	if !first {
		canonical.write(",")
	}
	encoded, _ := json.Marshal(name)
	_, _ = canonical.hash.Write(encoded)
	canonical.write(":")
	return nil
}

func snapshotScalar(decoder *json.Decoder, canonical *replicationSnapshotCanonicalHash, target any) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if err := canonical.writeRaw(raw); err != nil {
		return err
	}
	return decodeSnapshotRaw(raw, target)
}

func snapshotArray(decoder *json.Decoder, canonical *replicationSnapshotCanonicalHash, visit func(json.RawMessage) error) error {
	if err := snapshotToken(decoder, '['); err != nil {
		return err
	}
	canonical.write("[")
	first := true
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if !first {
			canonical.write(",")
		}
		first = false
		if err := canonical.writeRaw(raw); err != nil {
			return err
		}
		if err := visit(raw); err != nil {
			return err
		}
	}
	if err := snapshotToken(decoder, ']'); err != nil {
		return err
	}
	canonical.write("]")
	return nil
}

func walkSnapshotTables(decoder *json.Decoder, canonical *replicationSnapshotCanonicalHash, visitor replicationSnapshotVisitor) error {
	if err := snapshotToken(decoder, '['); err != nil {
		return err
	}
	canonical.write("[")
	firstTable := true
	for decoder.More() {
		if !firstTable {
			canonical.write(",")
		}
		firstTable = false
		if err := snapshotToken(decoder, '{'); err != nil {
			return err
		}
		canonical.write("{")
		if err := snapshotKey(decoder, canonical, "name", true); err != nil {
			return err
		}
		var tableName string
		if err := snapshotScalar(decoder, canonical, &tableName); err != nil {
			return err
		}
		if err := visitor.startTable(tableName); err != nil {
			return err
		}
		if err := snapshotKey(decoder, canonical, "rows", false); err != nil {
			return err
		}
		if err := snapshotArray(decoder, canonical, func(raw json.RawMessage) error {
			var row replicationSnapshotRow
			if err := decodeSnapshotRaw(raw, &row); err != nil {
				return err
			}
			return visitor.tableRow(tableName, row)
		}); err != nil {
			return err
		}
		if err := snapshotToken(decoder, '}'); err != nil {
			return err
		}
		canonical.write("}")
		if err := visitor.endTable(tableName); err != nil {
			return err
		}
	}
	if err := snapshotToken(decoder, ']'); err != nil {
		return err
	}
	canonical.write("]")
	return nil
}

func walkReplicationSnapshot(path string, manifest replicationSnapshotManifest, maximumBytes int64, visitor replicationSnapshotVisitor) (replicationSnapshotWalkResult, error) {
	var result replicationSnapshotWalkResult
	if err := manifest.validate(maximumBytes); err != nil {
		return result, err
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return result, err
	}
	if info.Size() != manifest.ContentSizeBytes || info.Size() <= 0 || info.Size() > maximumBytes {
		return result, errors.New("replication: snapshot content size failure")
	}
	rawHash := sha256.New()
	decoder := json.NewDecoder(bufio.NewReader(io.TeeReader(file, rawHash)))
	decoder.UseNumber()
	canonical := newReplicationSnapshotCanonicalHash()
	if err = snapshotToken(decoder, '{'); err != nil {
		return result, err
	}
	canonical.write("{")
	if err = snapshotKey(decoder, canonical, "baseline_cursors", true); err != nil {
		return result, err
	}
	if err = snapshotArray(decoder, canonical, func(raw json.RawMessage) error {
		var cursor wireCursor
		if decodeErr := decodeSnapshotRaw(raw, &cursor); decodeErr != nil {
			return decodeErr
		}
		result.document.BaselineCursors = append(result.document.BaselineCursors, cursor)
		return visitor.cursor(cursor)
	}); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "created_at_utc", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.CreatedAtUTC); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "created_by_node_uuid", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.CreatedByNodeUUID); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "field_versions", false); err != nil {
		return result, err
	}
	if err = snapshotArray(decoder, canonical, func(raw json.RawMessage) error {
		var field replicationSnapshotFieldVersion
		if decodeErr := decodeSnapshotRaw(raw, &field); decodeErr != nil {
			return decodeErr
		}
		if field.HLCPhysicalUS > result.maxPhysical || field.HLCPhysicalUS == result.maxPhysical && field.HLCLogical > result.maxLogical {
			result.maxPhysical, result.maxLogical = field.HLCPhysicalUS, field.HLCLogical
		}
		return visitor.fieldVersion(field)
	}); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "format_version", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.FormatVersion); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "membership_epoch", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.MembershipEpoch); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "membership_manifest_hash", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.MembershipManifestHash); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "replication_domain", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.ReplicationDomain); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "row_versions", false); err != nil {
		return result, err
	}
	if err = snapshotArray(decoder, canonical, func(raw json.RawMessage) error {
		var version replicationSnapshotRowVersion
		if decodeErr := decodeSnapshotRaw(raw, &version); decodeErr != nil {
			return decodeErr
		}
		if version.HLCPhysicalUS > result.maxPhysical || version.HLCPhysicalUS == result.maxPhysical && version.HLCLogical > result.maxLogical {
			result.maxPhysical, result.maxLogical = version.HLCPhysicalUS, version.HLCLogical
		}
		return visitor.rowVersion(version)
	}); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "schema_hash", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.SchemaHash); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "schema_version", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.SchemaVersion); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "snapshot_uuid", false); err != nil {
		return result, err
	}
	if err = snapshotScalar(decoder, canonical, &result.document.SnapshotUUID); err != nil {
		return result, err
	}
	if err = snapshotKey(decoder, canonical, "tables", false); err != nil {
		return result, err
	}
	if err = walkSnapshotTables(decoder, canonical, visitor); err != nil {
		return result, err
	}
	if err = snapshotToken(decoder, '}'); err != nil {
		return result, err
	}
	canonical.write("}")
	if err = decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			err = errors.New("replication: trailing snapshot JSON value")
		}
		return result, err
	}
	rawContentHash := hex.EncodeToString(rawHash.Sum(nil))
	if rawContentHash != manifest.ContentHash {
		return result, errors.New("replication: snapshot content integrity failure")
	}
	if canonical.sum() != rawContentHash {
		return result, errors.New("replication: non-canonical snapshot")
	}
	return result, nil
}

type replicationSnapshotValidationVisitor struct {
	descriptors map[string]replicationTableDescriptor
	columns     map[string]map[string]bool
	origins     map[string]bool
	tables      map[string]bool
	current     string
}

func newReplicationSnapshotValidationVisitor(descriptors []replicationTableDescriptor) *replicationSnapshotValidationVisitor {
	visitor := &replicationSnapshotValidationVisitor{descriptors: descriptorMap(descriptors), columns: make(map[string]map[string]bool), origins: make(map[string]bool), tables: make(map[string]bool)}
	for _, descriptor := range descriptors {
		columns := make(map[string]bool, len(descriptor.Table.Columns))
		for _, column := range descriptor.Table.Columns {
			columns[column] = true
		}
		visitor.columns[descriptor.Table.Name] = columns
	}
	return visitor
}

func (v *replicationSnapshotValidationVisitor) cursor(cursor wireCursor) error {
	if !isCanonicalUUID(cursor.OriginNodeUUID) || cursor.ContiguousCounter < 0 || cursor.HighestSeenCounter != cursor.ContiguousCounter || cursor.RequiresSnapshot || v.origins[cursor.OriginNodeUUID] {
		return errors.New("replication: invalid snapshot cursor vector")
	}
	v.origins[cursor.OriginNodeUUID] = true
	return nil
}

func (v *replicationSnapshotValidationVisitor) fieldVersion(field replicationSnapshotFieldVersion) error {
	canonicalKey, err := canonicalJSON([]byte(field.RowKeyJSON))
	if err != nil || string(canonicalKey) != field.RowKeyJSON || !v.columns[field.TableName][field.FieldName] || field.HLCPhysicalUS <= 0 || field.HLCLogical < 0 || !isCanonicalUUID(field.OriginNodeUUID) || !isCanonicalUUID(field.ChangeUUID) {
		return errors.New("replication: invalid snapshot field version")
	}
	return nil
}

func (v *replicationSnapshotValidationVisitor) rowVersion(version replicationSnapshotRowVersion) error {
	canonicalKey, err := canonicalJSON([]byte(version.RowKeyJSON))
	_, known := v.descriptors[version.TableName]
	if err != nil || string(canonicalKey) != version.RowKeyJSON || !known || version.RowState != "live" && version.RowState != "deleted" && version.RowState != "unique_deleted" || version.HLCPhysicalUS <= 0 || version.HLCLogical < 0 || !isCanonicalUUID(version.OriginNodeUUID) || !isCanonicalUUID(version.ChangeUUID) {
		return errors.New("replication: invalid snapshot row version")
	}
	return nil
}

func (v *replicationSnapshotValidationVisitor) startTable(table string) error {
	if _, ok := v.descriptors[table]; !ok || v.tables[table] {
		return errors.New("replication: invalid snapshot table")
	}
	v.tables[table], v.current = true, table
	return nil
}

func (v *replicationSnapshotValidationVisitor) tableRow(table string, row replicationSnapshotRow) error {
	descriptor, ok := v.descriptors[table]
	if !ok || table != v.current || len(row.Values) != len(descriptor.Table.Columns) {
		return errors.New("replication: incomplete snapshot row")
	}
	for index, value := range row.Values {
		if value.Name != descriptor.Table.Columns[index] || !value.Value.Present {
			return errors.New("replication: invalid snapshot column")
		}
		if _, err := decodeWireValue(value.Value); err != nil {
			return err
		}
	}
	return nil
}

func (v *replicationSnapshotValidationVisitor) endTable(table string) error {
	if table != v.current {
		return errors.New("replication: invalid snapshot table")
	}
	v.current = ""
	return nil
}

func (v *replicationSnapshotValidationVisitor) complete() error {
	if v.current != "" || len(v.tables) != len(v.descriptors) {
		return errors.New("replication: incomplete snapshot table set")
	}
	return nil
}

type replicationSnapshotInstallVisitor struct {
	ctx         context.Context
	tx          *sql.Tx
	descriptors map[string]replicationTableDescriptor
	statement   *sql.Stmt
	table       string
}

func (v *replicationSnapshotInstallVisitor) cursor(wireCursor) error { return nil }

func (v *replicationSnapshotInstallVisitor) fieldVersion(field replicationSnapshotFieldVersion) error {
	_, err := v.tx.ExecContext(v.ctx, `INSERT INTO replication_field_versions VALUES(?,?,?,?,?,?,?,?,?,?)`, field.TableName, field.RowKeyJSON, field.FieldName, field.HLCPhysicalUS, field.HLCLogical, field.OriginNodeUUID, field.ChangeUUID, field.ChangedAtUTC, field.ValueHash, field.UpdatedAtUTC)
	return err
}

func (v *replicationSnapshotInstallVisitor) rowVersion(version replicationSnapshotRowVersion) error {
	_, err := v.tx.ExecContext(v.ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?)`, version.TableName, version.RowKeyJSON, version.RowState, version.HLCPhysicalUS, version.HLCLogical, version.OriginNodeUUID, version.ChangeUUID, version.ChangedAtUTC, version.UpdatedAtUTC)
	return err
}

func (v *replicationSnapshotInstallVisitor) startTable(table string) error {
	descriptor := v.descriptors[table]
	columns := make([]string, len(descriptor.Table.Columns))
	marks := make([]string, len(columns))
	for index, column := range descriptor.Table.Columns {
		columns[index], marks[index] = quoteReplicationIdent(column), "?"
	}
	statement := `INSERT INTO ` + quoteReplicationIdent(table) + `(` + strings.Join(columns, ",") + `) VALUES(` + strings.Join(marks, ",") + `)`
	prepared, err := v.tx.PrepareContext(v.ctx, statement)
	if err != nil {
		return err
	}
	v.statement, v.table = prepared, table
	return nil
}

func (v *replicationSnapshotInstallVisitor) tableRow(table string, row replicationSnapshotRow) error {
	if table != v.table || v.statement == nil {
		return errors.New("replication: invalid snapshot table stream")
	}
	args := make([]any, len(row.Values))
	for index, value := range row.Values {
		decoded, err := decodeWireValue(value.Value)
		if err != nil {
			return err
		}
		args[index] = decoded
	}
	_, err := v.statement.ExecContext(v.ctx, args...)
	return err
}

func (v *replicationSnapshotInstallVisitor) endTable(table string) error {
	if table != v.table || v.statement == nil {
		return errors.New("replication: invalid snapshot table stream")
	}
	err := v.statement.Close()
	v.statement, v.table = nil, ""
	return err
}

func validateSnapshotHeader(document replicationSnapshotDocument, manifest replicationSnapshotManifest, expectedCreator, domain, membershipHash, schemaHash string, membershipEpoch, schemaVersion int64) error {
	if document.FormatVersion != replicationSnapshotFormatVersion || !isCanonicalUUID(document.SnapshotUUID) || document.SnapshotUUID != manifest.SnapshotUUID || document.CreatedByNodeUUID != expectedCreator || document.CreatedByNodeUUID != manifest.CreatedByNodeUUID {
		return errors.New("replication: invalid snapshot identity")
	}
	if document.ReplicationDomain != domain || document.ReplicationDomain != manifest.ReplicationDomain || document.MembershipEpoch != membershipEpoch || document.MembershipEpoch != manifest.MembershipEpoch || document.MembershipManifestHash != membershipHash || document.MembershipManifestHash != manifest.MembershipManifestHash || document.SchemaVersion != manifest.SchemaVersion || document.SchemaHash != schemaHash || document.SchemaHash != manifest.SchemaHash || document.CreatedAtUTC != manifest.CreatedAtUTC {
		return ErrReplicationSchemaMismatch
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000Z", document.CreatedAtUTC); err != nil {
		return errors.New("replication: invalid snapshot timestamp")
	}
	return nil
}

func (r *replicationRuntime) installSessionSnapshotFile(ctx context.Context, expectedCreator string, manifest replicationSnapshotManifest, temporaryPath string, maximumBytes int64) error {
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	var local, domain, membershipHash, schemaHash string
	var membershipEpoch, schemaVersion, lastCounter int64
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,last_origin_counter FROM replication_local_state`).Scan(&local, &domain, &membershipEpoch, &membershipHash, &schemaVersion, &schemaHash, &lastCounter); err != nil {
		return err
	}
	if lastCounter != 0 {
		return errors.New("replication: snapshot installation requires a node with no local-origin history")
	}
	descriptors, err := snapshotDescriptorsFromDB(ctx, r.db)
	if err != nil {
		return err
	}
	validator := newReplicationSnapshotValidationVisitor(descriptors)
	result, err := walkReplicationSnapshot(temporaryPath, manifest, maximumBytes, validator)
	if err != nil {
		return err
	}
	if err = validator.complete(); err != nil {
		return err
	}
	if err = validateSnapshotHeader(result.document, manifest, expectedCreator, domain, membershipHash, schemaHash, membershipEpoch, schemaVersion); err != nil {
		return err
	}
	cursorRaw, err := canonicalJSONMustMarshal(result.document.BaselineCursors)
	if err != nil {
		return err
	}
	var cursorOutput bytes.Buffer
	cursorWriter := gzip.NewWriter(&cursorOutput)
	if _, err = cursorWriter.Write(cursorRaw); err != nil {
		return err
	}
	if err = cursorWriter.Close(); err != nil {
		return err
	}
	finalPath, err := r.snapshotFinalPath(manifest.SnapshotUUID)
	if err != nil {
		return err
	}
	r.writer.Lock()
	defer r.writer.Unlock()
	moved := false
	err = r.withRemoteTransaction(ctx, func(tx *sql.Tx) error {
		var knownCreator int
		if queryErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_nodes WHERE node_uuid=?`, expectedCreator).Scan(&knownCreator); queryErr != nil || knownCreator != 1 {
			if queryErr != nil {
				return queryErr
			}
			return errors.New("replication: snapshot creator is not a domain member")
		}
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
		installer := &replicationSnapshotInstallVisitor{ctx: ctx, tx: tx, descriptors: descriptorMap(descriptors)}
		if _, walkErr := walkReplicationSnapshot(temporaryPath, manifest, maximumBytes, installer); walkErr != nil {
			if installer.statement != nil {
				_ = installer.statement.Close()
			}
			return walkErr
		}
		if _, cursorErr := tx.ExecContext(ctx, `DELETE FROM replication_origin_cursors WHERE tracking_node_uuid=?`, local); cursorErr != nil {
			return cursorErr
		}
		now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
		for _, cursor := range result.document.BaselineCursors {
			var known int
			if cursorErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_nodes WHERE node_uuid=?`, cursor.OriginNodeUUID).Scan(&known); cursorErr != nil || known != 1 {
				if cursorErr != nil {
					return cursorErr
				}
				return errors.New("replication: snapshot cursor origin is not a domain member")
			}
			if _, cursorErr := tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?,?,?,0,?)`, local, cursor.OriginNodeUUID, cursor.ContiguousCounter, cursor.HighestSeenCounter, manifest.SnapshotUUID, now); cursorErr != nil {
				return cursorErr
			}
		}
		if _, updateErr := tx.ExecContext(ctx, `UPDATE replication_local_state SET last_hlc_physical_utc_us=max(last_hlc_physical_utc_us,?),last_hlc_logical=CASE WHEN ?>last_hlc_physical_utc_us THEN ? ELSE max(last_hlc_logical,?) END,blocked_reason=NULL,updated_at_utc=?`, result.maxPhysical, result.maxPhysical, result.maxLogical, result.maxLogical, now); updateErr != nil {
			return updateErr
		}
		if existing, statErr := os.Stat(finalPath); statErr == nil {
			if existing.Size() != manifest.ContentSizeBytes {
				return errors.New("replication: conflicting installed snapshot file")
			}
			size, contentHash, hashErr := snapshotFileHash(finalPath, maximumBytes)
			if hashErr != nil || size != manifest.ContentSizeBytes || contentHash != manifest.ContentHash {
				return errors.New("replication: conflicting installed snapshot file")
			}
			if removeErr := os.Remove(temporaryPath); removeErr != nil {
				return removeErr
			}
			removeTemporary = false
		} else if !os.IsNotExist(statErr) {
			return statErr
		} else {
			if renameErr := os.Rename(temporaryPath, finalPath); renameErr != nil {
				return renameErr
			}
			moved = true
			removeTemporary = false
		}
		if _, insertErr := tx.ExecContext(ctx, `INSERT INTO replication_snapshots(snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,baseline_cursors_gzip,baseline_cursors_uncompressed_bytes,content_hash,snapshot_auth_mode,content_size_bytes,snapshot_state,storage_uri,installed_by_node_uuid,created_at_utc,verified_at_utc,installed_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,'session',?,'installed',?,?,?,?,?) ON CONFLICT(snapshot_uuid) DO UPDATE SET snapshot_state='installed',storage_uri=excluded.storage_uri,installed_by_node_uuid=excluded.installed_by_node_uuid,verified_at_utc=excluded.verified_at_utc,installed_at_utc=excluded.installed_at_utc`, manifest.SnapshotUUID, manifest.CreatedByNodeUUID, manifest.ReplicationDomain, manifest.MembershipEpoch, manifest.MembershipManifestHash, manifest.SchemaVersion, manifest.SchemaHash, cursorOutput.Bytes(), len(cursorRaw), manifest.ContentHash, manifest.ContentSizeBytes, finalPath, local, manifest.CreatedAtUTC, now, now); insertErr != nil {
			return insertErr
		}
		return nil
	})
	if err != nil && moved {
		_ = os.Remove(finalPath)
	}
	return err
}

func snapshotDescriptorsFromDB(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]replicationTableDescriptor, error) {
	rows, err := db.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
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
	if err = rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Table.Name < descriptors[j].Table.Name })
	return descriptors, nil
}
