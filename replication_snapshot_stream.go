package sqliteseal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultMaximumReplicationSnapshotBytes int64 = 256 << 20

type replicationSnapshotFile struct {
	Manifest replicationSnapshotManifest
	Path     string
}

type replicationSnapshotStreamWriter struct {
	writer io.Writer
	hash   hash.Hash
	size   int64
	limit  int64
}

func newReplicationSnapshotStreamWriter(writer io.Writer, limit int64) *replicationSnapshotStreamWriter {
	return &replicationSnapshotStreamWriter{writer: writer, hash: sha256.New(), limit: limit}
}

func (w *replicationSnapshotStreamWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.limit-w.size {
		return 0, errors.New("replication: snapshot exceeds size limit")
	}
	n, err := w.writer.Write(data)
	if n > 0 {
		_, _ = w.hash.Write(data[:n])
		w.size += int64(n)
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *replicationSnapshotStreamWriter) contentHash() string {
	return hex.EncodeToString(w.hash.Sum(nil))
}

func writeSnapshotCanonicalValue(writer io.Writer, value any) error {
	raw, err := canonicalJSONMustMarshal(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(raw)
	return err
}

func writeSnapshotArrayValue(writer io.Writer, first *bool, value any) error {
	if !*first {
		if _, err := io.WriteString(writer, ","); err != nil {
			return err
		}
	}
	*first = false
	return writeSnapshotCanonicalValue(writer, value)
}

func writeSnapshotFieldVersionStream(ctx context.Context, tx *sql.Tx, writer io.Writer) error {
	rows, err := tx.QueryContext(ctx, `SELECT table_name,row_key_json,field_name,winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,winner_change_uuid,winner_changed_at_utc,value_hash,updated_at_utc FROM replication_field_versions ORDER BY table_name,row_key_json,field_name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var field replicationSnapshotFieldVersion
		var valueHash sql.NullString
		if err = rows.Scan(&field.TableName, &field.RowKeyJSON, &field.FieldName, &field.HLCPhysicalUS, &field.HLCLogical, &field.OriginNodeUUID, &field.ChangeUUID, &field.ChangedAtUTC, &valueHash, &field.UpdatedAtUTC); err != nil {
			return err
		}
		if valueHash.Valid {
			value := valueHash.String
			field.ValueHash = &value
		}
		if err = writeSnapshotArrayValue(writer, &first, field); err != nil {
			return err
		}
	}
	return rows.Err()
}

func writeSnapshotRowVersionStream(ctx context.Context, tx *sql.Tx, writer io.Writer) error {
	rows, err := tx.QueryContext(ctx, `SELECT table_name,row_key_json,row_state,winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,winner_change_uuid,winner_changed_at_utc,updated_at_utc FROM replication_row_versions ORDER BY table_name,row_key_json`)
	if err != nil {
		return err
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var version replicationSnapshotRowVersion
		if err = rows.Scan(&version.TableName, &version.RowKeyJSON, &version.RowState, &version.HLCPhysicalUS, &version.HLCLogical, &version.OriginNodeUUID, &version.ChangeUUID, &version.ChangedAtUTC, &version.UpdatedAtUTC); err != nil {
			return err
		}
		if err = writeSnapshotArrayValue(writer, &first, version); err != nil {
			return err
		}
	}
	return rows.Err()
}

func writeSnapshotTableStream(ctx context.Context, tx *sql.Tx, writer io.Writer, descriptors []replicationTableDescriptor) error {
	for tableIndex, descriptor := range descriptors {
		if tableIndex > 0 {
			if _, err := io.WriteString(writer, ","); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(writer, `{"name":`); err != nil {
			return err
		}
		if err := writeSnapshotCanonicalValue(writer, descriptor.Table.Name); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, `,"rows":[`); err != nil {
			return err
		}
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
			return err
		}
		first := true
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(values))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err = rows.Scan(pointers...); err != nil {
				_ = rows.Close()
				return err
			}
			row := replicationSnapshotRow{Values: make([]replicationSnapshotValue, len(values))}
			for index, value := range values {
				row.Values[index] = replicationSnapshotValue{Name: descriptor.Table.Columns[index], Value: encodeWireValue(value, true)}
			}
			if err = writeSnapshotArrayValue(writer, &first, row); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if _, err = io.WriteString(writer, `]}`); err != nil {
			return err
		}
	}
	return nil
}

func writeCanonicalReplicationSnapshot(ctx context.Context, tx *sql.Tx, writer io.Writer, document replicationSnapshotDocument, descriptors []replicationTableDescriptor) error {
	if _, err := io.WriteString(writer, `{"baseline_cursors":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.BaselineCursors); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"created_at_utc":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.CreatedAtUTC); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"created_by_node_uuid":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.CreatedByNodeUUID); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"field_versions":[`); err != nil {
		return err
	}
	if err := writeSnapshotFieldVersionStream(ctx, tx, writer); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `],"format_version":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.FormatVersion); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"membership_epoch":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.MembershipEpoch); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"membership_manifest_hash":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.MembershipManifestHash); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"replication_domain":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.ReplicationDomain); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"row_versions":[`); err != nil {
		return err
	}
	if err := writeSnapshotRowVersionStream(ctx, tx, writer); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `],"schema_hash":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.SchemaHash); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"schema_version":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.SchemaVersion); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"snapshot_uuid":`); err != nil {
		return err
	}
	if err := writeSnapshotCanonicalValue(writer, document.SnapshotUUID); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, `,"tables":[`); err != nil {
		return err
	}
	if err := writeSnapshotTableStream(ctx, tx, writer, descriptors); err != nil {
		return err
	}
	_, err := io.WriteString(writer, `]}`)
	return err
}

func (r *replicationRuntime) snapshotDirectory() (string, error) {
	directory := r.db.path + ".replication-snapshots"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	return directory, nil
}

func (r *replicationRuntime) createSnapshotTemporaryFile(snapshotUUID string) (*os.File, string, error) {
	directory, err := r.snapshotDirectory()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(directory, "."+snapshotUUID+"-*.tmp")
	file, err := os.CreateTemp(directory, filepath.Base(path))
	if err != nil {
		return nil, "", err
	}
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, "", err
	}
	return file, file.Name(), nil
}

func (r *replicationRuntime) snapshotFinalPath(snapshotUUID string) (string, error) {
	directory, err := r.snapshotDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, snapshotUUID+".json"), nil
}

func (db *DB) CreateReplicationSnapshot(ctx context.Context) (ReplicationSnapshotInfo, error) {
	return db.createReplicationSnapshot(ctx, defaultMaximumReplicationSnapshotBytes)
}

func (db *DB) createReplicationSnapshot(ctx context.Context, maximumBytes int64) (ReplicationSnapshotInfo, error) {
	var info ReplicationSnapshotInfo
	if db.replication == nil {
		return info, ErrReplicationNotInitialized
	}
	if maximumBytes <= 0 {
		return info, ErrReplicationInvalidConfig
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
	cursorRaw, err := canonicalJSONMustMarshal(document.BaselineCursors)
	if err != nil {
		return info, err
	}
	cursorGzip, err := gzipSnapshotJSON(cursorRaw)
	if err != nil {
		return info, err
	}
	file, temporaryPath, err := r.createSnapshotTemporaryFile(document.SnapshotUUID)
	if err != nil {
		return info, err
	}
	keepTemporary := false
	defer func() {
		_ = file.Close()
		if !keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	stream := newReplicationSnapshotStreamWriter(file, maximumBytes)
	if err = writeCanonicalReplicationSnapshot(ctx, tx, stream, document, descriptors); err != nil {
		return info, err
	}
	if err = file.Sync(); err != nil {
		return info, err
	}
	if err = file.Close(); err != nil {
		return info, err
	}
	if err = tx.Commit(); err != nil {
		return info, err
	}
	storagePath, err := r.snapshotFinalPath(document.SnapshotUUID)
	if err != nil {
		return info, err
	}
	if err = os.Rename(temporaryPath, storagePath); err != nil {
		return info, err
	}
	keepTemporary = true
	contentHash := stream.contentHash()
	_, err = db.ExecContext(ctx, `INSERT INTO replication_snapshots(snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,baseline_cursors_gzip,baseline_cursors_uncompressed_bytes,content_hash,snapshot_auth_mode,content_size_bytes,snapshot_state,storage_uri,created_at_utc,verified_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,'session',?,'ready',?,?,?)`, document.SnapshotUUID, document.CreatedByNodeUUID, document.ReplicationDomain, document.MembershipEpoch, document.MembershipManifestHash, document.SchemaVersion, document.SchemaHash, cursorGzip, len(cursorRaw), contentHash, stream.size, storagePath, document.CreatedAtUTC, document.CreatedAtUTC)
	if err != nil {
		_ = os.Remove(storagePath)
		return info, err
	}
	created, _ := time.Parse("2006-01-02T15:04:05.000000Z", document.CreatedAtUTC)
	return ReplicationSnapshotInfo{SnapshotUUID: document.SnapshotUUID, SchemaHash: document.SchemaHash, ContentHash: contentHash, CreatedAt: created, SizeBytes: stream.size}, nil
}

func snapshotFileHash(path string, maximumBytes int64) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if info.Size() <= 0 || info.Size() > maximumBytes {
		return 0, "", errors.New("replication: stored snapshot size failure")
	}
	hasher := sha256.New()
	buffer := make([]byte, replicationSnapshotChunkBytes)
	written, err := io.CopyBuffer(hasher, file, buffer)
	if err != nil {
		return 0, "", err
	}
	return written, hex.EncodeToString(hasher.Sum(nil)), nil
}

func (r *replicationRuntime) snapshotByUUIDFile(ctx context.Context, snapshotUUID string, maximumBytes int64) (replicationSnapshotFile, error) {
	var snapshot replicationSnapshotFile
	err := r.db.QueryRowContext(ctx, `SELECT snapshot_uuid,created_by_node_uuid,replication_domain,membership_epoch,membership_manifest_hash,schema_version,schema_hash,content_hash,content_size_bytes,created_at_utc,storage_uri FROM replication_snapshots WHERE snapshot_uuid=? AND snapshot_state IN('ready','installed')`, snapshotUUID).Scan(&snapshot.Manifest.SnapshotUUID, &snapshot.Manifest.CreatedByNodeUUID, &snapshot.Manifest.ReplicationDomain, &snapshot.Manifest.MembershipEpoch, &snapshot.Manifest.MembershipManifestHash, &snapshot.Manifest.SchemaVersion, &snapshot.Manifest.SchemaHash, &snapshot.Manifest.ContentHash, &snapshot.Manifest.ContentSizeBytes, &snapshot.Manifest.CreatedAtUTC, &snapshot.Path)
	if err != nil {
		return snapshot, err
	}
	if err = snapshot.Manifest.validate(maximumBytes); err != nil {
		return snapshot, err
	}
	size, contentHash, err := snapshotFileHash(snapshot.Path, maximumBytes)
	if err != nil {
		return snapshot, err
	}
	if size != snapshot.Manifest.ContentSizeBytes || contentHash != snapshot.Manifest.ContentHash {
		return snapshot, errors.New("replication: stored snapshot integrity failure")
	}
	return snapshot, nil
}

func (r *replicationRuntime) latestSnapshotFile(ctx context.Context, maximumBytes int64) (replicationSnapshotFile, error) {
	var snapshotUUID string
	err := r.db.QueryRowContext(ctx, `SELECT snapshot_uuid FROM replication_snapshots WHERE snapshot_state IN('ready','installed') AND content_size_bytes<=? ORDER BY created_at_utc DESC LIMIT 1`, maximumBytes).Scan(&snapshotUUID)
	if err == sql.ErrNoRows {
		info, createErr := r.db.createReplicationSnapshot(ctx, maximumBytes)
		if createErr != nil {
			return replicationSnapshotFile{}, createErr
		}
		snapshotUUID = info.SnapshotUUID
	} else if err != nil {
		return replicationSnapshotFile{}, err
	}
	return r.snapshotByUUIDFile(ctx, snapshotUUID, maximumBytes)
}

func (r *replicationRuntime) createTransferSnapshotFile(ctx context.Context, maximumBytes int64) (replicationSnapshotFile, error) {
	info, err := r.db.createReplicationSnapshot(ctx, maximumBytes)
	if err != nil {
		return replicationSnapshotFile{}, err
	}
	return r.snapshotByUUIDFile(ctx, info.SnapshotUUID, maximumBytes)
}
