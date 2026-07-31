package sqliteseal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	replicationSnapshotFormatVersion = 1
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

func canonicalJSONMustMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

func descriptorMap(descriptors []replicationTableDescriptor) map[string]replicationTableDescriptor {
	result := make(map[string]replicationTableDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		result[descriptor.Table.Name] = descriptor
	}
	return result
}

func isHexSnapshotHash(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func (manifest replicationSnapshotManifest) validate(maximumBytes int64) error {
	if !isCanonicalUUID(manifest.SnapshotUUID) || !isCanonicalUUID(manifest.CreatedByNodeUUID) || manifest.ContentSizeBytes <= 0 || manifest.ContentSizeBytes > maximumBytes || len(manifest.ContentHash) != 64 || manifest.ContentHash != strings.ToLower(manifest.ContentHash) || !isHexSnapshotHash(manifest.ContentHash) {
		return fmt.Errorf("replication: invalid snapshot manifest")
	}
	return nil
}
