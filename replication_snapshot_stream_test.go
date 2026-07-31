package sqliteseal

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func copySnapshotForInstall(t *testing.T, target *DB, snapshot replicationSnapshotFile) string {
	t.Helper()
	source, err := os.Open(snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, path, err := target.replication.createSnapshotTemporaryFile(snapshot.Manifest.SnapshotUUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.CopyBuffer(destination, source, make([]byte, replicationSnapshotChunkBytes)); err != nil {
		_ = destination.Close()
		_ = os.Remove(path)
		t.Fatal(err)
	}
	if err = destination.Close(); err != nil {
		_ = os.Remove(path)
		t.Fatal(err)
	}
	return path
}

func TestStreamingSnapshotPreservesCanonicalV1Bytes(t *testing.T) {
	ctx, source, _, _ := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('canonical','value','note')`); err != nil {
		t.Fatal(err)
	}
	info, err := source.CreateReplicationSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.replication.snapshotByUUIDFile(ctx, info.SnapshotUUID, defaultMaximumReplicationSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	var document replicationSnapshotDocument
	if err = jsonUnmarshalSnapshot(raw, &document); err != nil {
		t.Fatal(err)
	}
	legacy, err := canonicalSnapshotBytes(document)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, legacy) || snapshotHash(raw) != info.ContentHash {
		t.Fatal("streamed snapshot differs from canonical format v1")
	}
}

func jsonUnmarshalSnapshot(raw []byte, document *replicationSnapshotDocument) error {
	return decodeSnapshotRaw(raw, document)
}

func TestStreamingSnapshotLimitConfiguration(t *testing.T) {
	db := openReconnectTestDB(t, filepath.Join(t.TempDir(), "limit.db"))
	defer db.Close()
	var defaults PeerConfig
	defaultsPeer(&defaults)
	if defaults.MaxSnapshotBytes != defaultMaximumReplicationSnapshotBytes {
		t.Fatalf("default max snapshot bytes=%d", defaults.MaxSnapshotBytes)
	}
	peer := PeerConfig{
		NodeUUID: "00000000-0000-4000-8000-000000000701", IncarnationUUID: "00000000-0000-4000-8000-000000000702",
		NodeName: "large-snapshot-peer", Address: "127.0.0.1:1", Role: ReplicationAccept, AuthMode: ReplicationAuthPSK,
		MaxSnapshotBytes: 2 << 30,
	}
	if err := db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	config, err := db.replication.loadPeerRuntimeConfig(t.Context(), peer.NodeUUID)
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxSnapshotBytes != peer.MaxSnapshotBytes {
		t.Fatalf("persisted max snapshot bytes=%d", config.MaxSnapshotBytes)
	}
	peer.MaxSnapshotBytes = -1
	if err = db.UpsertReplicationPeer(t.Context(), peer); !errors.Is(err, ErrReplicationInvalidConfig) {
		t.Fatalf("negative snapshot limit error=%v", err)
	}
}

func TestStreamingSnapshotCreationLimitCleansTemporaryFile(t *testing.T) {
	ctx, source, _, _ := setupEventValidationNodes(t)
	if _, err := source.Exec(`INSERT INTO items VALUES('large','value','note')`); err != nil {
		t.Fatal(err)
	}
	if _, err := source.createReplicationSnapshot(ctx, 1); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("small limit error=%v", err)
	}
	matches, err := filepath.Glob(source.path + ".replication-snapshots/.*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("snapshot temporary files remain: %v", matches)
	}
	var count int
	if err = source.QueryRow(`SELECT count(*) FROM replication_snapshots`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("snapshot metadata count=%d err=%v", count, err)
	}
}

func TestStreamingSnapshotRejectsNonCanonicalFile(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	prepareSnapshotDestination(t, ctx, source, target, sourceID)
	if _, err := source.Exec(`INSERT INTO items VALUES('one','value','note')`); err != nil {
		t.Fatal(err)
	}
	info, err := source.CreateReplicationSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.replication.snapshotByUUIDFile(ctx, info.SnapshotUUID, defaultMaximumReplicationSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	hash := sha256.Sum256(raw)
	snapshot.Manifest.ContentHash = hex.EncodeToString(hash[:])
	snapshot.Manifest.ContentSizeBytes = int64(len(raw))
	temporary, path, err := target.replication.createSnapshotTemporaryFile(snapshot.Manifest.SnapshotUUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = temporary.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = temporary.Close(); err != nil {
		t.Fatal(err)
	}
	err = target.replication.installSessionSnapshotFile(ctx, sourceID, snapshot.Manifest, path, defaultMaximumReplicationSnapshotBytes)
	if err == nil || !strings.Contains(err.Error(), "non-canonical") {
		t.Fatalf("non-canonical snapshot error=%v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("rejected temporary snapshot remains: %v", statErr)
	}
}

func TestStreamingSnapshotInstallRollsBackLateSQLFailure(t *testing.T) {
	ctx, source, target, sourceID := setupEventValidationNodes(t)
	prepareSnapshotDestination(t, ctx, source, target, sourceID)
	if _, err := source.Exec(`INSERT INTO items VALUES('blocked','source','note')`); err != nil {
		t.Fatal(err)
	}
	if err := target.replication.withRemoteTransaction(ctx, func(tx *sql.Tx) error {
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO items VALUES('sentinel','target','preserve')`)
		return insertErr
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Exec(`CREATE TRIGGER reject_snapshot_row BEFORE INSERT ON items WHEN NEW.id='blocked' BEGIN SELECT RAISE(ABORT,'blocked by test'); END`); err != nil {
		t.Fatal(err)
	}
	info, err := source.CreateReplicationSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.replication.snapshotByUUIDFile(ctx, info.SnapshotUUID, defaultMaximumReplicationSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	path := copySnapshotForInstall(t, target, snapshot)
	if err = target.replication.installSessionSnapshotFile(ctx, sourceID, snapshot.Manifest, path, defaultMaximumReplicationSnapshotBytes); err == nil {
		t.Fatal("snapshot install unexpectedly ignored SQL failure")
	}
	var sentinel, blocked int
	if err = target.QueryRow(`SELECT count(*) FROM items WHERE id='sentinel'`).Scan(&sentinel); err != nil {
		t.Fatal(err)
	}
	if err = target.QueryRow(`SELECT count(*) FROM items WHERE id='blocked'`).Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if sentinel != 1 || blocked != 0 {
		t.Fatalf("partial snapshot install sentinel=%d blocked=%d", sentinel, blocked)
	}
}

func TestStreamingSnapshotReceiveFailureCleansTemporaryFile(t *testing.T) {
	ctx, source, _, sourceID := setupEventValidationNodes(t)
	_ = ctx
	payload := []byte("expected snapshot")
	hash := sha256.Sum256(payload)
	manifest := replicationSnapshotManifest{SnapshotUUID: "00000000-0000-4000-8000-000000000711", CreatedByNodeUUID: sourceID, ContentSizeBytes: int64(len(payload)), ContentHash: hex.EncodeToString(hash[:])}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		request, err := readReplicationFrame(server, 8<<20, 32<<20)
		if err != nil {
			done <- err
			return
		}
		chunk := wireSnapshotChunk{SnapshotUUID: manifest.SnapshotUUID, Offset: request.SnapshotChunk.Offset, Data: []byte("bad"), ChunkHash: "wrong"}
		done <- writeReplicationFrame(server, wireMessage{Type: "snapshot_chunk", SnapshotChunk: &chunk}, 8<<20)
	}()
	_, err := source.replication.requestSnapshotChunks(client, manifest, defaultMaximumReplicationSnapshotBytes, 8<<20, 32<<20)
	_ = client.Close()
	if err == nil {
		t.Fatal("invalid snapshot chunk was accepted")
	}
	if serverErr := <-done; serverErr != nil {
		t.Fatal(serverErr)
	}
	matches, globErr := filepath.Glob(source.path + ".replication-snapshots/.*.tmp")
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("receive temporary files remain: %v", matches)
	}
}
