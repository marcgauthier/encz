package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
)

const (
	snapshotSourceID = "30000000-0000-4000-8000-000000000003"
	snapshotTargetID = "40000000-0000-4000-8000-000000000004"
)

func verifyControlPlane(ctx context.Context, a, b node) error {
	status, err := a.db.ReplicationStatus(ctx)
	if err != nil {
		return fmt.Errorf("replication status: %w", err)
	}
	if !status.Initialized || !status.Ready || !status.NetworkEnabled || status.MembershipEpoch != 2 || len(status.Peers) != 1 || status.Peers[0].NodeUUID != b.id {
		return fmt.Errorf("unexpected replication status: %+v", status)
	}
	if err = a.db.TestReplicationPeer(ctx, b.id); err != nil {
		return fmt.Errorf("administrative peer authentication: %w", err)
	}
	if err = a.db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{NodeUUID: a.id, NodeName: a.name, ReplicationDomain: domain}, []sqliteseal.ReplicatedTable{{Name: "items"}}); !errors.Is(err, sqliteseal.ErrReplicationAlreadyInitialized) {
		return fmt.Errorf("repeat initialization error = %v", err)
	}
	if err = a.db.SyncReplicationPeer(ctx, "ffffffff-ffff-4fff-8fff-ffffffffffff"); !errors.Is(err, sqliteseal.ErrReplicationPeerNotFound) {
		return fmt.Errorf("unknown peer error = %v", err)
	}
	if err = a.db.ApplyReplicationMigration(ctx, sqliteseal.ReplicationMigration{FromVersion: 1, ToVersion: 1}); !errors.Is(err, sqliteseal.ErrReplicationInvalidConfig) {
		return fmt.Errorf("invalid migration error = %v", err)
	}
	badRetirement := sqliteseal.MembershipManifest{Epoch: 3, Domain: domain}
	if err = a.db.RetireReplicationPeer(ctx, b.id, badRetirement); !errors.Is(err, sqliteseal.ErrReplicationMembershipMismatch) {
		return fmt.Errorf("invalid retirement error = %v", err)
	}
	if err = b.db.ReloadReplicationCredentials(ctx); err != nil {
		return fmt.Errorf("reload B credentials: %w", err)
	}
	if err = a.db.ReloadReplicationCredentials(ctx); err != nil {
		return fmt.Errorf("reload A credentials: %w", err)
	}
	if err = waitConnected(ctx, a.db, b.id); err != nil {
		return fmt.Errorf("credential reload reconnect: %w", err)
	}
	return nil
}

func verifySnapshotCreation(ctx context.Context, db *sqliteseal.DB) error {
	info, err := db.CreateReplicationSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}
	if info.SnapshotUUID == "" || len(info.SchemaHash) != 64 || len(info.ContentHash) != 64 || info.SizeBytes <= 0 || info.CreatedAt.IsZero() {
		return fmt.Errorf("invalid snapshot info: %+v", info)
	}
	var state, authMode, storageURI, hash string
	var size int64
	err = db.QueryRowContext(ctx, `SELECT snapshot_state,snapshot_auth_mode,storage_uri,content_hash,content_size_bytes FROM replication_snapshots WHERE snapshot_uuid=?`, info.SnapshotUUID).Scan(&state, &authMode, &storageURI, &hash, &size)
	if err != nil {
		return fmt.Errorf("snapshot metadata: %w", err)
	}
	if state != "ready" || authMode != "session" || hash != info.ContentHash || size != info.SizeBytes || storageURI == "" {
		return fmt.Errorf("invalid snapshot metadata state=%s auth=%s hash=%s size=%d uri=%q", state, authMode, hash, size, storageURI)
	}
	file, err := os.Stat(storageURI)
	if err != nil {
		return fmt.Errorf("snapshot storage: %w", err)
	}
	if file.Size() != info.SizeBytes {
		return fmt.Errorf("snapshot file size=%d metadata=%d", file.Size(), info.SizeBytes)
	}
	return nil
}

func runAutomaticSnapshotBootstrap(ctx context.Context, runDir string, pki generatedPKI, signPriv ed25519.PrivateKey, signPub ed25519.PublicKey, psk []byte) error {
	address, err := freeAddress()
	if err != nil {
		return err
	}
	source := node{name: "snapshot-source", id: snapshotSourceID, key: "snapshot-source-encryption-key", path: runDir + "/snapshot-source.db", creds: &credentials{pki.a, pki.roots, psk}, verify: verifier{signPub}}
	target := node{name: "snapshot-target", id: snapshotTargetID, key: "snapshot-target-encryption-key", path: runDir + "/snapshot-target.db", creds: &credentials{pki.b, pki.roots, psk}, verify: verifier{signPub}}
	if err = openNode(ctx, &source, address); err != nil {
		return fmt.Errorf("open snapshot source: %w", err)
	}
	defer source.db.Close()
	if err = openNode(ctx, &target, ""); err != nil {
		return fmt.Errorf("open snapshot target: %w", err)
	}
	defer target.db.Close()
	if err = target.db.UpsertReplicationPeer(ctx, peer(source, address, sqliteseal.ReplicationDial, true)); err != nil {
		return err
	}
	if err = source.db.UpsertReplicationPeer(ctx, peer(target, "127.0.0.1:1", sqliteseal.ReplicationAccept, false)); err != nil {
		return err
	}
	if _, err = source.db.ExecContext(ctx, `INSERT INTO items VALUES('snapshot-row','before',1,'bootstrap',?)`, now()); err != nil {
		return err
	}
	if _, err = source.db.ExecContext(ctx, `UPDATE items SET name='from-snapshot',quantity=42,updated_at=? WHERE id='snapshot-row'`, now()); err != nil {
		return err
	}
	if err = compactFirstSnapshotEvent(ctx, source.db, source.id); err != nil {
		return err
	}
	sourceStatus := mustStatus(ctx, source.db)
	targetStatus := mustStatus(ctx, target.db)
	manifest := sqliteseal.MembershipManifest{Epoch: 2, Domain: domain, PolicyHash: "snapshot-bootstrap-policy-v1", Nodes: []sqliteseal.MembershipNode{
		{NodeUUID: source.id, IncarnationUUID: sourceStatus.IncarnationUUID, State: "active", ListenEnabled: true, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{target.id: sqliteseal.ReplicationAccept}},
		{NodeUUID: target.id, IncarnationUUID: targetStatus.IncarnationUUID, State: "active", ListenEnabled: false, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{source.id: sqliteseal.ReplicationDial}},
	}}
	manifest.Signature = signManifest(manifest, signPriv)
	if err = source.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate snapshot source: %w", err)
	}
	if err = target.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate snapshot target: %w", err)
	}
	if err = waitCounter(ctx, target.db, source.db, source.id); err != nil {
		return fmt.Errorf("automatic snapshot catch-up: %w", err)
	}
	if err = expectItem(ctx, target.db, "snapshot-row", "from-snapshot", 42, "bootstrap"); err != nil {
		return err
	}
	var installed, baseline, requires int
	if err = target.db.QueryRowContext(ctx, `SELECT count(*) FROM replication_snapshots WHERE snapshot_state='installed' AND created_by_node_uuid=?`, source.id).Scan(&installed); err != nil {
		return err
	}
	if err = target.db.QueryRowContext(ctx, `SELECT count(*),coalesce(max(requires_snapshot),0) FROM replication_origin_cursors WHERE tracking_node_uuid=? AND origin_node_uuid=?`, target.id, source.id).Scan(&baseline, &requires); err != nil {
		return err
	}
	if installed != 1 || baseline != 1 || requires != 0 {
		return fmt.Errorf("snapshot bootstrap installed=%d baseline=%d requires=%d", installed, baseline, requires)
	}
	return nil
}

func compactFirstSnapshotEvent(ctx context.Context, db *sqliteseal.DB, origin string) error {
	var changeUUID, descriptorID string
	if err := db.QueryRowContext(ctx, `SELECT c.change_uuid,d.descriptor_id FROM replication_changes c JOIN replication_table_descriptors d ON d.table_name=c.table_name WHERE c.origin_node_uuid=? AND c.origin_counter=1`, origin).Scan(&changeUUID, &descriptorID); err != nil {
		return err
	}
	if descriptorID == "" || strings.Trim(descriptorID, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return errors.New("unsafe snapshot descriptor identifier")
	}
	payloadTable := `"` + descriptorID + `__replication_changes"`
	if _, err := db.ExecContext(ctx, `DELETE FROM `+payloadTable+` WHERE change_uuid=?`, changeUUID); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `DELETE FROM replication_changes WHERE change_uuid=?`, changeUUID)
	return err
}
