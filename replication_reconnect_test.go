package sqliteseal

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReconnectBackoffAndJitterBounds(t *testing.T) {
	var defaults PeerConfig
	defaultsPeer(&defaults)
	if defaults.ReconnectInitial != time.Second || defaults.ReconnectMaximum != time.Minute || defaults.ReconnectJitterPercent == nil || *defaults.ReconnectJitterPercent != 20 {
		t.Fatalf("reconnect defaults=%s,%s,%v", defaults.ReconnectInitial, defaults.ReconnectMaximum, defaults.ReconnectJitterPercent)
	}
	zeroJitter := 0
	disabledJitter := PeerConfig{ReconnectJitterPercent: &zeroJitter}
	defaultsPeer(&disabledJitter)
	if disabledJitter.ReconnectJitterPercent == nil || *disabledJitter.ReconnectJitterPercent != 0 {
		t.Fatalf("explicit zero jitter was not preserved")
	}
	initial := 100 * time.Millisecond
	maximum := 800 * time.Millisecond
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 800 * time.Millisecond}
	for index, expected := range want {
		if got := reconnectBackoff(initial, maximum, int64(index+1)); got != expected {
			t.Fatalf("failure %d backoff=%s want=%s", index+1, got, expected)
		}
	}
	if got := reconnectBackoff(initial, maximum, 1_000_000); got != maximum {
		t.Fatalf("large failure count backoff=%s", got)
	}
	lower, upper := reconnectJitterBounds(400*time.Millisecond, maximum, 20)
	if lower != 320*time.Millisecond || upper != 480*time.Millisecond {
		t.Fatalf("jitter bounds=%s..%s", lower, upper)
	}
	lower, upper = reconnectJitterBounds(maximum, maximum, 20)
	if lower != 640*time.Millisecond || upper != maximum {
		t.Fatalf("capped jitter bounds=%s..%s", lower, upper)
	}
	for range 100 {
		delay := randomizedReconnectDelay(400*time.Millisecond, maximum, 20)
		if delay < 320*time.Millisecond || delay > 480*time.Millisecond {
			t.Fatalf("randomized delay outside bounds: %s", delay)
		}
	}
	if delay := randomizedReconnectDelay(400*time.Millisecond, maximum, 0); delay != 400*time.Millisecond {
		t.Fatalf("disabled jitter delay=%s", delay)
	}
}

func TestReconnectConfigurationAndStatus(t *testing.T) {
	db := openReconnectTestDB(t, filepath.Join(t.TempDir(), "status.db"))
	defer db.Close()
	zero := 0
	peer := PeerConfig{
		NodeUUID: "00000000-0000-4000-8000-000000000601", IncarnationUUID: "00000000-0000-4000-8000-000000000602",
		NodeName: "retry-peer", Address: "127.0.0.1:1", Role: ReplicationDial, AuthMode: ReplicationAuthPSK,
		ReconnectInitial: 100 * time.Millisecond, ReconnectMaximum: 800 * time.Millisecond, ReconnectJitterPercent: &zero,
	}
	if err := db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	var initialMS, maximumMS int64
	var jitter int
	if err := db.QueryRow(`SELECT reconnect_initial_ms,reconnect_max_ms,reconnect_jitter_percent FROM replication_peer_connections WHERE peer_node_uuid=?`, peer.NodeUUID).Scan(&initialMS, &maximumMS, &jitter); err != nil {
		t.Fatal(err)
	}
	if initialMS != 100 || maximumMS != 800 || jitter != 0 {
		t.Fatalf("persisted reconnect config=%d,%d,%d", initialMS, maximumMS, jitter)
	}
	if _, err := db.Exec(`UPDATE replication_peer_connections SET session_state='connecting' WHERE peer_node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	config, err := db.replication.loadPeerRuntimeConfig(t.Context(), peer.NodeUUID)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	next, recorded, err := db.replication.recordDialFailure(config, "", errors.New("network unavailable"))
	if err != nil || !recorded {
		t.Fatalf("record failure: recorded=%v err=%v", recorded, err)
	}
	if next.Before(before.Add(90*time.Millisecond)) || next.After(time.Now().UTC().Add(120*time.Millisecond)) {
		t.Fatalf("next retry=%s outside expected first backoff", next)
	}
	status, err := db.ReplicationStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Peers) != 1 || status.Peers[0].ConsecutiveFailures != 1 || status.Peers[0].NextRetryAt == nil {
		t.Fatalf("retry status=%+v", status.Peers)
	}
	db.replication.setPeerAuthenticated(peer.NodeUUID, "00000000-0000-4000-8000-000000000603")
	status, err = db.ReplicationStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.Peers[0].State != "connected" || status.Peers[0].ConsecutiveFailures != 0 || status.Peers[0].NextRetryAt != nil || status.Peers[0].ConnectedAt.IsZero() {
		t.Fatalf("authenticated retry status=%+v", status.Peers[0])
	}
	invalid := 101
	peer.ReconnectJitterPercent = &invalid
	if err = db.UpsertReplicationPeer(t.Context(), peer); !errors.Is(err, ErrReplicationInvalidConfig) {
		t.Fatalf("invalid jitter error=%v", err)
	}
}

func TestReconnectMetadataCompatibilityMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db := openReconnectTestDB(t, path)
	if _, err := db.Exec(`ALTER TABLE replication_peer_connections DROP COLUMN reconnect_jitter_percent`); err != nil {
		if _, err := db.Exec(`ALTER TABLE replication_peer_connections DROP COLUMN max_snapshot_bytes`); err != nil {
			t.Fatal(err)
		}
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openReconnectExistingDB(t, path)
	defer db.Close()
	found, err := replicationColumnExists(t.Context(), db, "replication_peer_connections", "reconnect_jitter_percent")
	snapshotLimitFound, snapshotLimitErr := replicationColumnExists(t.Context(), db, "replication_peer_connections", "max_snapshot_bytes")
	if snapshotLimitErr != nil || !snapshotLimitFound {
		t.Fatalf("snapshot limit migration found=%v err=%v", snapshotLimitFound, snapshotLimitErr)
	}
	if err != nil || !found {
		t.Fatalf("jitter migration found=%v err=%v", found, err)
	}
}

func TestReconnectScheduleSurvivesReopenAndManualWakeBypassesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persistent.db")
	db := openReconnectTestDB(t, path)
	zero := 0
	peer := PeerConfig{
		NodeUUID: "00000000-0000-4000-8000-000000000611", IncarnationUUID: "00000000-0000-4000-8000-000000000612",
		NodeName: "offline-peer", Address: replicationTestAddress(t), Role: ReplicationDial, AuthMode: ReplicationAuthPSK,
		ConnectTimeout: 100 * time.Millisecond, ReconnectInitial: 700 * time.Millisecond, ReconnectMaximum: 700 * time.Millisecond, ReconnectJitterPercent: &zero,
	}
	if err := db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_nodes SET enabled=1,membership_state='active' WHERE node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_peer_connections SET enabled=1,session_state='disconnected' WHERE peer_node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_local_state SET network_enabled=1,blocked_reason=NULL`); err != nil {
		t.Fatal(err)
	}
	db.replication.start()
	waitForReconnectFailures(t, db, peer.NodeUUID, 1, 3*time.Second)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openReconnectExistingDB(t, path)
	defer db.Close()
	time.Sleep(100 * time.Millisecond)
	if failures := reconnectFailureCount(t, db, peer.NodeUUID); failures != 1 {
		t.Fatalf("persisted retry was not honored after reopen: failures=%d", failures)
	}
	if err := db.SyncReplicationPeer(t.Context(), peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	waitForReconnectFailures(t, db, peer.NodeUUID, 2, 400*time.Millisecond)
}

func TestReconnectReopenReplacesStaleConnectedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale-connected.db")
	db := openReconnectTestDB(t, path)
	zero := 0
	peer := PeerConfig{
		NodeUUID: "00000000-0000-4000-8000-000000000621", IncarnationUUID: "00000000-0000-4000-8000-000000000622",
		NodeName: "stale-peer", Address: replicationTestAddress(t), Role: ReplicationDial, AuthMode: ReplicationAuthPSK,
		ConnectTimeout: 100 * time.Millisecond, ReconnectInitial: 500 * time.Millisecond, ReconnectMaximum: 500 * time.Millisecond, ReconnectJitterPercent: &zero,
	}
	if err := db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_nodes SET enabled=1,membership_state='active' WHERE node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_peer_connections SET enabled=1,session_state='connected',last_session_uuid='stale-session' WHERE peer_node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE replication_local_state SET network_enabled=1,blocked_reason=NULL`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openReconnectExistingDB(t, path)
	defer db.Close()
	waitForReconnectFailures(t, db, peer.NodeUUID, 1, 2*time.Second)
	var state string
	if err := db.QueryRow(`SELECT session_state FROM replication_peer_connections WHERE peer_node_uuid=?`, peer.NodeUUID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "disconnected" {
		t.Fatalf("stale connected state was not replaced: %s", state)
	}
}

func openReconnectTestDB(t *testing.T, path string) *DB {
	t.Helper()
	db := openReconnectExistingDB(t, path)
	if _, err := db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeReplication(t.Context(), LocalNodeConfig{NodeUUID: "00000000-0000-4000-8000-000000000600", NodeName: "retry-local", ReplicationDomain: "retry-test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	return db
}

func openReconnectExistingDB(t *testing.T, path string) *DB {
	t.Helper()
	db, err := OpenWithOptions(path, Options{Key: "key", Replication: &ReplicationRuntimeOptions{Credentials: shortPSKProvider{}}})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func reconnectFailureCount(t *testing.T, db *DB, peer string) int64 {
	t.Helper()
	var failures int64
	if err := db.QueryRow(`SELECT consecutive_failures FROM replication_peer_connections WHERE peer_node_uuid=?`, peer).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	return failures
}

func waitForReconnectFailures(t *testing.T, db *DB, peer string, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if failures := reconnectFailureCount(t, db, peer); failures >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("retry failures did not reach %d", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
