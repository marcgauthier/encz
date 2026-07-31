package sqliteseal

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestReplicationLivenessReadTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	connection := newReplicationLivenessConn(client, 100*time.Millisecond)
	started := time.Now()
	_, err := connection.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("idle read did not time out")
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("read error=%v, want network timeout", err)
	}
	if elapsed := time.Since(started); elapsed < 60*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("read timeout elapsed=%s", elapsed)
	}
	if normalized := normalizeReplicationConnectionError(err); !errors.Is(normalized, errReplicationHeartbeatTimeout) {
		t.Fatalf("normalized error=%v", normalized)
	}
}

func TestReplicationLivenessReadDeadlineSlidesWithTraffic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		for _, value := range []byte("abc") {
			time.Sleep(100 * time.Millisecond)
			if _, err := server.Write([]byte{value}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	connection := newReplicationLivenessConn(client, 200*time.Millisecond)
	buffer := make([]byte, 3)
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "abc" {
		t.Fatalf("buffer=%q", buffer)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReplicationLivenessWriteTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	connection := newReplicationLivenessConn(client, 100*time.Millisecond)
	_, err := connection.Write([]byte("blocked"))
	if err == nil {
		t.Fatal("blocked write did not time out")
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("write error=%v, want network timeout", err)
	}
}

func TestReplicationPeerHeartbeatDefaultsAndLiveUpdate(t *testing.T) {
	var defaults PeerConfig
	defaultsPeer(&defaults)
	if defaults.HeartbeatInterval != 15*time.Second || defaults.HeartbeatTimeout != 45*time.Second {
		t.Fatalf("default heartbeat interval=%s timeout=%s", defaults.HeartbeatInterval, defaults.HeartbeatTimeout)
	}
	customDefaults := PeerConfig{HeartbeatInterval: 30 * time.Second}
	defaultsPeer(&customDefaults)
	if customDefaults.HeartbeatTimeout != 90*time.Second {
		t.Fatalf("scaled heartbeat timeout=%s", customDefaults.HeartbeatTimeout)
	}

	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "heartbeat.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(t.Context(), LocalNodeConfig{NodeName: "local", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	peer := PeerConfig{
		NodeUUID:          "00000000-0000-4000-8000-000000000501",
		IncarnationUUID:   "00000000-0000-4000-8000-000000000502",
		NodeName:          "peer",
		Address:           "127.0.0.1:1",
		Role:              ReplicationDial,
		AuthMode:          ReplicationAuthPSK,
		HeartbeatInterval: 2 * time.Second,
		HeartbeatTimeout:  6 * time.Second,
	}
	if err = db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	peer.HeartbeatInterval = 3 * time.Second
	peer.HeartbeatTimeout = 9 * time.Second
	if err = db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	var intervalMS, timeoutMS int64
	if err = db.QueryRow(`SELECT heartbeat_interval_ms,heartbeat_timeout_ms FROM replication_peer_connections WHERE peer_node_uuid=?`, peer.NodeUUID).Scan(&intervalMS, &timeoutMS); err != nil {
		t.Fatal(err)
	}
	if intervalMS != 3000 || timeoutMS != 9000 {
		t.Fatalf("persisted interval=%d timeout=%d", intervalMS, timeoutMS)
	}
	if _, err = db.Exec(`UPDATE replication_peer_connections SET enabled=1,heartbeat_timeout_ms=heartbeat_interval_ms WHERE peer_node_uuid=?`, peer.NodeUUID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.replication.loadPeerRuntimeConfig(t.Context(), peer.NodeUUID); !errors.Is(err, ErrReplicationInvalidConfig) {
		t.Fatalf("invalid persisted heartbeat error=%v", err)
	}
}

func TestReplicationDisconnectIsSessionAware(t *testing.T) {
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "session-aware.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(t.Context(), LocalNodeConfig{NodeName: "local", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	peer := PeerConfig{NodeUUID: "00000000-0000-4000-8000-000000000511", IncarnationUUID: "00000000-0000-4000-8000-000000000512", NodeName: "peer", Address: "127.0.0.1:1", Role: ReplicationAccept, AuthMode: ReplicationAuthPSK}
	if err = db.UpsertReplicationPeer(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	const oldSession = "00000000-0000-4000-8000-000000000513"
	const newSession = "00000000-0000-4000-8000-000000000514"
	db.replication.setPeerAuthenticated(peer.NodeUUID, newSession)
	db.replication.setPeerDisconnected(peer.NodeUUID, oldSession, errReplicationHeartbeatTimeout)
	var state, session, lastError string
	if err = db.QueryRow(`SELECT session_state,last_session_uuid,coalesce(last_error,'') FROM replication_peer_connections WHERE peer_node_uuid=?`, peer.NodeUUID).Scan(&state, &session, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "connected" || session != newSession || lastError != "" {
		t.Fatalf("stale disconnect changed current session: state=%s session=%s error=%q", state, session, lastError)
	}
	db.replication.setPeerDisconnected(peer.NodeUUID, newSession, errReplicationHeartbeatTimeout)
	if err = db.QueryRow(`SELECT session_state,coalesce(last_error,'') FROM replication_peer_connections WHERE peer_node_uuid=?`, peer.NodeUUID).Scan(&state, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "disconnected" || lastError != errReplicationHeartbeatTimeout.Error() {
		t.Fatalf("current disconnect state=%s error=%q", state, lastError)
	}
}
