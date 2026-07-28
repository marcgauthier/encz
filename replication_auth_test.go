package sqliteseal

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type shortPSKProvider struct{}

func (shortPSKProvider) PSK(context.Context, string) ([]byte, error) { return []byte("short"), nil }
func (shortPSKProvider) TLSConfig(context.Context, string, bool) (*tls.Config, error) {
	return &tls.Config{}, nil
}

func TestReplicationAuthenticationReplayCache(t *testing.T) {
	runtime := &replicationRuntime{authReplay: map[string]time.Time{}}
	if !runtime.consumeAuthenticationReplay("peer", "session", "initiator", "acceptor") {
		t.Fatal("first transcript rejected")
	}
	if runtime.consumeAuthenticationReplay("peer", "session", "initiator", "acceptor") {
		t.Fatal("replayed transcript accepted")
	}
	if !runtime.consumeAuthenticationReplay("peer", "different-session", "initiator", "acceptor") {
		t.Fatal("fresh session rejected")
	}
}

func TestReplicationAuthenticationRejectsStaleHello(t *testing.T) {
	runtime := &replicationRuntime{}
	hello := wireHello{
		Protocol: replicationProtocolVersion, NodeUUID: "00000000-0000-4000-8000-000000000051",
		IncarnationUUID: "00000000-0000-4000-8000-000000000052",
		Nonce:           base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		SentAtUTC:       time.Now().Add(-3 * time.Minute).UTC().Format("2006-01-02T15:04:05.000000Z"),
	}
	if _, _, err := runtime.validatePeerHello(context.Background(), nil, hello, ""); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("got %v", err)
	}
}

func TestReplicationAuthenticationRejectsShortPSK(t *testing.T) {
	runtime := &replicationRuntime{opts: &ReplicationRuntimeOptions{Credentials: shortPSKProvider{}}}
	if _, err := runtime.authenticationProof(context.Background(), nil, "credential", ReplicationAuthPSK, wireHello{}, wireHello{}, "initiator"); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("got %v", err)
	}
}

func TestReplicationMTLSRequiresCertificateAuthorizer(t *testing.T) {
	ctx := context.Background()
	db, err := OpenSQLiteSeal(filepath.Join(t.TempDir(), "mtls.db"), "key")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: "00000000-0000-4000-8000-000000000053", NodeName: "local", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	peerID := "00000000-0000-4000-8000-000000000054"
	peerIncarnation := "00000000-0000-4000-8000-000000000055"
	if err = db.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: peerID, IncarnationUUID: peerIncarnation, NodeName: "peer", Address: "127.0.0.1:1", Role: ReplicationDial, AuthMode: ReplicationAuthMTLS, ListenEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE replication_nodes SET enabled=1,membership_state='active' WHERE node_uuid=?`, peerID); err != nil {
		t.Fatal(err)
	}
	status, err := db.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := wireHello{Protocol: replicationProtocolVersion, NodeUUID: peerID, IncarnationUUID: peerIncarnation, Domain: status.Domain, SchemaVersion: status.SchemaVersion, SchemaHash: status.SchemaHash, MembershipEpoch: status.MembershipEpoch, MembershipHash: status.MembershipHash, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), SentAtUTC: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")}
	if _, _, err = db.replication.validatePeerHello(ctx, nil, hello, peerID); err == nil || !strings.Contains(err.Error(), "certificate authorizer") {
		t.Fatalf("got %v", err)
	}
}
