package sqliteseal

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"time"
)

func (r *replicationRuntime) handshake(c net.Conn, outbound bool, expected string) (wireHello, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var peer wireHello
	if outbound {
		credential, auth, err := r.peerAuthConfig(ctx, expected)
		if err != nil {
			return peer, err
		}
		local, err := r.makeHello(ctx, credential, auth)
		if err != nil {
			return peer, err
		}
		if err = writeReplicationFrame(c, wireMessage{Type: "hello", Hello: &local}, 8<<20); err != nil {
			return peer, err
		}
		msg, err := readReplicationFrame(c, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if msg.Type != "hello" || msg.Hello == nil {
			return peer, errors.New("replication: expected hello")
		}
		peer = *msg.Hello
	} else {
		msg, err := readReplicationFrame(c, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if msg.Type != "hello" || msg.Hello == nil {
			return peer, errors.New("replication: expected hello")
		}
		peer = *msg.Hello
		credential, auth, err := r.peerAuthConfig(ctx, peer.NodeUUID)
		if err != nil {
			return peer, err
		}
		local, err := r.makeHello(ctx, credential, auth)
		if err != nil {
			return peer, err
		}
		if err = writeReplicationFrame(c, wireMessage{Type: "hello", Hello: &local}, 8<<20); err != nil {
			return peer, err
		}
	}
	if peer.Protocol != replicationProtocolVersion {
		return peer, errors.New("replication: unsupported protocol version")
	}
	if peer.Nonce == "" {
		return peer, errors.New("replication: missing session nonce")
	}
	var inc, domain, schema, member, peerCred string
	var auth ReplicationAuthMode
	var version, epoch int64
	var enabled int
	if err := r.db.QueryRowContext(ctx, `SELECT incarnation_uuid,replication_domain,enabled,credential_name,auth_mode FROM replication_nodes WHERE node_uuid=?`, peer.NodeUUID).Scan(&inc, &domain, &enabled, &peerCred, &auth); err != nil {
		return peer, err
	}
	if expected != "" && peer.NodeUUID != expected {
		return peer, errors.New("replication: unexpected peer identity")
	}
	if enabled == 0 || inc != peer.IncarnationUUID || domain != peer.Domain {
		return peer, errors.New("replication: unauthorized peer")
	}
	if err := r.db.QueryRowContext(ctx, `SELECT schema_hash,membership_manifest_hash,schema_version,membership_epoch FROM replication_local_state`).Scan(&schema, &member, &version, &epoch); err != nil {
		return peer, err
	}
	if peer.SchemaHash != schema || peer.SchemaVersion != version {
		return peer, ErrReplicationSchemaMismatch
	}
	if peer.MembershipHash != member || peer.MembershipEpoch != epoch {
		return peer, ErrReplicationMembershipMismatch
	}
	if auth == ReplicationAuthPSK {
		psk, err := r.opts.Credentials.PSK(ctx, peerCred)
		if err != nil {
			return peer, err
		}
		defer wipeBytes(psk)
		nonce, err := base64.RawURLEncoding.DecodeString(peer.Nonce)
		if err != nil || len(nonce) != 32 {
			return peer, errors.New("replication: invalid PSK nonce")
		}
		got, err := base64.RawURLEncoding.DecodeString(peer.Proof)
		if err != nil {
			return peer, err
		}
		want, _ := base64.RawURLEncoding.DecodeString(replicationProof(psk, peer))
		if !hmac.Equal(got, want) {
			return peer, errors.New("replication: PSK proof rejected")
		}
	}
	if auth == ReplicationAuthMTLS {
		tc, ok := c.(*tls.Conn)
		if !ok || len(tc.ConnectionState().PeerCertificates) == 0 {
			return peer, errors.New("replication: mTLS peer certificate missing")
		}
	}
	_ = c.SetDeadline(time.Time{})
	return peer, nil
}
func (r *replicationRuntime) peerAuthConfig(ctx context.Context, node string) (string, ReplicationAuthMode, error) {
	var credential string
	var auth ReplicationAuthMode
	err := r.db.QueryRowContext(ctx, `SELECT credential_name,auth_mode FROM replication_nodes WHERE node_uuid=?`, node).Scan(&credential, &auth)
	return credential, auth, err
}
func (r *replicationRuntime) makeHello(ctx context.Context, credential string, auth ReplicationAuthMode) (wireHello, error) {
	if auth == ReplicationAuthPSK {
		return r.localHello(ctx, credential)
	}
	var h wireHello
	h.Protocol = replicationProtocolVersion
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,local_incarnation_uuid,replication_domain,schema_version,schema_hash,membership_epoch,membership_manifest_hash FROM replication_local_state`).Scan(&h.NodeUUID, &h.IncarnationUUID, &h.Domain, &h.SchemaVersion, &h.SchemaHash, &h.MembershipEpoch, &h.MembershipHash); err != nil {
		return h, err
	}
	h.Nonce = replicationUUID()
	return h, nil
}
