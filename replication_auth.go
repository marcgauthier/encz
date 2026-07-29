package sqliteseal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	replicationAuthFreshness = 2 * time.Minute
	replicationReplayWindow  = 5 * time.Minute
)

type replicationAuthTranscript struct {
	Protocol       int       `json:"protocol"`
	SessionUUID    string    `json:"session_uuid"`
	Initiator      wireHello `json:"initiator"`
	Acceptor       wireHello `json:"acceptor"`
	ChannelBinding string    `json:"tls_exporter"`
}

func (r *replicationRuntime) handshake(connection net.Conn, outbound bool, expected string) (wireHello, error) {
	return r.handshakePurpose(connection, outbound, expected, false)
}

func (r *replicationRuntime) handshakePurpose(connection net.Conn, outbound bool, expected string, administrativeTest bool) (wireHello, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return wireHello{}, errors.New("replication: TLS connection required")
	}
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return wireHello{}, err
	}
	if tlsConnection.ConnectionState().Version < tls.VersionTLS12 {
		return wireHello{}, errors.New("replication: TLS 1.2 or newer is required")
	}
	var peer wireHello
	if outbound {
		initiator, err := r.newAuthHello(ctx, "")
		initiator.AdministrativeTest = administrativeTest
		if err != nil {
			return peer, err
		}
		if err = writeReplicationFrame(connection, wireMessage{Type: "auth_init", Hello: &initiator}, 8<<20); err != nil {
			return peer, err
		}
		message, err := readReplicationFrame(connection, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if message.Type != "auth_challenge" || message.Hello == nil {
			return peer, errors.New("replication: expected authentication challenge")
		}
		peer = *message.Hello
		credential, mode, err := r.validatePeerHello(ctx, tlsConnection, peer, expected)
		if err != nil {
			return peer, err
		}
		if peer.AdministrativeTest != administrativeTest {
			return peer, errors.New("replication: authentication purpose mismatch")
		}
		if !isCanonicalUUID(peer.SessionUUID) {
			return peer, errors.New("replication: invalid session identity")
		}
		initiator.SessionUUID = peer.SessionUUID
		proof, err := r.authenticationProof(ctx, tlsConnection, credential, mode, initiator, peer, "initiator")
		if err != nil {
			return peer, err
		}
		proofMessage := initiator
		proofMessage.Proof = proof
		if err = writeReplicationFrame(connection, wireMessage{Type: "auth_proof", Hello: &proofMessage}, 8<<20); err != nil {
			return peer, err
		}
		message, err = readReplicationFrame(connection, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if message.Type != "auth_result" || message.Hello == nil || message.Hello.SessionUUID != peer.SessionUUID {
			return peer, errors.New("replication: invalid authentication result")
		}
		if err = r.verifyAuthenticationProof(ctx, tlsConnection, credential, mode, initiator, peer, "acceptor", message.Hello.Proof); err != nil {
			return peer, err
		}
		if !r.consumeAuthenticationReplay(peer.NodeUUID, peer.SessionUUID, initiator.Nonce, peer.Nonce) {
			return peer, errors.New("replication: authentication replay rejected")
		}
	} else {
		message, err := readReplicationFrame(connection, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if message.Type != "auth_init" || message.Hello == nil || message.Hello.SessionUUID != "" || message.Hello.Proof != "" {
			return peer, errors.New("replication: expected authentication initialization")
		}
		peer = *message.Hello
		credential, mode, err := r.validatePeerHello(ctx, tlsConnection, peer, "")
		if err != nil {
			return peer, err
		}
		acceptor, err := r.newAuthHello(ctx, replicationUUID())
		acceptor.AdministrativeTest = peer.AdministrativeTest
		if err != nil {
			return peer, err
		}
		if err = writeReplicationFrame(connection, wireMessage{Type: "auth_challenge", Hello: &acceptor}, 8<<20); err != nil {
			return peer, err
		}
		message, err = readReplicationFrame(connection, 8<<20, 32<<20)
		if err != nil {
			return peer, err
		}
		if message.Type != "auth_proof" || message.Hello == nil || !sameAuthenticationIdentity(peer, *message.Hello) || message.Hello.SessionUUID != acceptor.SessionUUID {
			return peer, errors.New("replication: invalid authentication proof message")
		}
		initiator := peer
		initiator.SessionUUID = acceptor.SessionUUID
		if err = r.verifyAuthenticationProof(ctx, tlsConnection, credential, mode, initiator, acceptor, "initiator", message.Hello.Proof); err != nil {
			return peer, err
		}
		if !r.consumeAuthenticationReplay(peer.NodeUUID, acceptor.SessionUUID, peer.Nonce, acceptor.Nonce) {
			return peer, errors.New("replication: authentication replay rejected")
		}
		proof, err := r.authenticationProof(ctx, tlsConnection, credential, mode, initiator, acceptor, "acceptor")
		if err != nil {
			return peer, err
		}
		result := acceptor
		result.Proof = proof
		if err = writeReplicationFrame(connection, wireMessage{Type: "auth_result", Hello: &result}, 8<<20); err != nil {
			return peer, err
		}
		peer.SessionUUID = acceptor.SessionUUID
	}
	_ = connection.SetDeadline(time.Time{})
	return peer, nil
}

func (r *replicationRuntime) newAuthHello(ctx context.Context, session string) (wireHello, error) {
	var hello wireHello
	hello.Protocol = replicationProtocolVersion
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid,local_incarnation_uuid,replication_domain,schema_version,schema_hash,membership_epoch,membership_manifest_hash FROM replication_local_state`).Scan(&hello.NodeUUID, &hello.IncarnationUUID, &hello.Domain, &hello.SchemaVersion, &hello.SchemaHash, &hello.MembershipEpoch, &hello.MembershipHash); err != nil {
		return hello, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return hello, err
	}
	hello.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	hello.SessionUUID = session
	hello.SentAtUTC = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	return hello, nil
}

func (r *replicationRuntime) validatePeerHello(ctx context.Context, connection *tls.Conn, peer wireHello, expected string) (string, ReplicationAuthMode, error) {
	if peer.Protocol != replicationProtocolVersion || !isCanonicalUUID(peer.NodeUUID) || !isCanonicalUUID(peer.IncarnationUUID) {
		return "", "", errors.New("replication: invalid peer protocol identity")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(peer.Nonce)
	if err != nil || len(nonce) != 32 {
		return "", "", errors.New("replication: invalid authentication nonce")
	}
	sent, err := time.Parse("2006-01-02T15:04:05.000000Z", peer.SentAtUTC)
	if err != nil || time.Since(sent) > replicationAuthFreshness || time.Until(sent) > replicationAuthFreshness {
		return "", "", errors.New("replication: stale authentication message")
	}
	var incarnation, domain, credential string
	var mode ReplicationAuthMode
	var enabled int
	if err = r.db.QueryRowContext(ctx, `SELECT incarnation_uuid,replication_domain,enabled,credential_name,auth_mode FROM replication_nodes WHERE node_uuid=?`, peer.NodeUUID).Scan(&incarnation, &domain, &enabled, &credential, &mode); err != nil {
		return "", "", err
	}
	if expected != "" && peer.NodeUUID != expected {
		return "", "", errors.New("replication: unexpected peer identity")
	}
	if enabled == 0 || incarnation != peer.IncarnationUUID || domain != peer.Domain {
		return "", "", errors.New("replication: unauthorized peer")
	}
	var schema, membership string
	var schemaVersion, membershipEpoch int64
	if err = r.db.QueryRowContext(ctx, `SELECT schema_hash,membership_manifest_hash,schema_version,membership_epoch FROM replication_local_state`).Scan(&schema, &membership, &schemaVersion, &membershipEpoch); err != nil {
		return "", "", err
	}
	if peer.SchemaHash != schema || peer.SchemaVersion != schemaVersion {
		return "", "", ErrReplicationSchemaMismatch
	}
	if peer.MembershipHash != membership || peer.MembershipEpoch != membershipEpoch {
		return "", "", ErrReplicationMembershipMismatch
	}
	if mode == ReplicationAuthMTLS {
		if r.opts == nil || r.opts.CertificateAuthorizer == nil {
			return "", "", errors.New("replication: mTLS certificate authorizer is unavailable")
		}
		state := connection.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return "", "", errors.New("replication: mTLS peer certificate missing")
		}
		if err = r.opts.CertificateAuthorizer.AuthorizeReplicationCertificate(ctx, credential, peer.NodeUUID, peer.Domain, state.PeerCertificates[0]); err != nil {
			return "", "", fmt.Errorf("replication: mTLS certificate authorization: %w", err)
		}
	}
	return credential, mode, nil
}

func sameAuthenticationIdentity(first, second wireHello) bool {
	return first.Protocol == second.Protocol && first.NodeUUID == second.NodeUUID && first.IncarnationUUID == second.IncarnationUUID && first.Domain == second.Domain && first.SchemaVersion == second.SchemaVersion && first.SchemaHash == second.SchemaHash && first.MembershipEpoch == second.MembershipEpoch && first.MembershipHash == second.MembershipHash && first.Nonce == second.Nonce && first.SentAtUTC == second.SentAtUTC && first.AdministrativeTest == second.AdministrativeTest
}

func authenticationTranscript(connection *tls.Conn, initiator, acceptor wireHello) ([]byte, error) {
	initiator.Proof = ""
	acceptor.Proof = ""
	initiator.SessionUUID = acceptor.SessionUUID
	state := connection.ConnectionState()
	binding, err := state.ExportKeyingMaterial("EXPORTER-SQLiteSeal-Replication-v1", []byte(acceptor.SessionUUID), 32)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(binding)
	transcript := replicationAuthTranscript{Protocol: replicationProtocolVersion, SessionUUID: acceptor.SessionUUID, Initiator: initiator, Acceptor: acceptor, ChannelBinding: base64.RawURLEncoding.EncodeToString(binding)}
	return json.Marshal(transcript)
}

func (r *replicationRuntime) authenticationProof(ctx context.Context, connection *tls.Conn, credential string, mode ReplicationAuthMode, initiator, acceptor wireHello, role string) (string, error) {
	if mode == ReplicationAuthMTLS {
		return "", nil
	}
	if mode != ReplicationAuthPSK || r.opts == nil || r.opts.Credentials == nil {
		return "", errors.New("replication: unsupported authentication mode")
	}
	key, err := r.opts.Credentials.PSK(ctx, credential)
	if err != nil {
		return "", err
	}
	defer wipeBytes(key)
	if len(key) < 32 {
		return "", errors.New("replication: PSK must contain at least 32 bytes")
	}
	transcript, err := authenticationTranscript(connection, initiator, acceptor)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(role))
	mac.Write([]byte{0})
	mac.Write(transcript)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (r *replicationRuntime) verifyAuthenticationProof(ctx context.Context, connection *tls.Conn, credential string, mode ReplicationAuthMode, initiator, acceptor wireHello, role, proof string) error {
	expected, err := r.authenticationProof(ctx, connection, credential, mode, initiator, acceptor, role)
	if err != nil {
		return err
	}
	if mode == ReplicationAuthMTLS {
		if proof != "" {
			return errors.New("replication: unexpected mTLS proof")
		}
		return nil
	}
	got, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return errors.New("replication: invalid authentication proof")
	}
	want, _ := base64.RawURLEncoding.DecodeString(expected)
	if !hmac.Equal(got, want) {
		return errors.New("replication: PSK proof rejected")
	}
	return nil
}

func (r *replicationRuntime) consumeAuthenticationReplay(peer, session, initiatorNonce, acceptorNonce string) bool {
	now := time.Now()
	key := peer + "\x00" + session + "\x00" + initiatorNonce + "\x00" + acceptorNonce
	r.mu.Lock()
	defer r.mu.Unlock()
	for existing, seen := range r.authReplay {
		if now.Sub(seen) > replicationReplayWindow {
			delete(r.authReplay, existing)
		}
	}
	if _, exists := r.authReplay[key]; exists {
		return false
	}
	r.authReplay[key] = now
	return true
}
