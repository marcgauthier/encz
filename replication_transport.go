package sqliteseal

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	sqlite3 "github.com/mattn/go-sqlite3"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

const replicationProtocolVersion = 2

type wireHello struct {
	Protocol           int    `json:"protocol"`
	NodeUUID           string `json:"node_uuid"`
	IncarnationUUID    string `json:"incarnation_uuid"`
	Domain             string `json:"domain"`
	Level              int    `json:"level"`
	SchemaVersion      int64  `json:"schema_version"`
	SchemaHash         string `json:"schema_hash"`
	MembershipEpoch    int64  `json:"membership_epoch"`
	MembershipHash     string `json:"membership_hash"`
	Nonce              string `json:"nonce"`
	SessionUUID        string `json:"session_uuid,omitempty"`
	SentAtUTC          string `json:"sent_at_utc"`
	AdministrativeTest bool   `json:"administrative_test,omitempty"`
	Proof              string `json:"proof,omitempty"`
}
type wireValue struct {
	Present bool   `json:"present"`
	Type    string `json:"type"`
	Value   string `json:"value,omitempty"`
}
type wireEvent struct {
	ChangeUUID         string               `json:"change_uuid"`
	OriginNodeUUID     string               `json:"origin_node_uuid"`
	OriginCounter      int64                `json:"origin_counter"`
	Operation          string               `json:"operation"`
	TableName          string               `json:"table_name"`
	RowKeyJSON         string               `json:"row_key_json"`
	ChangedFieldsJSON  string               `json:"changed_fields_json"`
	ExplicitRecreation bool                 `json:"is_explicit_recreation"`
	HLCPhysicalUS      int64                `json:"hlc_physical_utc_us"`
	HLCLogical         int64                `json:"hlc_logical"`
	SchemaVersion      int64                `json:"schema_version"`
	SchemaHash         string               `json:"schema_hash"`
	Domain             string               `json:"replication_domain"`
	CreatedAtUTC       string               `json:"created_at_utc"`
	PayloadHash        string               `json:"payload_hash"`
	Values             map[string]wireValue `json:"values"`
	StoredValuesJSON   string               `json:"-"`
}
type wireCursor struct {
	OriginNodeUUID          string `json:"origin_node_uuid"`
	ContiguousCounter       int64  `json:"contiguous_counter"`
	HighestSeenCounter      int64  `json:"highest_seen_counter"`
	EarliestRetainedCounter int64  `json:"earliest_retained_counter,omitempty"`
	BaselineSnapshotUUID    string `json:"baseline_snapshot_uuid,omitempty"`
	RequiresSnapshot        bool   `json:"requires_snapshot,omitempty"`
}
type wireGap struct {
	OriginNodeUUID string `json:"origin_node_uuid"`
	StartCounter   int64  `json:"start_counter"`
	EndCounter     int64  `json:"end_counter"`
}
type wireSnapshotChunk struct {
	SnapshotUUID string `json:"snapshot_uuid"`
	Offset       int64  `json:"offset"`
	Data         []byte `json:"data,omitempty"`
	ChunkHash    string `json:"chunk_hash,omitempty"`
	Done         bool   `json:"done,omitempty"`
}
type wireMessage struct {
	Type             string                       `json:"type"`
	Hello            *wireHello                   `json:"hello,omitempty"`
	Cursors          []wireCursor                 `json:"cursors,omitempty"`
	Gaps             []wireGap                    `json:"gaps,omitempty"`
	Events           []wireEvent                  `json:"events,omitempty"`
	More             bool                         `json:"more,omitempty"`
	SnapshotRequired bool                         `json:"snapshot_required,omitempty"`
	Snapshot         *replicationSnapshotManifest `json:"snapshot,omitempty"`
	SnapshotChunk    *wireSnapshotChunk           `json:"snapshot_chunk,omitempty"`
	Schemas          []wireSchemaDeclaration      `json:"schemas,omitempty"`
	SchemaPending    bool                         `json:"schema_pending,omitempty"`
	Error            string                       `json:"error,omitempty"`
}
type peerRuntimeConfig struct {
	NodeUUID, IncarnationUUID, Address, CredentialName  string
	Role                                                ReplicationConnectionRole
	Auth                                                ReplicationAuthMode
	Enabled, ReconnectEnabled                           bool
	ConnectTimeout, HeartbeatInterval, HeartbeatTimeout time.Duration
	ReconnectInitial, ReconnectMaximum                  time.Duration
	ReconnectJitterPercent                              int
	NextRetryAt                                         *time.Time
	ConsecutiveFailures                                 int64
	MaxSnapshotBytes                                    int64
	MaxCompressed, MaxUncompressed, MaxBatch            int
}

func (r *replicationRuntime) start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	var enabled int
	var localAddr, credential string
	if err := r.db.QueryRow(`SELECT l.network_enabled,coalesce(n.address,''),coalesce(n.credential_name,'') FROM replication_local_state l JOIN replication_nodes n ON n.node_uuid=l.local_node_uuid`).Scan(&enabled, &localAddr, &credential); err != nil || enabled == 0 {
		return
	}
	if r.opts == nil || r.opts.Credentials == nil {
		_, _ = r.db.Exec(`UPDATE replication_local_state SET blocked_reason='replication credential provider is unavailable'`)
		return
	}
	if localAddr != "" && len(r.listeners) == 0 {
		cfg, err := r.opts.Credentials.TLSConfig(r.ctx, credential, true)
		if err != nil {
			r.blocked(err)
			return
		}
		raw, err := net.Listen("tcp", localAddr)
		if err != nil {
			r.blocked(err)
			return
		}
		ln := tls.NewListener(raw, cfg.Clone())
		r.listeners = append(r.listeners, ln)
		actual := raw.Addr().String()
		_, _ = r.db.Exec(`UPDATE replication_nodes SET address=?,updated_at_utc=sqliteseal_utc_now() WHERE is_local=1`, actual)
		r.wg.Add(1)
		go r.acceptLoop(ln)
	}
	rows, err := r.db.Query(`SELECT peer_node_uuid FROM replication_peer_connections WHERE enabled=1 AND connection_role='dial'`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var nodeUUID string
		if rows.Scan(&nodeUUID) != nil {
			continue
		}
		if r.dialers[nodeUUID] == nil {
			control := newReplicationDialerControl()
			r.dialers[nodeUUID] = control
			r.wg.Add(1)
			go r.dialLoop(nodeUUID, control)
		}
	}
}

func (r *replicationRuntime) loadPeerRuntimeConfig(ctx context.Context, nodeUUID string) (peerRuntimeConfig, error) {
	var p peerRuntimeConfig
	var enabled, reconnectEnabled int
	var connectTimeoutMS, heartbeatIntervalMS, heartbeatTimeoutMS, reconnectInitialMS, reconnectMaximumMS int64
	var nextRetry sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT p.peer_node_uuid,n.incarnation_uuid,p.address,n.credential_name,p.connection_role,n.auth_mode,p.enabled,p.reconnect_enabled,p.connect_timeout_ms,p.heartbeat_interval_ms,p.heartbeat_timeout_ms,p.reconnect_initial_ms,p.reconnect_max_ms,p.reconnect_jitter_percent,p.next_retry_at_utc,p.consecutive_failures,p.max_snapshot_bytes,p.max_compressed_frame_bytes,p.max_uncompressed_message_bytes,p.max_events_per_batch
		FROM replication_peer_connections p JOIN replication_nodes n ON n.node_uuid=p.peer_node_uuid WHERE p.peer_node_uuid=?`, nodeUUID).
		Scan(&p.NodeUUID, &p.IncarnationUUID, &p.Address, &p.CredentialName, &p.Role, &p.Auth, &enabled, &reconnectEnabled, &connectTimeoutMS, &heartbeatIntervalMS, &heartbeatTimeoutMS, &reconnectInitialMS, &reconnectMaximumMS, &p.ReconnectJitterPercent, &nextRetry, &p.ConsecutiveFailures, &p.MaxSnapshotBytes, &p.MaxCompressed, &p.MaxUncompressed, &p.MaxBatch)
	if err != nil {
		return p, err
	}
	p.Enabled = enabled == 1
	p.ReconnectEnabled = reconnectEnabled == 1
	p.ConnectTimeout = time.Duration(connectTimeoutMS) * time.Millisecond
	p.HeartbeatInterval = time.Duration(heartbeatIntervalMS) * time.Millisecond
	p.HeartbeatTimeout = time.Duration(heartbeatTimeoutMS) * time.Millisecond
	p.ReconnectInitial = time.Duration(reconnectInitialMS) * time.Millisecond
	p.ReconnectMaximum = time.Duration(reconnectMaximumMS) * time.Millisecond
	if nextRetry.Valid {
		retryAt, parseErr := parseReplicationTimestamp(nextRetry.String)
		if parseErr != nil {
			return p, fmt.Errorf("%w: invalid next retry timestamp", ErrReplicationInvalidConfig)
		}
		p.NextRetryAt = &retryAt
	}
	if p.ConnectTimeout <= 0 || p.HeartbeatInterval <= 0 || p.HeartbeatTimeout <= p.HeartbeatInterval ||
		p.ReconnectInitial <= 0 || p.ReconnectMaximum < p.ReconnectInitial || p.ReconnectJitterPercent < 0 || p.ReconnectJitterPercent > 100 ||
		p.ConsecutiveFailures < 0 || p.MaxSnapshotBytes <= 0 || p.MaxCompressed <= 0 || p.MaxUncompressed < p.MaxCompressed || p.MaxBatch <= 0 {
		return p, ErrReplicationInvalidConfig
	}
	return p, nil
}
func (r *replicationRuntime) blocked(err error) {
	_, _ = r.db.Exec(`UPDATE replication_local_state SET blocked_reason=?`, err.Error())
	r.log("replication blocked: %v", err)
}
func (r *replicationRuntime) log(f string, a ...any) {
	if r.opts != nil && r.opts.Logf != nil {
		r.opts.Logf(f, a...)
	}
}
func (r *replicationRuntime) acceptLoop(ln net.Listener) {
	defer r.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer c.Close()
			peer, err := r.handshake(c, false, "")
			if err != nil {
				r.log("replication inbound handshake: %v", err)
				return
			}
			if peer.AdministrativeTest {
				r.log("replication administrative authentication succeeded for %s", peer.NodeUUID)
				return
			}
			config, err := r.loadPeerRuntimeConfig(r.ctx, peer.NodeUUID)
			if err != nil || !config.Enabled || config.Role != ReplicationAccept {
				if err == nil {
					err = ErrReplicationInvalidConfig
				}
				r.log("replication inbound peer configuration: %v", err)
				return
			}
			if err = configureReplicationTCPKeepalive(c, config.HeartbeatInterval, config.HeartbeatTimeout); err != nil {
				r.log("replication TCP keepalive for %s: %v", peer.NodeUUID, err)
			}
			r.setPeerAuthenticated(peer.NodeUUID, peer.SessionUUID)
			r.trackConnection(peer.NodeUUID, c, true)
			defer r.trackConnection(peer.NodeUUID, c, false)
			sessionErr := r.serveSession(newReplicationLivenessConn(c, config.HeartbeatTimeout), peer, config)
			r.setPeerDisconnected(peer.NodeUUID, peer.SessionUUID, sessionErr)
		}()
	}
}
func (r *replicationRuntime) dialLoop(nodeUUID string, control *replicationDialerControl) {
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		if r.dialers[nodeUUID] == control {
			delete(r.dialers, nodeUUID)
		}
		r.mu.Unlock()
		if r.ctx.Err() != nil {
			return
		}
		config, err := r.loadPeerRuntimeConfig(r.ctx, nodeUUID)
		if err == nil && config.Enabled && config.ReconnectEnabled && config.Role == ReplicationDial {
			r.start()
		}
	}()
	for {
		if r.ctx.Err() != nil {
			return
		}
		if !r.networkIsEnabled() {
			if !waitForReplicationDialerWake(r.ctx, control) {
				return
			}
			continue
		}
		p, err := r.loadPeerRuntimeConfig(r.ctx, nodeUUID)
		if err != nil {
			r.setPeerStateIfNotConnected(nodeUUID, "disconnected", sanitizedReplicationConnectionError(err))
			return
		}
		if !p.Enabled || !p.ReconnectEnabled || p.Role != ReplicationDial {
			return
		}
		next, err := r.clampPersistedRetry(p, time.Now().UTC())
		if err != nil {
			r.setPeerStateIfNotConnected(nodeUUID, "disconnected", sanitizedReplicationConnectionError(err))
			if !r.fallbackRetryWait(control, p) {
				return
			}
			continue
		}
		if wait := time.Until(next); wait > 0 {
			if !waitForReplicationDialer(r.ctx, control, wait) {
				return
			}
			continue
		}
		revision := r.controlRevision(control)
		r.setPeerConnecting(p.NodeUUID)
		tlsCfg, err := r.opts.Credentials.TLSConfig(r.ctx, p.CredentialName, false)
		var sessionUUID string
		if err == nil {
			d := net.Dialer{Timeout: p.ConnectTimeout}
			raw, dialErr := d.DialContext(r.ctx, "tcp", p.Address)
			err = dialErr
			if err == nil {
				if keepaliveErr := configureReplicationTCPKeepalive(raw, p.HeartbeatInterval, p.HeartbeatTimeout); keepaliveErr != nil {
					r.log("replication TCP keepalive for %s: %v", p.NodeUUID, keepaliveErr)
				}
				tc := tls.Client(raw, tlsCfg.Clone())
				var peer wireHello
				peer, err = r.handshake(tc, true, p.NodeUUID)
				if err == nil {
					sessionUUID = peer.SessionUUID
					r.trackConnection(p.NodeUUID, tc, true)
					r.setPeerAuthenticated(p.NodeUUID, sessionUUID)
					err = r.clientSession(newReplicationLivenessConn(tc, p.HeartbeatTimeout), peer, p, control)
					r.trackConnection(p.NodeUUID, tc, false)
					if err == nil {
						err = errors.New("replication: session ended")
					}
				}
				_ = tc.Close()
			}
		}
		if err == nil {
			err = errors.New("replication: connection attempt ended")
		}
		if r.suppressDialFailure(nodeUUID, control, revision) {
			continue
		}
		_, recorded, scheduleErr := r.recordDialFailure(p, sessionUUID, err)
		if scheduleErr != nil {
			r.log("replication retry scheduling for %s: %v", p.NodeUUID, scheduleErr)
			if !r.fallbackRetryWait(control, p) {
				return
			}
			continue
		}
		if !recorded {
			continue
		}
	}
}
func (r *replicationRuntime) trackConnection(peer string, c net.Conn, add bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		if old := r.connections[peer]; old != nil && old != c {
			_ = old.Close()
		}
		r.connections[peer] = c
	} else if old := r.connections[peer]; old == c || c == nil {
		delete(r.connections, peer)
	}
}
func (r *replicationRuntime) setPeerAuthenticated(peer, session string) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state='connected',last_session_uuid=?,last_error=NULL,connected_at_utc=sqliteseal_utc_now(),next_retry_at_utc=NULL,consecutive_failures=0,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, session, peer)
}
func (r *replicationRuntime) setPeerState(peer, state, lastErr string) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state=?,last_error=?,connected_at_utc=CASE WHEN ?='connected' THEN sqliteseal_utc_now() ELSE connected_at_utc END,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, state, lastErr, state, peer)
}
func (r *replicationRuntime) setPeerStateIfNotConnected(peer, state, lastErr string) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state=?,last_error=?,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=? AND session_state!='connected'`, state, lastErr, peer)
}
func (r *replicationRuntime) setPeerDisconnected(peer, session string, sessionErr error) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state='disconnected',last_error=?,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=? AND session_state IN('connected','schema_pending') AND last_session_uuid=?`, sanitizedReplicationConnectionError(sessionErr), peer, session)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (r *replicationRuntime) clientSession(c net.Conn, peer wireHello, p peerRuntimeConfig, control *replicationDialerControl) error {
	ticker := time.NewTicker(p.HeartbeatInterval)
	defer ticker.Stop()
	for {
		if err := r.syncCycle(c, peer.NodeUUID, p); err != nil {
			return err
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-control.wake:
		case <-ticker.C:
		}
	}
}
func (r *replicationRuntime) syncCycle(c net.Conn, peer string, p peerRuntimeConfig) error {
	if p.MaxSnapshotBytes <= 0 {
		p.MaxSnapshotBytes = defaultMaximumReplicationSnapshotBytes
	}
	pending, err := r.schemaSyncClient(c, p)
	if err != nil {
		r.setPeerState(peer, "schema_pending", err.Error())
		return err
	}
	if pending {
		r.setPeerState(peer, "schema_pending", "schema agreement is pending")
		return nil
	}
	r.setPeerState(peer, "connected", "")
	vector, err := r.buildCursorVector(r.ctx)
	if err != nil {
		return err
	}
	gaps, err := r.localGapRequests(r.ctx, peer)
	if err != nil {
		return err
	}
	if err = writeReplicationFrame(c, wireMessage{Type: "sync_request", Cursors: vector, Gaps: gaps}, p.MaxCompressed); err != nil {
		return err
	}
	resp, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if resp.Type != "sync_response" {
		return errors.New("replication: invalid synchronization response")
	}
	if err = r.persistPeerCursorVector(r.ctx, peer, resp.Cursors); err != nil {
		return err
	}
	if resp.SnapshotRequired {
		if resp.Snapshot == nil {
			return ErrReplicationSnapshotRequired
		}
		temporaryPath, fetchErr := r.requestSnapshotChunks(c, *resp.Snapshot, p.MaxSnapshotBytes, p.MaxCompressed, p.MaxUncompressed)
		if fetchErr != nil {
			return fetchErr
		}
		if err = r.installSessionSnapshotFile(r.ctx, peer, *resp.Snapshot, temporaryPath, p.MaxSnapshotBytes); err != nil {
			return err
		}
		return nil
	}
	if err = r.applyRemoteEvents(r.ctx, peer, resp.Events); err != nil {
		return err
	}
	if err = r.recoverDeferredEvents(r.ctx); err != nil {
		return err
	}
	vector, err = r.buildCursorVector(r.ctx)
	if err != nil {
		return err
	}
	var local string
	if err = r.db.QueryRowContext(r.ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return err
	}
	peerCursor := cursorFromVector(resp.Cursors, local)
	snapshotRequired, err := r.localHistoryUnavailable(r.ctx, peerCursor.ContiguousCounter, resp.Gaps)
	if err != nil {
		return err
	}
	localEvents, err := r.loadOriginEvents(r.ctx, peerCursor.ContiguousCounter, p.MaxBatch)
	if err != nil {
		return err
	}
	var uploadManifest *replicationSnapshotManifest
	var uploadSnapshot *replicationSnapshotFile
	if snapshotRequired {
		snapshot, snapshotErr := r.createTransferSnapshotFile(r.ctx, p.MaxSnapshotBytes)
		if snapshotErr != nil {
			return snapshotErr
		}
		uploadSnapshot = &snapshot
		uploadManifest = &snapshot.Manifest
	}
	push := wireMessage{Type: "sync_push", Cursors: vector, Events: localEvents, Gaps: resp.Gaps, More: moreOriginEvents(localEvents, vector, local), SnapshotRequired: snapshotRequired, Snapshot: uploadManifest}
	if err = writeReplicationFrame(c, push, p.MaxCompressed); err != nil {
		return err
	}
	ack, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
	if err != nil {
		return err
	}
	if snapshotRequired && ack.Type == "snapshot_fetch" {
		ack, err = answerSnapshotFetch(c, ack, *uploadSnapshot, p.MaxCompressed, p.MaxUncompressed)
		if err != nil {
			return err
		}
	}
	if ack.Error != "" {
		return errors.New(ack.Error)
	}
	if ack.Type != "sync_ack" {
		return errors.New("replication: invalid synchronization acknowledgment")
	}
	if err = r.persistPeerCursorVector(r.ctx, peer, ack.Cursors); err != nil {
		return err
	}
	return r.recordPeerAck(peer, cursorFromVector(ack.Cursors, local).ContiguousCounter)
}
func (r *replicationRuntime) serveSession(c net.Conn, peer wireHello, p peerRuntimeConfig) error {
	if p.MaxSnapshotBytes <= 0 {
		p.MaxSnapshotBytes = defaultMaximumReplicationSnapshotBytes
	}
	schemaReady := false
	for {
		msg, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
		if err != nil {
			return err
		}
		switch msg.Type {
		case "schema_request":
			if err = r.mergeSchemaDeclarations(r.ctx, msg.Schemas); err != nil {
				_ = writeReplicationFrame(c, wireMessage{Type: "schema_response", Error: err.Error()}, p.MaxCompressed)
				return err
			}
			pending, reconcileErr := r.reconcileSchemas(r.ctx)
			declarations, loadErr := r.loadSchemaDeclarations(r.ctx)
			if reconcileErr == nil {
				reconcileErr = loadErr
			}
			response := wireMessage{Type: "schema_response", Schemas: declarations, SchemaPending: pending}
			if reconcileErr != nil {
				response.Error = reconcileErr.Error()
				response.SchemaPending = true
			}
			schemaReady = !response.SchemaPending
			if schemaReady {
				r.setPeerState(peer.NodeUUID, "connected", "")
			} else {
				r.setPeerState(peer.NodeUUID, "schema_pending", response.Error)
			}
			if err = writeReplicationFrame(c, response, p.MaxCompressed); err != nil {
				return err
			}
			continue
		case "sync_request":
			if !schemaReady {
				err = errors.New("replication: schema agreement required before synchronization")
				_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: err.Error()}, p.MaxCompressed)
				return err
			}
			if err = r.persistPeerCursorVector(r.ctx, peer.NodeUUID, msg.Cursors); err != nil {
				_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: err.Error()}, p.MaxCompressed)
				return err
			}
			var local string
			if err = r.db.QueryRowContext(r.ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
				return err
			}
			requested := cursorFromVector(msg.Cursors, local)
			snapshotRequired, e := r.localHistoryUnavailable(r.ctx, requested.ContiguousCounter, msg.Gaps)
			vector, vectorErr := r.buildCursorVector(r.ctx)
			if e == nil {
				e = vectorErr
			}
			var events []wireEvent
			var snapshotManifest *replicationSnapshotManifest
			var snapshotFile *replicationSnapshotFile
			if e == nil && !snapshotRequired {
				events, e = r.loadOriginEvents(r.ctx, requested.ContiguousCounter, 500)
			} else if e == nil {
				snapshot, snapshotErr := r.createTransferSnapshotFile(r.ctx, p.MaxSnapshotBytes)
				if snapshotErr != nil {
					e = snapshotErr
				} else {
					snapshotFile = &snapshot
					snapshotManifest = &snapshot.Manifest
				}
			}
			gaps, gapErr := r.localGapRequests(r.ctx, peer.NodeUUID)
			if e == nil {
				e = gapErr
			}
			if e != nil {
				_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: e.Error()}, p.MaxCompressed)
			} else {
				e = writeReplicationFrame(c, wireMessage{Type: "sync_response", Cursors: vector, Gaps: gaps, Events: events, More: moreOriginEvents(events, vector, local), SnapshotRequired: snapshotRequired, Snapshot: snapshotManifest}, p.MaxCompressed)
			}
			if e != nil {
				return e
			}
			if snapshotRequired {
				if e = provideSnapshotChunks(c, *snapshotFile, p.MaxCompressed, p.MaxUncompressed); e != nil {
					return e
				}
			}
		case "sync_push":
			if err = r.persistPeerCursorVector(r.ctx, peer.NodeUUID, msg.Cursors); err != nil {
				_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: err.Error()}, p.MaxCompressed)
				return err
			}
			if msg.SnapshotRequired {
				if msg.Snapshot == nil {
					return errors.New("replication: snapshot offer is missing")
				}
				temporaryPath, receiveErr := r.requestSnapshotChunks(c, *msg.Snapshot, p.MaxSnapshotBytes, p.MaxCompressed, p.MaxUncompressed)
				if receiveErr != nil {
					return receiveErr
				}
				if err = r.installSessionSnapshotFile(r.ctx, peer.NodeUUID, *msg.Snapshot, temporaryPath, p.MaxSnapshotBytes); err != nil {
					return err
				}
			} else {
				if err = r.applyRemoteEvents(r.ctx, peer.NodeUUID, msg.Events); err != nil {
					_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: err.Error()}, p.MaxCompressed)
					return err
				}
				if err = r.recoverDeferredEvents(r.ctx); err != nil {
					return err
				}
			}
			vector, e := r.buildCursorVector(r.ctx)
			if e != nil {
				return e
			}
			if err = writeReplicationFrame(c, wireMessage{Type: "sync_ack", Cursors: vector}, p.MaxCompressed); err != nil {
				return err
			}
		default:
			return errors.New("replication: unsupported message")
		}
	}
}
func writeReplicationFrame(w io.Writer, msg wireMessage, max int) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err = gz.Write(raw); err != nil {
		return err
	}
	if err = gz.Close(); err != nil {
		return err
	}
	if compressed.Len() == 0 || compressed.Len() > max {
		return errors.New("replication: frame exceeds limit")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(compressed.Len()))
	if _, err = w.Write(h[:]); err != nil {
		return err
	}
	_, err = w.Write(compressed.Bytes())
	return err
}
func readReplicationFrame(r io.Reader, maxCompressed, maxRaw int) (wireMessage, error) {
	var msg wireMessage
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return msg, err
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n <= 0 || n > maxCompressed {
		return msg, errors.New("replication: invalid frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return msg, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return msg, err
	}
	raw, err := io.ReadAll(io.LimitReader(gz, int64(maxRaw)+1))
	_ = gz.Close()
	if err != nil {
		return msg, err
	}
	if len(raw) > maxRaw {
		return msg, errors.New("replication: decompressed frame exceeds limit")
	}
	if err = validateReplicationJSON(raw); err != nil {
		return msg, err
	}
	dec := json.NewDecoder(bufio.NewReader(bytes.NewReader(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&msg); err != nil {
		return msg, err
	}
	canonical, err := json.Marshal(msg)
	if err != nil {
		return msg, err
	}
	if !bytes.Equal(raw, canonical) {
		return msg, errors.New("replication: non-canonical JSON envelope")
	}
	return msg, nil
}

func (r *replicationRuntime) descriptor(ctx context.Context, table string) (replicationTableDescriptor, error) {
	var raw string
	var d replicationTableDescriptor
	if err := r.db.QueryRowContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors WHERE table_name=?`, table).Scan(&raw); err != nil {
		return d, err
	}
	err := json.Unmarshal([]byte(raw), &d)
	return d, err
}
func encodeWireValue(v any, present bool) wireValue {
	w := wireValue{Present: present}
	switch x := v.(type) {
	case nil:
		w.Type = "null"
	case int64:
		w.Type = "integer"
		w.Value = strconv.FormatInt(x, 10)
	case float64:
		w.Type = "float"
		w.Value = strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		w.Type = "boolean"
		w.Value = strconv.FormatBool(x)
	case []byte:
		if x == nil {
			w.Type = "null"
		} else {
			w.Type = "blob"
			w.Value = base64.RawURLEncoding.EncodeToString(x)
		}
	case string:
		w.Type = "text"
		w.Value = x
	default:
		w.Type = "text"
		w.Value = fmt.Sprint(x)
	}
	return w
}
func decodeWireValue(w wireValue) (any, error) {
	switch w.Type {
	case "null":
		return nil, nil
	case "integer":
		return strconv.ParseInt(w.Value, 10, 64)
	case "float":
		f, e := strconv.ParseFloat(w.Value, 64)
		if e == nil && (math.IsInf(f, 0) || math.IsNaN(f)) {
			e = errors.New("non-finite float")
		}
		return f, e
	case "boolean":
		return strconv.ParseBool(w.Value)
	case "blob":
		return base64.RawURLEncoding.DecodeString(w.Value)
	case "text":
		return w.Value, nil
	default:
		return nil, errors.New("replication: unknown value type")
	}
}
func (r *replicationRuntime) loadOriginEvents(ctx context.Context, since int64, limit int) ([]wireEvent, error) {
	if err := r.updateIdentityGuard(); err != nil {
		return nil, err
	}
	var local string
	if err := r.db.QueryRowContext(ctx, `SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,payload_hash,wire_values_json FROM replication_changes WHERE origin_node_uuid=? AND origin_counter>? AND apply_state IN('applied','ignored') ORDER BY origin_counter LIMIT ?`, local, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wireEvent
	for rows.Next() {
		var e wireEvent
		var recreate int
		var valuesRaw sql.NullString
		if err = rows.Scan(&e.ChangeUUID, &e.OriginNodeUUID, &e.OriginCounter, &e.Operation, &e.TableName, &e.RowKeyJSON, &e.ChangedFieldsJSON, &recreate, &e.HLCPhysicalUS, &e.HLCLogical, &e.SchemaVersion, &e.SchemaHash, &e.Domain, &e.CreatedAtUTC, &e.PayloadHash, &valuesRaw); err != nil {
			return nil, err
		}
		e.ExplicitRecreation = recreate == 1
		if valuesRaw.Valid {
			if err = json.Unmarshal([]byte(valuesRaw.String), &e.Values); err != nil {
				return nil, err
			}
		}
		if !valuesRaw.Valid {
			d, descriptorErr := r.descriptor(ctx, e.TableName)
			if descriptorErr != nil {
				return nil, descriptorErr
			}
			cols := make([]string, 0, len(d.Table.Columns)*2)
			for _, name := range d.Table.Columns {
				cols = append(cols, quoteReplicationIdent(name+"__value"), quoteReplicationIdent(name+"__present"))
			}
			query := `SELECT ` + strings.Join(cols, ",") + ` FROM ` + quoteReplicationIdent(d.DescriptorID+"__replication_changes") + ` WHERE change_uuid=?`
			values := make([]any, len(d.Table.Columns)*2)
			pointers := make([]any, len(values))
			for i := range values {
				pointers[i] = &values[i]
			}
			if descriptorErr = r.db.QueryRowContext(ctx, query, e.ChangeUUID).Scan(pointers...); descriptorErr != nil {
				return nil, descriptorErr
			}
			e.Values = make(map[string]wireValue, len(d.Table.Columns))
			for i, name := range d.Table.Columns {
				present, ok := values[i*2+1].(int64)
				if !ok {
					return nil, errors.New("replication: invalid stored presence marker")
				}
				e.Values[name] = encodeWireValue(values[i*2], present == 1)
			}
		}

		hash, size, hashErr := replicationEventHash(e)
		if hashErr != nil {
			return nil, hashErr
		}
		if hash != e.PayloadHash {
			return nil, fmt.Errorf("replication: local event payload hash mismatch: change=%s stored=%s computed=%s", e.ChangeUUID, e.PayloadHash, hash)
		}
		if size > defaultMaximumEventBytes {
			return nil, errors.New("replication: local event exceeds size limit")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r *replicationRuntime) cursorFor(origin string) (int64, error) {
	var local string
	var v int64
	if err := r.db.QueryRow(`SELECT local_node_uuid FROM replication_local_state`).Scan(&local); err != nil {
		return 0, err
	}
	err := r.db.QueryRow(`SELECT contiguous_counter FROM replication_origin_cursors WHERE tracking_node_uuid=? AND origin_node_uuid=?`, local, origin).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return v, err
}
func compareReplicationVersion(ph, ll int64, origin string, cph, cll int64, corigin string) int {
	if ph < cph {
		return -1
	}
	if ph > cph {
		return 1
	}
	if ll < cll {
		return -1
	}
	if ll > cll {
		return 1
	}
	return strings.Compare(origin, corigin)
}

func (r *replicationRuntime) applyRemoteEvent(ctx context.Context, peer string, e wireEvent) error {
	r.writer.Lock()
	defer r.writer.Unlock()
	return retryReplicationBusy(ctx, func() error {
		return r.applyRemoteEventOnce(ctx, peer, e)
	})
}

func (r *replicationRuntime) applyRemoteEventOnce(ctx context.Context, peer string, e wireEvent) error {
	var domain, schema, local string
	var version int64
	if err := r.db.QueryRowContext(ctx, `SELECT replication_domain,schema_hash,schema_version,local_node_uuid FROM replication_local_state`).Scan(&domain, &schema, &version, &local); err != nil {
		return err
	}
	if e.OriginNodeUUID != peer || e.Domain != domain {
		return errors.New("replication: origin authorization failed")
	}
	d, err := r.descriptor(ctx, e.TableName)
	if err != nil {
		_ = r.recordRejectedEvent(ctx, peer, e, "unknown_table", "")
		return err
	}
	if err = validateWireEvent(d, e, domain, schema, version, defaultMaximumEventBytes); err != nil {
		_ = r.recordRejectedEvent(ctx, peer, e, "invalid_event", "")
		return err
	}
	valuesRaw, _ := json.Marshal(e.Values)
	e.StoredValuesJSON = string(valuesRaw)
	e = expandWireEvent(d, e)
	skew, err := r.maximumFutureSkew(ctx)
	if err != nil {
		return err
	}
	future := e.HLCPhysicalUS > time.Now().UTC().Add(skew).UnixMicro()
	contiguous, err := r.cursorFor(e.OriginNodeUUID)
	if err != nil {
		return err
	}
	deferred := false
	var existing, existingState string
	err = r.db.QueryRowContext(ctx, `SELECT payload_hash,apply_state FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=?`, e.OriginNodeUUID, e.OriginCounter).Scan(&existing, &existingState)
	if err == nil {
		if existing != e.PayloadHash {
			if recordErr := r.recordRejectedEvent(ctx, peer, e, "conflicting_duplicate", existing); recordErr != nil {
				return fmt.Errorf("replication: record conflicting duplicate: %w", recordErr)
			}
			return errors.New("replication: conflicting duplicate event")
		}
		if existingState == "pending" || existingState == "quarantined" {
			if existingState == "quarantined" && future {
				return fmt.Errorf("%w: future_clock", ErrReplicationEventQuarantined)
			}
			if existingState == "pending" && e.OriginCounter > contiguous+1 {
				dependencyGap, gapErr := r.foreignKeyDependencyGap(ctx, e.OriginNodeUUID, contiguous+1, e.OriginCounter-1)
				if gapErr != nil {
					return gapErr
				}
				if !dependencyGap {
					return nil
				}
			}
			deferred = true
		} else {
			tx, beginErr := r.db.BeginTx(ctx, nil)
			if beginErr != nil {
				return beginErr
			}
			defer tx.Rollback()
			now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
			if advanceErr := advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); advanceErr != nil {
				return advanceErr
			}
			return tx.Commit()
		}
	} else if err != sql.ErrNoRows {
		return err
	}
	if future {
		return r.quarantineRemoteEvent(ctx, peer, local, d, e, "future_clock")
	}
	if e.OriginCounter > contiguous+1 {
		dependencyGap, gapErr := r.foreignKeyDependencyGap(ctx, e.OriginNodeUUID, contiguous+1, e.OriginCounter-1)
		if gapErr != nil {
			return gapErr
		}
		if !dependencyGap {
			return r.deferOutOfOrderEvent(ctx, peer, local, d, e)
		}
	}
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var restore func()
	if err = conn.Raw(func(raw any) error {
		sc, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return ErrReplicationNotReady
		}
		var x error
		restore, x = setReplicationConnectionMode(sc, "remote")
		return x
	}); err != nil {
		return err
	}
	defer restore()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	if !deferred {
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,source_node_uuid,payload_hash,apply_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`, e.ChangeUUID, e.OriginNodeUUID, e.OriginCounter, e.Operation, e.TableName, e.RowKeyJSON, e.ChangedFieldsJSON, boolInt(e.ExplicitRecreation), e.HLCPhysicalUS, e.HLCLogical, e.SchemaVersion, e.SchemaHash, e.Domain, e.CreatedAtUTC, now, peer, e.PayloadHash); err != nil {
			return err
		}
		if err = persistWirePayload(ctx, tx, d, e); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `SAVEPOINT sqliteseal_materialize`); err != nil {
		return err
	}
	_, args, err := wireKey(d, e)
	if err != nil {
		return err
	}
	where := []string{}
	for _, k := range d.Table.PrimaryKeyColumns {
		where = append(where, quoteReplicationIdent(k)+"=?")
	}
	whereSQL := strings.Join(where, " AND ")
	var rowPH, rowLL int64
	var rowOrigin, rowState string
	rowErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid,row_state FROM replication_row_versions WHERE table_name=? AND row_key_json=?`, e.TableName, e.RowKeyJSON).Scan(&rowPH, &rowLL, &rowOrigin, &rowState)
	rowCmp := 1
	if rowErr == nil {
		rowCmp = compareReplicationVersion(e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, rowPH, rowLL, rowOrigin)
	} else if rowErr != sql.ErrNoRows {
		return rowErr
	}
	applied := false
	if e.Operation == "delete" {
		if rowCmp > 0 {
			if _, err = tx.ExecContext(ctx, `DELETE FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+whereSQL, args...); err != nil {
				if handled, result := handleManagedConstraint(ctx, tx, local, d, e, now, deferred, err); handled {
					return result
				}
				return err
			}
			applied = true
		}
	} else {
		inserted := false
		if (rowState == "deleted" && (rowCmp <= 0 || !e.ExplicitRecreation)) || (rowState == "unique_deleted" && rowCmp <= 0) {
			rowCmp = -1
		} else {
			var exists int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+whereSQL, args...).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 && e.Operation == "update" {
				if err = insertRemoteWireRow(ctx, tx, d, e); err != nil {
					if handled, result := handleManagedConstraint(ctx, tx, local, d, e, now, deferred, err); handled {
						return result
					}
					if !isReplicationConstraint(err) {
						return err
					}
					if deferred {
						return nil
					}
					if _, err = tx.ExecContext(ctx, `UPDATE replication_changes SET quarantine_reason='missing_base_row' WHERE change_uuid=?`, e.ChangeUUID); err != nil {
						return err
					}
					if err = advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); err != nil {
						return err
					}
					return tx.Commit()
				}
				exists = 1
				inserted = true
				applied = true
			}
			if exists == 0 && e.Operation == "insert" {
				if err = insertRemoteWireRow(ctx, tx, d, e); err != nil {
					if handled, result := handleManagedConstraint(ctx, tx, local, d, e, now, deferred, err); handled {
						return result
					}
					return err
				}
				exists = 1
				inserted = true
				applied = true
			}
			if exists > 0 {
				for _, n := range d.Table.Columns {
					w := e.Values[n]
					if !w.Present {
						continue
					}
					if !inserted {
						var ph, ll int64
						var origin string
						verErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid FROM replication_field_versions WHERE table_name=? AND row_key_json=? AND field_name=?`, e.TableName, e.RowKeyJSON, n).Scan(&ph, &ll, &origin)
						if verErr != nil && verErr != sql.ErrNoRows {
							return verErr
						}
						if verErr == nil && compareReplicationVersion(e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, ph, ll, origin) <= 0 {
							continue
						}
					}
					v, er := decodeWireValue(w)
					if er != nil {
						return er
					}
					if !inserted {
						if _, er = tx.ExecContext(ctx, `UPDATE `+quoteReplicationIdent(e.TableName)+` SET `+quoteReplicationIdent(n)+`=? WHERE `+whereSQL, append([]any{v}, args...)...); er != nil {
							if handled, result := handleManagedConstraint(ctx, tx, local, d, e, now, deferred, er); handled {
								return result
							}
							return er
						}
					}
					_, er = tx.ExecContext(ctx, `INSERT INTO replication_field_versions VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json,field_name) DO UPDATE SET winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, e.RowKeyJSON, n, e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, e.ChangeUUID, e.CreatedAtUTC, nil, now)
					if er != nil {
						return er
					}
					applied = true
				}
			}
		}
	}
	if rowCmp > 0 {
		state := "live"
		if e.Operation == "delete" {
			state = "deleted"
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_row_versions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(table_name,row_key_json) DO UPDATE SET row_state=excluded.row_state,winner_hlc_physical_utc_us=excluded.winner_hlc_physical_utc_us,winner_hlc_logical=excluded.winner_hlc_logical,winner_origin_node_uuid=excluded.winner_origin_node_uuid,winner_change_uuid=excluded.winner_change_uuid,winner_changed_at_utc=excluded.winner_changed_at_utc,updated_at_utc=excluded.updated_at_utc`, e.TableName, e.RowKeyJSON, state, e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, e.ChangeUUID, e.CreatedAtUTC, now); err != nil {
			return err
		}
	}
	state := "ignored"
	if applied {
		state = "applied"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=NULL WHERE change_uuid=?`, state, e.ChangeUUID); err != nil {
		return err
	}
	if err = mergeRemoteHLC(ctx, tx, e.HLCPhysicalUS, e.HLCLogical, time.Now().UTC().UnixMicro(), now); err != nil {
		return err
	}
	if err = advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (r *replicationRuntime) foreignKeyDependencyGap(ctx context.Context, origin string, first, last int64) (bool, error) {
	if last < first {
		return true, nil
	}
	var count int64
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes WHERE origin_node_uuid=? AND origin_counter BETWEEN ? AND ? AND apply_state='pending' AND quarantine_reason='foreign_key_dependency'`, origin, first, last).Scan(&count)
	return count == last-first+1, err
}

func handleManagedConstraint(ctx context.Context, tx *sql.Tx, local string, d replicationTableDescriptor, e wireEvent, now string, deferred bool, constraintErr error) (bool, error) {
	if d.Table.ConstraintPolicy != ReplicationConstraintsManaged {
		return false, nil
	}
	reason := replicationConstraintReason(constraintErr)
	if reason == "" {
		return false, nil
	}
	if reason == "unique_conflict" {
		return materializeManagedUniqueLWW(ctx, tx, local, d, e, now, constraintErr)
	}
	if deferred {
		return true, nil
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO sqliteseal_materialize`); err != nil {
		return true, err
	}
	if _, err := tx.ExecContext(ctx, `RELEASE sqliteseal_materialize`); err != nil {
		return true, err
	}
	state := "pending"
	if _, err := tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=?,quarantine_reason=? WHERE change_uuid=?`, state, reason, e.ChangeUUID); err != nil {
		return true, err
	}
	if err := advanceRemoteCursor(ctx, tx, local, e.OriginNodeUUID, e.OriginCounter, now); err != nil {
		return true, err
	}
	return true, tx.Commit()
}

func (r *replicationRuntime) recordRejectedEvent(ctx context.Context, peer string, e wireEvent, reason, existingHash string) error {
	evidence := []byte(fmt.Sprintf(
		`{"existing_payload_hash":%q,"received_payload_hash":%q}`,
		existingHash,
		e.PayloadHash,
	))
	if len(evidence) > 4096 {
		evidence = evidence[:4096]
	}
	hash := sha256.Sum256(evidence)
	_, err := r.db.ExecContext(ctx, `INSERT INTO replication_rejected_events(
		rejection_uuid,received_from_node_uuid,claimed_change_uuid,
		claimed_origin_node_uuid,claimed_origin_counter,evidence_hash,
		bounded_evidence,reason_code,recorded_at_utc
	) VALUES(sqliteseal_uuid(),?,?,?,?,?,?,?,sqliteseal_utc_now())`,
		peer, e.ChangeUUID, e.OriginNodeUUID, e.OriginCounter,
		fmt.Sprintf("%x", hash[:]), evidence, reason,
	)
	return err
}

func expandWireEvent(d replicationTableDescriptor, e wireEvent) wireEvent {
	for _, name := range d.Table.Columns {
		if _, ok := e.Values[name]; !ok {
			e.Values[name] = wireValue{Present: false, Type: "null"}
		}
	}
	return e
}
func persistWirePayload(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, e wireEvent) error {
	if e.StoredValuesJSON != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE replication_changes SET wire_values_json=? WHERE change_uuid=?`, e.StoredValuesJSON, e.ChangeUUID); err != nil {
			return err
		}
	}
	cols := []string{"change_uuid", "field_versions_json"}
	marks := []string{"?", "?"}
	args := []any{e.ChangeUUID, "{}"}
	for _, n := range d.Table.Columns {
		w := e.Values[n]
		v, err := decodeWireValue(w)
		if err != nil {
			return err
		}
		cols = append(cols, n+"__value", n+"__present")
		marks = append(marks, "?", "?")
		args = append(args, v, boolInt(w.Present))
	}
	for i := range cols {
		cols[i] = quoteReplicationIdent(cols[i])
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(d.DescriptorID+"__replication_changes")+`(`+strings.Join(cols, ",")+`) VALUES(`+strings.Join(marks, ",")+`)`, args...)
	return err
}
func wireKey(d replicationTableDescriptor, e wireEvent) (map[string]any, []any, error) {
	dec := json.NewDecoder(strings.NewReader(e.RowKeyJSON))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, nil, err
	}
	args := []any{}
	for _, n := range d.Table.PrimaryKeyColumns {
		v, ok := m[n]
		if !ok {
			return nil, nil, errors.New("replication: incomplete row key")
		}
		if num, ok := v.(json.Number); ok {
			if i, err := num.Int64(); err == nil {
				v = i
			} else {
				v = num.String()
			}
		}
		args = append(args, v)
	}
	return m, args, nil
}
func advanceRemoteCursor(ctx context.Context, tx *sql.Tx, local, origin string, counter int64, now string) error {
	var contiguous, highest int64
	err := tx.QueryRowContext(ctx, `SELECT contiguous_counter,highest_seen_counter FROM replication_origin_cursors WHERE tracking_node_uuid=? AND origin_node_uuid=?`, local, origin).Scan(&contiguous, &highest)
	if err == sql.ErrNoRows {
		contiguous = 0
		highest = 0
	} else if err != nil {
		return err
	}
	if counter > highest {
		highest = counter
	}
	for {
		var exists int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=? AND apply_state IN('applied','ignored')`, origin, contiguous+1).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			break
		}
		contiguous++
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?,?,NULL,0,?) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET contiguous_counter=excluded.contiguous_counter,highest_seen_counter=excluded.highest_seen_counter,updated_at_utc=excluded.updated_at_utc`, local, origin, contiguous, highest, now); err != nil {
		return err
	}
	return auditOriginGaps(ctx, tx, local, origin, contiguous, now)
}
func auditOriginGaps(ctx context.Context, tx *sql.Tx, local, origin string, contiguous int64, now string) error {
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS sqliteseal_gap_audit(
		gap_start_counter INTEGER PRIMARY KEY,gap_end_counter INTEGER NOT NULL)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sqliteseal_gap_audit`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `WITH observed(counter) AS (
		SELECT ?
		UNION
		SELECT origin_counter FROM replication_changes WHERE origin_node_uuid=? AND origin_counter>?
	), ranges AS (
		SELECT counter+1 AS gap_start_counter,lead(counter) OVER (ORDER BY counter)-1 AS gap_end_counter FROM observed
	)
	INSERT INTO sqliteseal_gap_audit(gap_start_counter,gap_end_counter)
	SELECT gap_start_counter,gap_end_counter FROM ranges WHERE gap_end_counter>=gap_start_counter`, contiguous, origin, contiguous); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO replication_origin_gaps(
		tracking_node_uuid,origin_node_uuid,gap_start_counter,gap_end_counter,detected_at_utc,last_requested_at_utc,request_count)
		SELECT ?,?,gap_start_counter,gap_end_counter,?,NULL,0 FROM sqliteseal_gap_audit WHERE true
		ON CONFLICT(tracking_node_uuid,origin_node_uuid,gap_start_counter) DO UPDATE SET gap_end_counter=excluded.gap_end_counter`, local, origin, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM replication_origin_gaps
		WHERE tracking_node_uuid=? AND origin_node_uuid=?
		AND NOT EXISTS(SELECT 1 FROM sqliteseal_gap_audit a WHERE a.gap_start_counter=replication_origin_gaps.gap_start_counter)`, local, origin)
	return err
}

func (r *replicationRuntime) recordPeerAck(peer string, cursor int64) error {
	if cursor <= 0 {
		return nil
	}
	r.writer.Lock()
	defer r.writer.Unlock()
	return retryReplicationBusy(r.ctx, func() error {
		_, err := r.db.ExecContext(r.ctx, `INSERT OR IGNORE INTO replication_change_acks SELECT change_uuid,?,'applied',sqliteseal_utc_now() FROM replication_changes WHERE origin_node_uuid=(SELECT local_node_uuid FROM replication_local_state) AND origin_counter<=?`, peer, cursor)
		return err
	})
}

func (db *DB) PauseReplication(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `UPDATE replication_local_state SET network_enabled=0,blocked_reason='paused by application',updated_at_utc=sqliteseal_utc_now()`); err != nil {
		return err
	}
	db.replication.mu.Lock()
	for _, c := range db.replication.connections {
		_ = c.Close()
	}
	for _, l := range db.replication.listeners {
		_ = l.Close()
	}
	db.replication.listeners = nil
	db.replication.mu.Unlock()
	return nil
}
func (db *DB) ResumeReplication(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `UPDATE replication_local_state SET network_enabled=1,blocked_reason=NULL,updated_at_utc=sqliteseal_utc_now()`); err != nil {
		return err
	}
	db.replication.wakeAllDialers(false)
	db.replication.start()
	return nil
}
func (db *DB) SyncReplicationPeer(ctx context.Context, node string) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM replication_peer_connections WHERE peer_node_uuid=? AND enabled=1`, node).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrReplicationPeerNotFound
	}
	db.replication.clearPeerRetryAndWake(node, false)
	return nil
}
func (db *DB) WaitForReplication(ctx context.Context, node, origin string, counter int64) error {
	delay := 10 * time.Millisecond
	for {
		v, err := db.replication.cursorFor(origin)
		if err == nil && v >= counter {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 250*time.Millisecond {
			delay *= 2
		}
	}
}
