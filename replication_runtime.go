package sqliteseal

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type replicationRuntime struct {
	db          *DB
	opts        *ReplicationRuntimeOptions
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	listeners   []net.Listener
	connections map[string]net.Conn
	dialers     map[string]*replicationDialerControl
	authReplay  map[string]time.Time
	writer      sync.Mutex
	wg          sync.WaitGroup
}

func (db *DB) openReplication(opts *ReplicationRuntimeOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	r := &replicationRuntime{db: db, opts: opts, ctx: ctx, cancel: cancel, connections: make(map[string]net.Conn), dialers: make(map[string]*replicationDialerControl), authReplay: make(map[string]time.Time)}
	db.replication = r
	var n int
	err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='replication_local_state'`).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		if err := r.ensureReplicationMetadataCompatibility(ctx); err != nil {
			return err
		}
		if err := r.seedSchemaDeclarations(ctx); err != nil {
			return err
		}
		if err := r.validateIdentityGuard(); err != nil {
			if errors.Is(err, ErrReplicationIdentityRollback) {
				return nil
			}
			return err
		}
		if err := r.registerIdentityGuardWriter(); err != nil {
			return err
		}
		if err := r.validateInstalledReplicationSchema(ctx); err != nil {
			r.fenceStartup(err)
			return nil
		}
		if err := r.recoverDeferredEvents(ctx); err != nil {
			r.fenceStartup(err)
			return nil
		}
		r.start()
	}
	return nil
}
func (r *replicationRuntime) close() {
	r.unregisterIdentityGuardWriter()
	r.cancel()
	r.mu.Lock()
	for _, l := range r.listeners {
		_ = l.Close()
	}
	for _, c := range r.connections {
		_ = c.Close()
	}
	r.listeners = nil
	r.mu.Unlock()
	r.wg.Wait()
}
func (db *DB) InitializeReplication(ctx context.Context, cfg LocalNodeConfig, tables []ReplicatedTable) error {
	if db == nil {
		return ErrDBClosed
	}
	if cfg.NodeName == "" || cfg.ReplicationDomain == "" || cfg.Level < 0 {
		return ErrReplicationInvalidConfig
	}
	if cfg.NodeUUID == "" {
		cfg.NodeUUID = replicationUUID()
	}
	if cfg.SchemaVersion <= 0 {
		cfg.SchemaVersion = 1
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = ReplicationAuthPSK
	}
	if cfg.MaximumFutureSkew <= 0 {
		cfg.MaximumFutureSkew = 5 * time.Minute
	}
	inc := replicationUUID()
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='replication_local_state'`).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return ErrReplicationAlreadyInitialized
	}
	if _, err = tx.ExecContext(ctx, replicationMetadataDDL); err != nil {
		return err
	}
	ds := make([]replicationTableDescriptor, 0, len(tables))
	for _, table := range tables {
		var tableExists int
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table.Name).Scan(&tableExists); e != nil {
			return e
		}
		if tableExists == 0 {
			if table.Name == "" || strings.HasPrefix(table.Name, "replication_") {
				return ErrReplicationInvalidConfig
			}
			continue
		}
		d, e := tableDescriptor(ctx, tx, table)
		if e != nil {
			return e
		}
		ds = append(ds, d)
	}
	hash, err := descriptorsHash(ds)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_nodes(node_uuid,incarnation_uuid,node_name,replication_domain,node_level,is_local,membership_state,membership_epoch,listen_enabled,address,auth_mode,credential_name,enabled,rebootstrap_required,created_at_utc,updated_at_utc) VALUES(?,?,?,?,?,1,'active',1,?,?,?,?,1,0,?,?)`, cfg.NodeUUID, inc, cfg.NodeName, cfg.ReplicationDomain, cfg.Level, boolInt(cfg.ListenAddress != ""), cfg.ListenAddress, string(cfg.AuthMode), cfg.CredentialName, now, now); err != nil {
		return err
	}
	zero := strings.Repeat("0", 64)
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_local_state(state_id,local_node_uuid,local_incarnation_uuid,replication_domain,last_origin_counter,last_hlc_physical_utc_us,last_hlc_logical,membership_epoch,membership_manifest_hash,database_generation,network_enabled,schema_version,schema_hash,blocked_reason,maximum_future_skew_us,created_at_utc,updated_at_utc) VALUES(1,?,?,?,0,0,0,1,?,1,0,?,?,NULL,?,?,?)`, cfg.NodeUUID, inc, cfg.ReplicationDomain, zero, cfg.SchemaVersion, hash, cfg.MaximumFutureSkew.Microseconds(), now, now); err != nil {
		return err
	}
	if err = initializeSchemaDeclarations(ctx, tx, cfg.NodeUUID, 1, tables, ds); err != nil {
		return err
	}
	for _, d := range ds {
		if err = installCaptureSchema(ctx, tx, d, hash); err != nil {
			return err
		}
		if err = captureExistingRows(ctx, tx, d); err != nil {
			return err
		}
		raw, _ := json.Marshal(d)
		if _, err = tx.ExecContext(ctx, `INSERT INTO replication_table_descriptors VALUES(?,?,?,?,?,?)`, d.Table.Name, d.DescriptorID, string(raw), hash, boolInt(d.Table.AllowExplicitRecreation), now); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err := db.replication.updateIdentityGuard(); err != nil {
		return err
	}
	if err := db.replication.registerIdentityGuardWriter(); err != nil {
		return err
	}
	db.replication.start()
	return nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (db *DB) UpsertReplicationPeer(ctx context.Context, p PeerConfig) error {
	if p.NodeUUID == "" || p.IncarnationUUID == "" || p.NodeName == "" || p.Address == "" || p.NodeUUID == p.IncarnationUUID {
		return ErrReplicationInvalidConfig
	}
	if p.Role != "dial" && p.Role != "accept" {
		return ErrReplicationInvalidConfig
	}
	if p.AuthMode != "psk" && p.AuthMode != "mtls" {
		return ErrReplicationInvalidConfig
	}
	defaultsPeer(&p)
	if p.ConnectTimeout.Milliseconds() <= 0 || p.HeartbeatInterval.Milliseconds() <= 0 ||
		p.HeartbeatTimeout.Milliseconds() <= p.HeartbeatInterval.Milliseconds() ||
		p.ReconnectInitial.Milliseconds() <= 0 || p.ReconnectMaximum.Milliseconds() < p.ReconnectInitial.Milliseconds() ||
		p.ReconnectJitterPercent == nil || *p.ReconnectJitterPercent < 0 || *p.ReconnectJitterPercent > 100 ||
		p.MaxSnapshotBytes <= 0 {
		return ErrReplicationInvalidConfig
	}
	var domain string
	if err := db.QueryRowContext(ctx, `SELECT replication_domain FROM replication_local_state WHERE state_id=1`).Scan(&domain); err != nil {
		return ErrReplicationNotInitialized
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO replication_nodes(node_uuid,incarnation_uuid,node_name,replication_domain,node_level,is_local,membership_state,membership_epoch,listen_enabled,address,auth_mode,credential_name,enabled,rebootstrap_required,created_at_utc,updated_at_utc) VALUES(?,?,?, ?,0,0,'joining',1,?,?,?,?,0,1,?,?) ON CONFLICT(node_uuid) DO UPDATE SET incarnation_uuid=excluded.incarnation_uuid,node_name=excluded.node_name,address=excluded.address,listen_enabled=excluded.listen_enabled,auth_mode=excluded.auth_mode,credential_name=excluded.credential_name,updated_at_utc=excluded.updated_at_utc`, p.NodeUUID, p.IncarnationUUID, p.NodeName, domain, boolInt(p.ListenEnabled), p.Address, string(p.AuthMode), p.CredentialName, now, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO replication_peer_connections(peer_node_uuid,connection_role,enabled,reconnect_enabled,address,connect_timeout_ms,heartbeat_interval_ms,heartbeat_timeout_ms,reconnect_initial_ms,reconnect_max_ms,reconnect_jitter_percent,max_snapshot_bytes,max_compressed_frame_bytes,max_uncompressed_message_bytes,max_events_per_batch,max_inflight_events,max_inflight_bytes,session_state,next_retry_at_utc,consecutive_failures,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'disabled',NULL,0,?) ON CONFLICT(peer_node_uuid) DO UPDATE SET connection_role=excluded.connection_role,reconnect_enabled=excluded.reconnect_enabled,address=excluded.address,connect_timeout_ms=excluded.connect_timeout_ms,heartbeat_interval_ms=excluded.heartbeat_interval_ms,heartbeat_timeout_ms=excluded.heartbeat_timeout_ms,reconnect_initial_ms=excluded.reconnect_initial_ms,reconnect_max_ms=excluded.reconnect_max_ms,reconnect_jitter_percent=excluded.reconnect_jitter_percent,max_snapshot_bytes=excluded.max_snapshot_bytes,max_compressed_frame_bytes=excluded.max_compressed_frame_bytes,max_uncompressed_message_bytes=excluded.max_uncompressed_message_bytes,max_events_per_batch=excluded.max_events_per_batch,max_inflight_events=excluded.max_inflight_events,max_inflight_bytes=excluded.max_inflight_bytes,next_retry_at_utc=NULL,updated_at_utc=excluded.updated_at_utc`, p.NodeUUID, string(p.Role), 0, boolInt(p.Role == ReplicationDial), p.Address, p.ConnectTimeout.Milliseconds(), p.HeartbeatInterval.Milliseconds(), p.HeartbeatTimeout.Milliseconds(), p.ReconnectInitial.Milliseconds(), p.ReconnectMaximum.Milliseconds(), *p.ReconnectJitterPercent, p.MaxSnapshotBytes, p.MaxCompressedBytes, p.MaxUncompressedBytes, p.MaxEventsPerBatch, p.MaxInflightEvents, p.MaxInflightBytes, now)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	db.replication.restartPeer(p.NodeUUID)
	return nil
}
func defaultsPeer(p *PeerConfig) {
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = 10 * time.Second
	}
	if p.HeartbeatInterval <= 0 {
		p.HeartbeatInterval = 15 * time.Second
	}
	if p.HeartbeatTimeout <= p.HeartbeatInterval {
		const maximumDuration = time.Duration(1<<63 - 1)
		if p.HeartbeatInterval > maximumDuration/3 {
			p.HeartbeatTimeout = maximumDuration
		} else {
			p.HeartbeatTimeout = 3 * p.HeartbeatInterval
		}
	}
	if p.ReconnectInitial <= 0 {
		p.ReconnectInitial = time.Second
	}
	if p.ReconnectMaximum <= 0 {
		p.ReconnectMaximum = time.Minute
		if p.ReconnectMaximum < p.ReconnectInitial {
			p.ReconnectMaximum = p.ReconnectInitial
		}
	}
	if p.ReconnectJitterPercent == nil {
		jitter := 20
		p.ReconnectJitterPercent = &jitter
	}
	if p.MaxSnapshotBytes == 0 {
		p.MaxSnapshotBytes = defaultMaximumReplicationSnapshotBytes
	}
	if p.MaxCompressedBytes <= 0 {
		p.MaxCompressedBytes = 8 << 20
	}
	if p.MaxUncompressedBytes < p.MaxCompressedBytes {
		p.MaxUncompressedBytes = 32 << 20
	}
	if p.MaxEventsPerBatch <= 0 {
		p.MaxEventsPerBatch = 500
	}
	if p.MaxInflightEvents < p.MaxEventsPerBatch {
		p.MaxInflightEvents = 2000
	}
	if p.MaxInflightBytes <= 0 {
		p.MaxInflightBytes = 64 << 20
	}
}

func (r *replicationRuntime) restartPeer(nodeUUID string) {
	r.clearPeerRetryAndWake(nodeUUID, true)
	r.mu.Lock()
	connection := r.connections[nodeUUID]
	r.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
	r.start()
}

func (db *DB) ApplyMembershipManifest(ctx context.Context, m MembershipManifest) error {
	h, raw, err := canonicalMembership(m)
	if err != nil {
		return err
	}
	if db.replication.opts == nil || db.replication.opts.MembershipVerifier == nil {
		return fmt.Errorf("%w: membership verifier missing", ErrReplicationNotReady)
	}
	if err = db.replication.opts.MembershipVerifier.VerifyMembership(ctx, raw, m.Signature); err != nil {
		return err
	}
	var domain string
	var epoch int64
	if err = db.QueryRowContext(ctx, `SELECT replication_domain,membership_epoch FROM replication_local_state`).Scan(&domain, &epoch); err != nil {
		return err
	}
	if m.Domain != domain || m.Epoch <= epoch {
		return ErrReplicationMembershipMismatch
	}
	if err = db.validateMembershipManifest(ctx, m); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range m.Nodes {
		if _, err = tx.ExecContext(ctx, `UPDATE replication_nodes SET node_level=?,membership_state=?,membership_epoch=?,enabled=CASE WHEN ?='active' THEN 1 ELSE 0 END,rebootstrap_required=CASE WHEN ?='active' THEN rebootstrap_required ELSE 1 END WHERE node_uuid=?`, n.Level, n.State, m.Epoch, n.State, n.State, n.NodeUUID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET membership_epoch=?,membership_manifest_hash=?,network_enabled=1,blocked_reason=NULL,updated_at_utc=sqliteseal_utc_now()`, m.Epoch, h); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_peer_connections SET enabled=CASE WHEN peer_node_uuid IN(SELECT node_uuid FROM replication_nodes WHERE enabled=1 AND is_local=0) THEN 1 ELSE 0 END,session_state=CASE WHEN peer_node_uuid IN(SELECT node_uuid FROM replication_nodes WHERE enabled=1 AND is_local=0) THEN 'disconnected' ELSE 'disabled' END,next_retry_at_utc=CASE WHEN peer_node_uuid IN(SELECT node_uuid FROM replication_nodes WHERE enabled=1 AND is_local=0) THEN NULL ELSE next_retry_at_utc END`); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		_ = db.replication.closeUnauthorizedSessions(ctx)
		db.replication.wakeAllDialers(false)
		db.replication.start()
	}
	return err
}
func canonicalMembership(m MembershipManifest) (string, []byte, error) {
	sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].NodeUUID < m.Nodes[j].NodeUUID })
	m.Signature = nil
	b, err := json.Marshal(m)
	if err != nil {
		return "", nil, err
	}
	sum := sha256Bytes(b)
	return fmt.Sprintf("%x", sum), b, nil
}
func sha256Bytes(b []byte) []byte { h := sha256.New(); h.Write(b); return h.Sum(nil) }

func (db *DB) ReplicationStatus(ctx context.Context) (ReplicationStatus, error) {
	var s ReplicationStatus
	err := db.QueryRowContext(ctx, `SELECT l.local_node_uuid,l.local_incarnation_uuid,l.replication_domain,n.node_level,l.schema_version,l.schema_hash,l.membership_epoch,l.membership_manifest_hash,l.last_origin_counter,l.last_hlc_physical_utc_us,l.last_hlc_logical,l.network_enabled,coalesce(l.blocked_reason,''),coalesce(n.address,'') FROM replication_local_state l JOIN replication_nodes n ON n.node_uuid=l.local_node_uuid WHERE l.state_id=1`).Scan(&s.NodeUUID, &s.IncarnationUUID, &s.Domain, &s.Level, &s.SchemaVersion, &s.SchemaHash, &s.MembershipEpoch, &s.MembershipHash, &s.LastOriginCounter, &s.LastHLCPhysicalUS, &s.LastHLCLogical, &s.NetworkEnabled, &s.BlockedReason, &s.ListenAddress)
	if err == sql.ErrNoRows {
		return s, ErrReplicationNotInitialized
	}
	if err != nil {
		return s, err
	}
	s.Initialized = true
	s.Ready = s.NetworkEnabled && s.BlockedReason == ""
	rows, err := db.QueryContext(ctx, `SELECT p.peer_node_uuid,n.node_level,p.session_state,coalesce(p.last_error,''),p.connected_at_utc,p.next_retry_at_utc,p.consecutive_failures,coalesce(c.contiguous_counter,0),coalesce(c.highest_seen_counter,0),(SELECT count(*) FROM replication_origin_gaps g WHERE g.tracking_node_uuid=l.local_node_uuid AND g.origin_node_uuid=p.peer_node_uuid) FROM replication_peer_connections p JOIN replication_nodes n ON n.node_uuid=p.peer_node_uuid CROSS JOIN replication_local_state l LEFT JOIN replication_origin_cursors c ON c.tracking_node_uuid=l.local_node_uuid AND c.origin_node_uuid=p.peer_node_uuid`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ReplicationPeerStatus
		var connectedAt, nextRetryAt sql.NullString
		if err = rows.Scan(&p.NodeUUID, &p.Level, &p.State, &p.LastError, &connectedAt, &nextRetryAt, &p.ConsecutiveFailures, &p.ContiguousCounter, &p.HighestSeenCounter, &p.GapCount); err != nil {
			return s, err
		}
		if connectedAt.Valid {
			p.ConnectedAt, err = parseReplicationTimestamp(connectedAt.String)
			if err != nil {
				return s, err
			}
		}
		if nextRetryAt.Valid {
			next, parseErr := parseReplicationTimestamp(nextRetryAt.String)
			if parseErr != nil {
				return s, parseErr
			}
			p.NextRetryAt = &next
		}
		s.Peers = append(s.Peers, p)
	}
	if err = rows.Err(); err != nil {
		return s, err
	}
	if err = rows.Close(); err != nil {
		return s, err
	}
	conflictRows, conflictErr := db.QueryContext(ctx, `SELECT table_name,column_name,authority_level,declared_types_json,origin_nodes_json FROM replication_schema_conflicts ORDER BY table_name,column_name`)
	if conflictErr != nil {
		return s, conflictErr
	}
	defer conflictRows.Close()
	for conflictRows.Next() {
		var conflict ReplicationSchemaConflict
		var typesRaw, nodesRaw string
		if conflictErr = conflictRows.Scan(&conflict.TableName, &conflict.ColumnName, &conflict.AuthorityLevel, &typesRaw, &nodesRaw); conflictErr != nil {
			return s, conflictErr
		}
		if conflictErr = json.Unmarshal([]byte(typesRaw), &conflict.DeclaredTypes); conflictErr != nil {
			return s, conflictErr
		}
		if conflictErr = json.Unmarshal([]byte(nodesRaw), &conflict.OriginNodeUUIDs); conflictErr != nil {
			return s, conflictErr
		}
		s.SchemaConflicts = append(s.SchemaConflicts, conflict)
	}
	return s, conflictRows.Err()
}

func (db *DB) ReplicationSyncStats(ctx context.Context) (ReplicationSyncStats, error) {
	var st ReplicationSyncStats
	err := db.QueryRowContext(ctx, `SELECT local_node_uuid, last_origin_counter FROM replication_local_state WHERE state_id=1`).Scan(&st.LocalNodeUUID, &st.LastOriginCounter)
	if err == sql.ErrNoRows {
		return st, ErrReplicationNotInitialized
	}
	if err != nil {
		return st, err
	}
	rows, err := db.QueryContext(ctx, `SELECT c.origin_node_uuid, c.contiguous_counter, c.highest_seen_counter, (SELECT count(*) FROM replication_origin_gaps g WHERE g.tracking_node_uuid=c.tracking_node_uuid AND g.origin_node_uuid=c.origin_node_uuid) FROM replication_origin_cursors c WHERE c.tracking_node_uuid=? ORDER BY c.origin_node_uuid`, st.LocalNodeUUID)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ReplicationOriginProgress
		if err = rows.Scan(&p.OriginNodeUUID, &p.ContiguousCounter, &p.HighestSeenCounter, &p.GapCount); err != nil {
			return st, err
		}
		st.PeerCursors = append(st.PeerCursors, p)
	}
	return st, rows.Err()
}
func (db *DB) TestReplicationPeer(ctx context.Context, node string) error {
	if db.replication == nil || db.replication.opts == nil || db.replication.opts.Credentials == nil {
		return ErrReplicationNotReady
	}
	var address, credential string
	var timeoutMS int64
	if err := db.QueryRowContext(ctx, `SELECT p.address,n.credential_name,p.connect_timeout_ms FROM replication_peer_connections p JOIN replication_nodes n ON n.node_uuid=p.peer_node_uuid WHERE p.peer_node_uuid=?`, node).Scan(&address, &credential, &timeoutMS); err == sql.ErrNoRows {
		return ErrReplicationPeerNotFound
	} else if err != nil {
		return err
	}
	configuration, err := db.replication.opts.Credentials.TLSConfig(ctx, credential, false)
	if err != nil {
		return err
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	tlsConnection := tls.Client(raw, configuration.Clone())
	defer tlsConnection.Close()
	peer, err := db.replication.handshakePurpose(tlsConnection, true, node, true)
	if err != nil {
		return err
	}
	if !peer.AdministrativeTest || peer.NodeUUID != node {
		return errors.New("replication: administrative peer identity mismatch")
	}
	return nil
}
func (db *DB) ReloadReplicationCredentials(context.Context) error {
	if db.replication.opts == nil || db.replication.opts.Credentials == nil {
		return ErrReplicationNotReady
	}
	db.replication.wakeAllDialers(true)
	db.replication.mu.Lock()
	for _, connection := range db.replication.connections {
		_ = connection.Close()
	}
	for _, listener := range db.replication.listeners {
		_ = listener.Close()
	}
	db.replication.connections = make(map[string]net.Conn)
	db.replication.listeners = nil
	db.replication.authReplay = make(map[string]time.Time)
	db.replication.mu.Unlock()
	db.replication.start()
	return nil
}
func (db *DB) RetireReplicationPeer(ctx context.Context, node string, m MembershipManifest) error {
	found := false
	for _, n := range m.Nodes {
		if n.NodeUUID == node && n.State == "retired" {
			found = true
		}
	}
	if !found {
		return ErrReplicationMembershipMismatch
	}
	return db.ApplyMembershipManifest(ctx, m)
}
func (db *DB) ReplicationConflicts(ctx context.Context) ([]ReplicationConflict, error) {
	rows, err := db.QueryContext(ctx, `SELECT change_uuid,origin_node_uuid,origin_counter,table_name,row_key_json,apply_state,coalesce(quarantine_reason,'') FROM replication_changes WHERE apply_state IN('pending','quarantined') AND quarantine_reason IN('foreign_key_dependency','unique_conflict') ORDER BY origin_node_uuid,origin_counter`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var conflicts []ReplicationConflict
	for rows.Next() {
		var conflict ReplicationConflict
		if err = rows.Scan(&conflict.ChangeUUID, &conflict.OriginNodeUUID, &conflict.OriginCounter, &conflict.TableName, &conflict.RowKeyJSON, &conflict.State, &conflict.Reason); err != nil {
			return nil, err
		}
		conflicts = append(conflicts, conflict)
	}
	return conflicts, rows.Err()
}

// RetryReplicationDeferred retries durable FK dependencies after related rows arrive.
func (db *DB) RetryReplicationDeferred(ctx context.Context) error {
	if db == nil || db.replication == nil {
		return ErrReplicationNotInitialized
	}
	return db.replication.recoverDeferredEvents(ctx)
}

func (db *DB) ApplyReplicationMigration(ctx context.Context, m ReplicationMigration) error {
	if db == nil || db.replication == nil {
		return ErrReplicationNotInitialized
	}
	if m.ToVersion <= m.FromVersion || len(m.Tables) == 0 {
		return ErrReplicationInvalidConfig
	}
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT schema_version FROM replication_local_state`).Scan(&version); err != nil {
		return err
	}
	if version != m.FromVersion {
		return ErrReplicationSchemaMismatch
	}
	if err := db.PauseReplication(ctx); err != nil {
		return err
	}
	db.replication.writer.Lock()
	defer db.replication.writer.Unlock()
	return db.replication.withReplicationModeTransaction(ctx, "maintenance", func(tx *sql.Tx) error {
		var unresolved int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes WHERE apply_state NOT IN(?,?)`, "applied", "ignored").Scan(&unresolved); err != nil {
			return err
		}
		if unresolved != 0 {
			return fmt.Errorf("%w: %d deferred or quarantined events must be resolved before migration", ErrReplicationNotReady, unresolved)
		}
		rows, err := tx.QueryContext(ctx, `SELECT descriptor_json FROM replication_table_descriptors ORDER BY table_name`)
		if err != nil {
			return err
		}
		var previous []replicationTableDescriptor
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			var d replicationTableDescriptor
			if err = json.Unmarshal([]byte(raw), &d); err != nil {
				rows.Close()
				return err
			}
			previous = append(previous, d)
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if err = materializeHistoricalWireValues(ctx, tx, previous); err != nil {
			return err
		}
		for _, d := range previous {
			if err = dropCaptureTriggers(ctx, tx, d); err != nil {
				return err
			}
		}
		for _, statement := range m.Statements {
			if strings.TrimSpace(statement) != "" {
				if _, err = tx.ExecContext(ctx, statement); err != nil {
					return err
				}
			}
		}
		descriptors := make([]replicationTableDescriptor, 0, len(m.Tables))
		for _, table := range m.Tables {
			d, descriptorErr := tableDescriptor(ctx, tx, table)
			if descriptorErr != nil {
				return descriptorErr
			}
			descriptors = append(descriptors, d)
		}
		hash, err := descriptorsHash(descriptors)
		if err != nil {
			return err
		}
		previousByName := make(map[string]replicationTableDescriptor, len(previous))
		for _, oldDescriptor := range previous {
			previousByName[oldDescriptor.Table.Name] = oldDescriptor
		}
		previousTables := make(map[string]bool, len(previous))
		for _, oldDescriptor := range previous {
			previousTables[oldDescriptor.Table.Name] = true
		}
		for table := range previousTables {
			found := false
			for _, descriptor := range descriptors {
				if descriptor.Table.Name == table {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: replicated table removal is not automatic", ErrReplicationInvalidConfig)
			}
		}
		if err = publishLocalSchemaDeclarations(ctx, tx, descriptors); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET network_enabled=0,schema_version=?,schema_hash=?,blocked_reason=?,updated_at_utc=sqliteseal_utc_now()`, m.ToVersion, hash, "schema migration completed; resume replication explicitly"); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM replication_table_descriptors`); err != nil {
			return err
		}
		now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
		for _, d := range descriptors {
			if err = installCaptureSchema(ctx, tx, d, hash); err != nil {
				return err
			}
			if !previousTables[d.Table.Name] {
				if err = captureExistingRows(ctx, tx, d); err != nil {
					return err
				}
			} else {
				oldSelected := make(map[string]bool)
				for _, name := range previousByName[d.Table.Name].Table.Columns {
					oldSelected[name] = true
				}
				var added []string
				for _, name := range d.Table.Columns {
					if !oldSelected[name] {
						added = append(added, name)
					}
				}
				if len(added) != 0 {
					if err = captureExistingColumnValues(ctx, tx, d, added); err != nil {
						return err
					}
				}
			}
			raw, marshalErr := json.Marshal(d)
			if marshalErr != nil {
				return marshalErr
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO replication_table_descriptors VALUES(?,?,?,?,?,?)`, d.Table.Name, d.DescriptorID, string(raw), hash, boolInt(d.Table.AllowExplicitRecreation), now); err != nil {
				return err
			}
		}
		return nil
	})
}
