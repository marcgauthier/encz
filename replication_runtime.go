package sqliteseal

import (
	"context"
	"crypto/sha256"
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
	dialers     map[string]bool
	authReplay  map[string]time.Time
	kick        chan struct{}
	writer      sync.Mutex
	wg          sync.WaitGroup
}

func (db *DB) openReplication(opts *ReplicationRuntimeOptions) error {
	ctx, cancel := context.WithCancel(context.Background())
	r := &replicationRuntime{db: db, opts: opts, ctx: ctx, cancel: cancel, connections: make(map[string]net.Conn), dialers: make(map[string]bool), authReplay: make(map[string]time.Time), kick: make(chan struct{}, 1)}
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
	if cfg.NodeName == "" || cfg.ReplicationDomain == "" || len(tables) == 0 {
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_nodes(node_uuid,incarnation_uuid,node_name,replication_domain,is_local,membership_state,membership_epoch,listen_enabled,address,auth_mode,credential_name,enabled,rebootstrap_required,created_at_utc,updated_at_utc) VALUES(?,?,?,?,1,'active',1,?,?,?,?,1,0,?,?)`, cfg.NodeUUID, inc, cfg.NodeName, cfg.ReplicationDomain, boolInt(cfg.ListenAddress != ""), cfg.ListenAddress, string(cfg.AuthMode), cfg.CredentialName, now, now); err != nil {
		return err
	}
	zero := strings.Repeat("0", 64)
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_local_state(state_id,local_node_uuid,local_incarnation_uuid,replication_domain,last_origin_counter,last_hlc_physical_utc_us,last_hlc_logical,membership_epoch,membership_manifest_hash,database_generation,network_enabled,schema_version,schema_hash,blocked_reason,maximum_future_skew_us,created_at_utc,updated_at_utc) VALUES(1,?,?,?,0,0,0,1,?,1,0,?,?,NULL,?,?,?)`, cfg.NodeUUID, inc, cfg.ReplicationDomain, zero, cfg.SchemaVersion, hash, cfg.MaximumFutureSkew.Microseconds(), now, now); err != nil {
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
	_, err = tx.ExecContext(ctx, `INSERT INTO replication_nodes(node_uuid,incarnation_uuid,node_name,replication_domain,is_local,membership_state,membership_epoch,listen_enabled,address,auth_mode,credential_name,enabled,rebootstrap_required,created_at_utc,updated_at_utc) VALUES(?,?,?, ?,0,'joining',1,?,?,?,?,0,1,?,?) ON CONFLICT(node_uuid) DO UPDATE SET incarnation_uuid=excluded.incarnation_uuid,node_name=excluded.node_name,address=excluded.address,listen_enabled=excluded.listen_enabled,auth_mode=excluded.auth_mode,credential_name=excluded.credential_name,updated_at_utc=excluded.updated_at_utc`, p.NodeUUID, p.IncarnationUUID, p.NodeName, domain, boolInt(p.ListenEnabled), p.Address, string(p.AuthMode), p.CredentialName, now, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO replication_peer_connections(peer_node_uuid,connection_role,enabled,reconnect_enabled,address,connect_timeout_ms,heartbeat_interval_ms,heartbeat_timeout_ms,reconnect_initial_ms,reconnect_max_ms,max_compressed_frame_bytes,max_uncompressed_message_bytes,max_events_per_batch,max_inflight_events,max_inflight_bytes,session_state,consecutive_failures,updated_at_utc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'disabled',0,?) ON CONFLICT(peer_node_uuid) DO UPDATE SET connection_role=excluded.connection_role,address=excluded.address,updated_at_utc=excluded.updated_at_utc`, p.NodeUUID, string(p.Role), 0, boolInt(p.Role == ReplicationDial), p.Address, p.ConnectTimeout.Milliseconds(), p.HeartbeatInterval.Milliseconds(), p.HeartbeatTimeout.Milliseconds(), p.ReconnectInitial.Milliseconds(), p.ReconnectMaximum.Milliseconds(), p.MaxCompressedBytes, p.MaxUncompressedBytes, p.MaxEventsPerBatch, p.MaxInflightEvents, p.MaxInflightBytes, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func defaultsPeer(p *PeerConfig) {
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = 10 * time.Second
	}
	if p.HeartbeatInterval <= 0 {
		p.HeartbeatInterval = 15 * time.Second
	}
	if p.HeartbeatTimeout <= p.HeartbeatInterval {
		p.HeartbeatTimeout = 45 * time.Second
	}
	if p.ReconnectInitial <= 0 {
		p.ReconnectInitial = time.Second
	}
	if p.ReconnectMaximum < p.ReconnectInitial {
		p.ReconnectMaximum = time.Minute
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
		if _, err = tx.ExecContext(ctx, `UPDATE replication_nodes SET membership_state=?,membership_epoch=?,enabled=CASE WHEN ?='active' THEN 1 ELSE 0 END,rebootstrap_required=CASE WHEN ?='active' THEN rebootstrap_required ELSE 1 END WHERE node_uuid=?`, n.State, m.Epoch, n.State, n.State, n.NodeUUID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET membership_epoch=?,membership_manifest_hash=?,network_enabled=1,blocked_reason=NULL,updated_at_utc=sqliteseal_utc_now()`, m.Epoch, h); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_peer_connections SET enabled=CASE WHEN peer_node_uuid IN(SELECT node_uuid FROM replication_nodes WHERE enabled=1 AND is_local=0) THEN 1 ELSE 0 END,session_state=CASE WHEN peer_node_uuid IN(SELECT node_uuid FROM replication_nodes WHERE enabled=1 AND is_local=0) THEN 'disconnected' ELSE 'disabled' END`); err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		_ = db.replication.closeUnauthorizedSessions(ctx)
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
	err := db.QueryRowContext(ctx, `SELECT l.local_node_uuid,l.local_incarnation_uuid,l.replication_domain,l.schema_version,l.schema_hash,l.membership_epoch,l.membership_manifest_hash,l.last_origin_counter,l.last_hlc_physical_utc_us,l.last_hlc_logical,l.network_enabled,coalesce(l.blocked_reason,''),coalesce(n.address,'') FROM replication_local_state l JOIN replication_nodes n ON n.node_uuid=l.local_node_uuid WHERE l.state_id=1`).Scan(&s.NodeUUID, &s.IncarnationUUID, &s.Domain, &s.SchemaVersion, &s.SchemaHash, &s.MembershipEpoch, &s.MembershipHash, &s.LastOriginCounter, &s.LastHLCPhysicalUS, &s.LastHLCLogical, &s.NetworkEnabled, &s.BlockedReason, &s.ListenAddress)
	if err == sql.ErrNoRows {
		return s, ErrReplicationNotInitialized
	}
	if err != nil {
		return s, err
	}
	s.Initialized = true
	s.Ready = s.NetworkEnabled && s.BlockedReason == ""
	rows, err := db.QueryContext(ctx, `SELECT p.peer_node_uuid,p.session_state,coalesce(p.last_error,''),coalesce(c.contiguous_counter,0),coalesce(c.highest_seen_counter,0),(SELECT count(*) FROM replication_origin_gaps g WHERE g.origin_node_uuid=p.peer_node_uuid) FROM replication_peer_connections p LEFT JOIN replication_origin_cursors c ON c.origin_node_uuid=p.peer_node_uuid`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ReplicationPeerStatus
		if err = rows.Scan(&p.NodeUUID, &p.State, &p.LastError, &p.ContiguousCounter, &p.HighestSeenCounter, &p.GapCount); err != nil {
			return s, err
		}
		s.Peers = append(s.Peers, p)
	}
	return s, rows.Err()
}
func (db *DB) TestReplicationPeer(ctx context.Context, node string) error {
	var addr string
	if err := db.QueryRowContext(ctx, `SELECT address FROM replication_peer_connections WHERE peer_node_uuid=?`, node).Scan(&addr); err == sql.ErrNoRows {
		return ErrReplicationPeerNotFound
	} else if err != nil {
		return err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}
func (db *DB) ReloadReplicationCredentials(context.Context) error {
	if db.replication.opts == nil || db.replication.opts.Credentials == nil {
		return ErrReplicationNotReady
	}
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
func (db *DB) ApplyReplicationMigration(ctx context.Context, m ReplicationMigration) error {
	if m.ToVersion <= m.FromVersion {
		return ErrReplicationInvalidConfig
	}
	var v int64
	if err := db.QueryRowContext(ctx, `SELECT schema_version FROM replication_local_state`).Scan(&v); err != nil {
		return err
	}
	if v != m.FromVersion {
		return ErrReplicationSchemaMismatch
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET network_enabled=0`); err != nil {
		return err
	}
	for _, q := range m.Statements {
		if strings.TrimSpace(q) != "" {
			if _, err = tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
	}
	ds := make([]replicationTableDescriptor, 0, len(m.Tables))
	for _, t := range m.Tables {
		d, e := tableDescriptor(ctx, tx, t)
		if e != nil {
			return e
		}
		ds = append(ds, d)
	}
	hash, err := descriptorsHash(ds)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replication_local_state SET schema_version=?,schema_hash=?,updated_at_utc=sqliteseal_utc_now()`, m.ToVersion, hash); err != nil {
		return err
	}
	return tx.Commit()
}
