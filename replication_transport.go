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

const replicationProtocolVersion = 1

type wireHello struct {
	Protocol        int    `json:"protocol"`
	NodeUUID        string `json:"node_uuid"`
	IncarnationUUID string `json:"incarnation_uuid"`
	Domain          string `json:"domain"`
	SchemaVersion   int64  `json:"schema_version"`
	SchemaHash      string `json:"schema_hash"`
	MembershipEpoch int64  `json:"membership_epoch"`
	MembershipHash  string `json:"membership_hash"`
	Nonce           string `json:"nonce"`
	SessionUUID     string `json:"session_uuid,omitempty"`
	SentAtUTC       string `json:"sent_at_utc"`
	Proof           string `json:"proof,omitempty"`
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
}
type wireMessage struct {
	Type   string      `json:"type"`
	Hello  *wireHello  `json:"hello,omitempty"`
	Since  int64       `json:"since,omitempty"`
	Cursor int64       `json:"cursor,omitempty"`
	Events []wireEvent `json:"events,omitempty"`
	Error  string      `json:"error,omitempty"`
}
type peerRuntimeConfig struct {
	NodeUUID, IncarnationUUID, Address, CredentialName string
	Role                                               ReplicationConnectionRole
	Auth                                               ReplicationAuthMode
	ConnectTimeout, Heartbeat                          time.Duration
	MaxCompressed, MaxUncompressed, MaxBatch           int
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
	rows, err := r.db.Query(`SELECT p.peer_node_uuid,n.incarnation_uuid,p.address,n.credential_name,p.connection_role,n.auth_mode,p.connect_timeout_ms,p.heartbeat_interval_ms,p.max_compressed_frame_bytes,p.max_uncompressed_message_bytes,p.max_events_per_batch FROM replication_peer_connections p JOIN replication_nodes n ON n.node_uuid=p.peer_node_uuid WHERE p.enabled=1 AND p.connection_role='dial'`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var p peerRuntimeConfig
		var ct, hb int64
		if rows.Scan(&p.NodeUUID, &p.IncarnationUUID, &p.Address, &p.CredentialName, &p.Role, &p.Auth, &ct, &hb, &p.MaxCompressed, &p.MaxUncompressed, &p.MaxBatch) != nil {
			continue
		}
		p.ConnectTimeout = time.Duration(ct) * time.Millisecond
		p.Heartbeat = time.Duration(hb) * time.Millisecond
		if !r.dialers[p.NodeUUID] {
			r.dialers[p.NodeUUID] = true
			r.wg.Add(1)
			go r.dialLoop(p)
		}
	}
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
			r.setPeerAuthenticated(peer.NodeUUID, peer.SessionUUID)
			r.trackConnection(peer.NodeUUID, c, true)
			defer r.trackConnection(peer.NodeUUID, nil, false)
			_ = r.serveSession(c, peer)
		}()
	}
}
func (r *replicationRuntime) dialLoop(p peerRuntimeConfig) {
	defer r.wg.Done()
	defer func() { r.mu.Lock(); delete(r.dialers, p.NodeUUID); r.mu.Unlock() }()
	backoff := time.Second
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		var enabled int
		if r.db.QueryRow(`SELECT network_enabled FROM replication_local_state`).Scan(&enabled) != nil || enabled == 0 {
			select {
			case <-r.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		tlsCfg, err := r.opts.Credentials.TLSConfig(r.ctx, p.CredentialName, false)
		if err == nil {
			d := net.Dialer{Timeout: p.ConnectTimeout}
			var raw net.Conn
			raw, err = d.DialContext(r.ctx, "tcp", p.Address)
			if err == nil {
				tc := tls.Client(raw, tlsCfg.Clone())
				err = tc.HandshakeContext(r.ctx)
				if err == nil {
					var peer wireHello
					peer, err = r.handshake(tc, true, p.NodeUUID)
					if err == nil {
						r.trackConnection(p.NodeUUID, tc, true)
						r.setPeerAuthenticated(p.NodeUUID, peer.SessionUUID)
						err = r.clientSession(tc, peer, p)
						r.trackConnection(p.NodeUUID, nil, false)
					}
				}
				_ = tc.Close()
			}
		}
		if err != nil {
			r.setPeerState(p.NodeUUID, "disconnected", err.Error())
		}
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
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
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state='connected',last_session_uuid=?,last_error=NULL,connected_at_utc=sqliteseal_utc_now(),consecutive_failures=0,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, session, peer)
}
func (r *replicationRuntime) setPeerState(peer, state, lastErr string) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state=?,last_error=?,connected_at_utc=CASE WHEN ?='connected' THEN sqliteseal_utc_now() ELSE connected_at_utc END,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, state, lastErr, state, peer)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (r *replicationRuntime) clientSession(c net.Conn, peer wireHello, p peerRuntimeConfig) error {
	interval := p.Heartbeat
	if interval <= 0 || interval > time.Second {
		interval = 150 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.syncCycle(c, peer.NodeUUID, p); err != nil {
			return err
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-r.kick:
		case <-ticker.C:
		}
	}
}
func (r *replicationRuntime) syncCycle(c net.Conn, peer string, p peerRuntimeConfig) error {
	since, _ := r.cursorFor(peer)
	if err := writeReplicationFrame(c, wireMessage{Type: "pull", Since: since}, p.MaxCompressed); err != nil {
		return err
	}
	resp, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	for i := range resp.Events {
		if err = r.applyRemoteEvent(r.ctx, peer, resp.Events[i]); err != nil {
			return err
		}
	}
	localEvents, err := r.loadOriginEvents(r.ctx, resp.Cursor, p.MaxBatch)
	if err != nil {
		return err
	}
	if err = writeReplicationFrame(c, wireMessage{Type: "push", Events: localEvents}, p.MaxCompressed); err != nil {
		return err
	}
	ack, err := readReplicationFrame(c, p.MaxCompressed, p.MaxUncompressed)
	if err != nil {
		return err
	}
	if ack.Error != "" {
		return errors.New(ack.Error)
	}
	return r.recordPeerAck(peer, ack.Cursor)
}
func (r *replicationRuntime) serveSession(c net.Conn, peer wireHello) error {
	for {
		msg, err := readReplicationFrame(c, 8<<20, 32<<20)
		if err != nil {
			return err
		}
		switch msg.Type {
		case "pull":
			events, e := r.loadOriginEvents(r.ctx, msg.Since, 500)
			cur, _ := r.cursorFor(peer.NodeUUID)
			if e != nil {
				_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: e.Error()}, 8<<20)
			} else {
				e = writeReplicationFrame(c, wireMessage{Type: "events", Events: events, Cursor: cur}, 8<<20)
			}
			if e != nil {
				return e
			}
		case "push":
			for i := range msg.Events {
				if err = r.applyRemoteEvent(r.ctx, peer.NodeUUID, msg.Events[i]); err != nil {
					_ = writeReplicationFrame(c, wireMessage{Type: "error", Error: err.Error()}, 8<<20)
					return err
				}
			}
			cur, _ := r.cursorFor(peer.NodeUUID)
			if err = writeReplicationFrame(c, wireMessage{Type: "ack", Cursor: cur}, 8<<20); err != nil {
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
	rows, err := r.db.QueryContext(ctx, `SELECT change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,payload_hash FROM replication_changes WHERE origin_node_uuid=? AND origin_counter>? AND apply_state IN('applied','ignored') ORDER BY origin_counter LIMIT ?`, local, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []wireEvent
	for rows.Next() {
		var e wireEvent
		var recreate int
		if err = rows.Scan(&e.ChangeUUID, &e.OriginNodeUUID, &e.OriginCounter, &e.Operation, &e.TableName, &e.RowKeyJSON, &e.ChangedFieldsJSON, &recreate, &e.HLCPhysicalUS, &e.HLCLogical, &e.SchemaVersion, &e.SchemaHash, &e.Domain, &e.CreatedAtUTC, &e.PayloadHash); err != nil {
			return nil, err
		}
		e.ExplicitRecreation = recreate == 1
		d, er := r.descriptor(ctx, e.TableName)
		if er != nil {
			return nil, er
		}
		cols := []string{}
		for _, n := range d.Table.Columns {
			cols = append(cols, quoteReplicationIdent(n+"__value"), quoteReplicationIdent(n+"__present"))
		}
		q := `SELECT ` + strings.Join(cols, ",") + ` FROM ` + quoteReplicationIdent(d.DescriptorID+"__replication_changes") + ` WHERE change_uuid=?`
		vals := make([]any, len(d.Table.Columns)*2)
		ptr := make([]any, len(vals))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		if er = r.db.QueryRowContext(ctx, q, e.ChangeUUID).Scan(ptr...); er != nil {
			return nil, er
		}
		e.Values = map[string]wireValue{}
		for i, n := range d.Table.Columns {
			present := vals[i*2+1].(int64) == 1
			e.Values[n] = encodeWireValue(vals[i*2], present)
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
	var domain, schema, local string
	var version int64
	if err := r.db.QueryRowContext(ctx, `SELECT replication_domain,schema_hash,schema_version,local_node_uuid FROM replication_local_state`).Scan(&domain, &schema, &version, &local); err != nil {
		return err
	}
	if e.OriginNodeUUID != peer || e.Domain != domain {
		return errors.New("replication: origin authorization failed")
	}
	if e.SchemaHash != schema || e.SchemaVersion != version {
		return ErrReplicationSchemaMismatch
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
	skew, err := r.maximumFutureSkew(ctx)
	if err != nil {
		return err
	}
	future := e.HLCPhysicalUS > time.Now().UTC().Add(skew).UnixMicro()
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
			if err = r.removeDeferredEvent(ctx, d, e.ChangeUUID); err != nil {
				return err
			}
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO replication_changes(change_uuid,origin_node_uuid,origin_counter,operation,table_name,row_key_json,changed_fields_json,is_explicit_recreation,hlc_physical_utc_us,hlc_logical,schema_version,schema_hash,replication_domain,created_at_utc,stored_at_utc,source_node_uuid,payload_hash,apply_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')`, e.ChangeUUID, e.OriginNodeUUID, e.OriginCounter, e.Operation, e.TableName, e.RowKeyJSON, e.ChangedFieldsJSON, boolInt(e.ExplicitRecreation), e.HLCPhysicalUS, e.HLCLogical, e.SchemaVersion, e.SchemaHash, e.Domain, e.CreatedAtUTC, now, peer, e.PayloadHash); err != nil {
		return err
	}
	if err = persistWirePayload(ctx, tx, d, e); err != nil {
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
				return err
			}
			applied = true
		}
	} else {
		if rowState == "deleted" && (rowCmp <= 0 || !e.ExplicitRecreation) {
			rowCmp = -1
		} else {
			var exists int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM `+quoteReplicationIdent(e.TableName)+` WHERE `+whereSQL, args...).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 && e.Operation == "insert" {
				cols := []string{}
				marks := []string{}
				vargs := []any{}
				for _, n := range d.Table.Columns {
					w := e.Values[n]
					v, er := decodeWireValue(w)
					if er != nil {
						return er
					}
					cols = append(cols, quoteReplicationIdent(n))
					marks = append(marks, "?")
					vargs = append(vargs, v)
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO `+quoteReplicationIdent(e.TableName)+`(`+strings.Join(cols, ",")+`) VALUES(`+strings.Join(marks, ",")+`)`, vargs...); err != nil {
					return err
				}
				exists = 1
				applied = true
			}
			if exists > 0 {
				for _, n := range d.Table.Columns {
					w := e.Values[n]
					if !w.Present {
						continue
					}
					var ph, ll int64
					var origin string
					verErr := tx.QueryRowContext(ctx, `SELECT winner_hlc_physical_utc_us,winner_hlc_logical,winner_origin_node_uuid FROM replication_field_versions WHERE table_name=? AND row_key_json=? AND field_name=?`, e.TableName, e.RowKeyJSON, n).Scan(&ph, &ll, &origin)
					if verErr != nil && verErr != sql.ErrNoRows {
						return verErr
					}
					if verErr == nil && compareReplicationVersion(e.HLCPhysicalUS, e.HLCLogical, e.OriginNodeUUID, ph, ll, origin) <= 0 {
						continue
					}
					v, er := decodeWireValue(w)
					if er != nil {
						return er
					}
					if _, er = tx.ExecContext(ctx, `UPDATE `+quoteReplicationIdent(e.TableName)+` SET `+quoteReplicationIdent(n)+`=? WHERE `+whereSQL, append([]any{v}, args...)...); er != nil {
						return er
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
	if _, err = tx.ExecContext(ctx, `UPDATE replication_changes SET apply_state=? WHERE change_uuid=?`, state, e.ChangeUUID); err != nil {
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

func persistWirePayload(ctx context.Context, tx *sql.Tx, d replicationTableDescriptor, e wireEvent) error {
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
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes WHERE origin_node_uuid=? AND origin_counter=? AND apply_state<>'quarantined'`, origin, contiguous+1).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			break
		}
		contiguous++
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO replication_origin_cursors VALUES(?,?,?,?,NULL,0,?) ON CONFLICT(tracking_node_uuid,origin_node_uuid) DO UPDATE SET contiguous_counter=excluded.contiguous_counter,highest_seen_counter=excluded.highest_seen_counter,updated_at_utc=excluded.updated_at_utc`, local, origin, contiguous, highest, now)
	return err
}
func (r *replicationRuntime) recordPeerAck(peer string, cursor int64) error {
	if cursor <= 0 {
		return nil
	}
	_, err := r.db.Exec(`INSERT OR IGNORE INTO replication_change_acks SELECT change_uuid,?,'applied',sqliteseal_utc_now() FROM replication_changes WHERE origin_node_uuid=(SELECT local_node_uuid FROM replication_local_state) AND origin_counter<=?`, peer, cursor)
	return err
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
	select {
	case db.replication.kick <- struct{}{}:
	default:
	}
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
