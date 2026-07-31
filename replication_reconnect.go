package sqliteseal

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"errors"
	"math/big"
	"time"
)

const replicationTimestampFormat = "2006-01-02T15:04:05.000000Z"

type replicationDialerControl struct {
	wake     chan struct{}
	revision uint64
}

func newReplicationDialerControl() *replicationDialerControl {
	return &replicationDialerControl{wake: make(chan struct{}, 1)}
}

func parseReplicationTimestamp(value string) (time.Time, error) {
	return time.Parse(replicationTimestampFormat, value)
}

func formatReplicationTimestamp(value time.Time) string {
	return value.UTC().Format(replicationTimestampFormat)
}

func (r *replicationRuntime) controlRevision(control *replicationDialerControl) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return control.revision
}

func (r *replicationRuntime) controlChanged(control *replicationDialerControl, revision uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return control.revision != revision
}

func signalReplicationDialer(control *replicationDialerControl) {
	select {
	case control.wake <- struct{}{}:
	default:
	}
}

func (r *replicationRuntime) clearPeerRetryAndWake(nodeUUID string, plannedClose bool) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET next_retry_at_utc=NULL,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, nodeUUID)
	r.mu.Lock()
	control := r.dialers[nodeUUID]
	if control != nil && plannedClose {
		control.revision++
	}
	r.mu.Unlock()
	if control != nil {
		signalReplicationDialer(control)
	}
}

func (r *replicationRuntime) wakeAllDialers(plannedClose bool) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET next_retry_at_utc=NULL,updated_at_utc=sqliteseal_utc_now() WHERE enabled=1 AND connection_role='dial'`)
	r.mu.Lock()
	controls := make([]*replicationDialerControl, 0, len(r.dialers))
	for _, control := range r.dialers {
		if plannedClose {
			control.revision++
		}
		controls = append(controls, control)
	}
	r.mu.Unlock()
	for _, control := range controls {
		signalReplicationDialer(control)
	}
}

func waitForReplicationDialer(ctx context.Context, control *replicationDialerControl, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-control.wake:
		return true
	case <-timer.C:
		return true
	}
}

func waitForReplicationDialerWake(ctx context.Context, control *replicationDialerControl) bool {
	select {
	case <-ctx.Done():
		return false
	case <-control.wake:
		return true
	}
}

func reconnectBackoff(initial, maximum time.Duration, failures int64) time.Duration {
	if initial <= 0 || maximum < initial {
		return 0
	}
	delay := initial
	for remaining := failures - 1; remaining > 0 && delay < maximum; remaining-- {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func reconnectJitterBounds(base, maximum time.Duration, percent int) (time.Duration, time.Duration) {
	if percent <= 0 || base <= 0 {
		return base, base
	}
	delta := (base/100)*time.Duration(percent) + (base%100)*time.Duration(percent)/100
	lower := base - delta
	upper := base
	if delta > maximum-base {
		upper = maximum
	} else {
		upper += delta
	}
	return lower, upper
}

func randomizedReconnectDelay(base, maximum time.Duration, percent int) time.Duration {
	lower, upper := reconnectJitterBounds(base, maximum, percent)
	if lower >= upper {
		return lower
	}
	span := new(big.Int).SetInt64(int64(upper - lower))
	span.Add(span, big.NewInt(1))
	sample, err := cryptorand.Int(cryptorand.Reader, span)
	if err != nil {
		return base
	}
	return lower + time.Duration(sample.Int64())
}

func (r *replicationRuntime) clampPersistedRetry(p peerRuntimeConfig, now time.Time) (time.Time, error) {
	if p.NextRetryAt == nil {
		return now, nil
	}
	next := *p.NextRetryAt
	latest := now.Add(p.ReconnectMaximum)
	if next.After(latest) {
		next = latest
		_, err := r.db.ExecContext(r.ctx, `UPDATE replication_peer_connections SET next_retry_at_utc=?,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, formatReplicationTimestamp(next), p.NodeUUID)
		if err != nil {
			return time.Time{}, err
		}
	}
	return next, nil
}

func (r *replicationRuntime) setPeerConnecting(peer string) {
	_, _ = r.db.Exec(`UPDATE replication_peer_connections SET session_state='connecting',next_retry_at_utc=NULL,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, peer)
}

func (r *replicationRuntime) recordDialFailure(p peerRuntimeConfig, session string, sessionErr error) (time.Time, bool, error) {
	tx, err := r.db.BeginTx(r.ctx, nil)
	if err != nil {
		return time.Time{}, false, err
	}
	defer tx.Rollback()
	var failures int64
	if session == "" {
		err = tx.QueryRowContext(r.ctx, `UPDATE replication_peer_connections SET consecutive_failures=CASE WHEN consecutive_failures<9223372036854775807 THEN consecutive_failures+1 ELSE consecutive_failures END WHERE peer_node_uuid=? AND session_state NOT IN('connected','schema_pending') RETURNING consecutive_failures`, p.NodeUUID).Scan(&failures)
	} else {
		err = tx.QueryRowContext(r.ctx, `UPDATE replication_peer_connections SET consecutive_failures=consecutive_failures+1 WHERE peer_node_uuid=? AND last_session_uuid=? AND session_state IN('connected','schema_pending') RETURNING consecutive_failures`, p.NodeUUID, session).Scan(&failures)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	base := reconnectBackoff(p.ReconnectInitial, p.ReconnectMaximum, failures)
	delay := randomizedReconnectDelay(base, p.ReconnectMaximum, p.ReconnectJitterPercent)
	next := time.Now().UTC().Add(delay)
	_, err = tx.ExecContext(r.ctx, `UPDATE replication_peer_connections SET session_state='disconnected',last_error=?,next_retry_at_utc=?,updated_at_utc=sqliteseal_utc_now() WHERE peer_node_uuid=?`, sanitizedReplicationConnectionError(sessionErr), formatReplicationTimestamp(next), p.NodeUUID)
	if err != nil {
		return time.Time{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return time.Time{}, false, err
	}
	return next, true, nil
}

func (r *replicationRuntime) networkIsEnabled() bool {
	var enabled int
	return r.db.QueryRow(`SELECT network_enabled FROM replication_local_state WHERE state_id=1`).Scan(&enabled) == nil && enabled == 1
}

func (r *replicationRuntime) suppressDialFailure(nodeUUID string, control *replicationDialerControl, revision uint64) bool {
	if r.ctx.Err() != nil || r.controlChanged(control, revision) || !r.networkIsEnabled() {
		return true
	}
	config, err := r.loadPeerRuntimeConfig(r.ctx, nodeUUID)
	return err != nil || !config.Enabled || !config.ReconnectEnabled || config.Role != ReplicationDial
}

func (r *replicationRuntime) fallbackRetryWait(control *replicationDialerControl, p peerRuntimeConfig) bool {
	delay := p.ReconnectInitial
	if delay <= 0 {
		delay = time.Second
	}
	return waitForReplicationDialer(r.ctx, control, delay)
}
