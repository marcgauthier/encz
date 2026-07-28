package sqliteseal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type replicationIdentityGuard struct {
	NodeUUID           string `json:"node_uuid"`
	IncarnationUUID    string `json:"incarnation_uuid"`
	DatabaseGeneration int64  `json:"database_generation"`
	Counter            int64  `json:"counter"`
	MAC                string `json:"mac"`
}

func (r *replicationRuntime) guardPath() string {
	if r.opts != nil && r.opts.IdentityGuardPath != "" {
		return r.opts.IdentityGuardPath
	}
	return r.db.path + ".replication-identity"
}
func (r *replicationRuntime) guardKey() ([]byte, error) {
	r.db.mu.RLock()
	defer r.db.mu.RUnlock()
	if r.db.key == nil {
		return nil, ErrDBClosed
	}
	h := sha256.New()
	h.Write([]byte("SQLiteSeal replication identity guard v1\x00"))
	h.Write(r.db.key.Bytes())
	return h.Sum(nil), nil
}
func guardMAC(key []byte, g replicationIdentityGuard) string {
	g.MAC = ""
	raw, _ := json.Marshal(g)
	m := hmac.New(sha256.New, key)
	m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}
func (r *replicationRuntime) validateIdentityGuard() error {
	var g replicationIdentityGuard
	var node, inc string
	var generation, counter int64
	if err := r.db.QueryRow(`SELECT local_node_uuid,local_incarnation_uuid,database_generation,last_origin_counter FROM replication_local_state`).Scan(&node, &inc, &generation, &counter); err != nil {
		return err
	}
	raw, err := os.ReadFile(r.guardPath())
	if errors.Is(err, os.ErrNotExist) {
		return r.updateIdentityGuard()
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &g); err != nil {
		return fmt.Errorf("identity guard: %w", err)
	}
	key, err := r.guardKey()
	if err != nil {
		return err
	}
	defer wipeBytes(key)
	if !hmac.Equal([]byte(g.MAC), []byte(guardMAC(key, g))) {
		return errors.New("replication identity guard authentication failed")
	}
	if g.NodeUUID != node || g.IncarnationUUID != inc || g.DatabaseGeneration != generation || g.Counter > counter {
		_, _ = r.db.Exec(`UPDATE replication_local_state SET network_enabled=0,blocked_reason=?`, ErrReplicationIdentityRollback.Error())
		return ErrReplicationIdentityRollback
	}
	if g.Counter < counter {
		return r.updateIdentityGuard()
	}
	return nil
}
func (r *replicationRuntime) updateIdentityGuard() error {
	var g replicationIdentityGuard
	if err := r.db.QueryRow(`SELECT local_node_uuid,local_incarnation_uuid,database_generation,last_origin_counter FROM replication_local_state`).Scan(&g.NodeUUID, &g.IncarnationUUID, &g.DatabaseGeneration, &g.Counter); err != nil {
		return err
	}
	key, err := r.guardKey()
	if err != nil {
		return err
	}
	g.MAC = guardMAC(key, g)
	wipeBytes(key)
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	path := r.guardPath()
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
