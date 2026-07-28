package sqliteseal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	sqlite3 "github.com/mattn/go-sqlite3"
	"sync"
	"time"
)

type replicationConnectionContext struct {
	mu   sync.RWMutex
	mode string
}

var replicationConnections sync.Map

func registerReplicationConnection(conn *sqlite3.SQLiteConn) error {
	c := &replicationConnectionContext{mode: "local"}
	replicationConnections.Store(conn, c)
	funcs := []struct {
		name string
		fn   any
		pure bool
	}{
		{"sqliteseal_replication_mode", func() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.mode }, false},
		{"sqliteseal_uuid", replicationUUID, false},
		{"sqliteseal_utc_now", func() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }, false},
		{"sqliteseal_time_us", func() int64 { return time.Now().UTC().UnixMicro() }, false},
		{"sqliteseal_time_from_us", replicationTimeFromUS, true},
		{"sqliteseal_event_uuid", replicationEventUUID, true},
		{"sqliteseal_canonical_object", canonicalRowKeySQL, true},
		{"sqliteseal_event_hash", replicationEventHashSQL, true},
		{"sqliteseal_is_nfc", replicationIsNFC, true},
		{"sqliteseal_sha256", func(v ...any) string {
			h := sha256.New()
			for _, x := range v {
				fmt.Fprintf(h, "%T:%v\x00", x, x)
			}
			return hex.EncodeToString(h.Sum(nil))
		}, false},
	}
	for _, f := range funcs {
		if err := conn.RegisterFunc(f.name, f.fn, f.pure); err != nil {
			return err
		}
	}
	return nil
}
func setReplicationConnectionMode(conn *sqlite3.SQLiteConn, mode string) (func(), error) {
	if mode != "local" && mode != "remote" && mode != "maintenance" {
		return nil, ErrReplicationInvalidConfig
	}
	v, ok := replicationConnections.Load(conn)
	if !ok {
		return nil, ErrReplicationNotReady
	}
	c := v.(*replicationConnectionContext)
	c.mu.Lock()
	old := c.mode
	c.mode = mode
	c.mu.Unlock()
	return func() { c.mu.Lock(); c.mode = old; c.mu.Unlock() }, nil
}
func replicationUUID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
