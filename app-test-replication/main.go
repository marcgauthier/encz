package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
)

const (
	nodeAID    = "10000000-0000-4000-8000-000000000001"
	nodeBID    = "20000000-0000-4000-8000-000000000002"
	domain     = "local-replication-test"
	credential = "local-link"
)

type credentials struct {
	cert  tls.Certificate
	roots *x509.CertPool
	psk   []byte
}

func (c *credentials) PSK(context.Context, string) ([]byte, error) {
	return append([]byte(nil), c.psk...), nil
}
func (c *credentials) TLSConfig(_ context.Context, _ string, server bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.cert}, RootCAs: c.roots, ClientCAs: c.roots, ServerName: "localhost"}
	if server {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

type verifier struct{ key ed25519.PublicKey }

func (v verifier) VerifyMembership(_ context.Context, b, s []byte) error {
	if !ed25519.Verify(v.key, b, s) {
		return errors.New("membership signature rejected")
	}
	return nil
}

type node struct {
	name, id, key, path string
	level               int
	db                  *sqliteseal.DB
	creds               *credentials
	verify              verifier
}
type item struct {
	ID, Name      string
	Quantity      int
	Note, Updated string
}

func main() {
	timeout := flag.Duration("timeout", 60*time.Second, "overall test timeout")
	flag.Parse()
	if err := run(*timeout); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}
func run(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runDir := filepath.Join("runs", time.Now().Format("20060102-150405.000"))
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return err
	}
	fmt.Printf("artifacts: %s\n", runDir)
	pki, signPriv, signPub, psk, err := makePKI()
	if err != nil {
		return err
	}
	addr, err := freeAddress()
	if err != nil {
		return err
	}
	a := node{level: 0, name: "node-a", id: nodeAID, key: "node-a-encryption-key", path: filepath.Join(runDir, "node-a.db"), creds: &credentials{pki.a, pki.roots, psk}, verify: verifier{signPub}}
	b := node{level: 1, name: "node-b", id: nodeBID, key: "node-b-encryption-key", path: filepath.Join(runDir, "node-b.db"), creds: &credentials{pki.b, pki.roots, psk}, verify: verifier{signPub}}
	if err = openNode(ctx, &a, ""); err != nil {
		return err
	}
	defer func() {
		if a.db != nil {
			_ = a.db.Close()
		}
	}()
	if err = openNode(ctx, &b, addr); err != nil {
		return err
	}
	defer func() {
		if b.db != nil {
			_ = b.db.Close()
		}
	}()
	if err = a.db.UpsertReplicationPeer(ctx, peer(b, addr, sqliteseal.ReplicationDial, true)); err != nil {
		return fmt.Errorf("stage A peer: %w", err)
	}
	if err = b.db.UpsertReplicationPeer(ctx, peer(a, "127.0.0.1:1", sqliteseal.ReplicationAccept, false)); err != nil {
		return fmt.Errorf("stage B peer: %w", err)
	}
	manifest := sqliteseal.MembershipManifest{Epoch: 2, Domain: domain, PolicyHash: "local-test-policy-v1", Nodes: []sqliteseal.MembershipNode{{NodeUUID: a.id, Level: a.level, IncarnationUUID: mustStatus(ctx, a.db).IncarnationUUID, State: "active", ListenEnabled: false, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{b.id: sqliteseal.ReplicationDial}}, {NodeUUID: b.id, Level: b.level, IncarnationUUID: mustStatus(ctx, b.db).IncarnationUUID, State: "active", ListenEnabled: true, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{a.id: sqliteseal.ReplicationAccept}}}}
	manifest.Signature = signManifest(manifest, signPriv)
	if err = a.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate A: %w", err)
	}
	if err = b.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate B: %w", err)
	}
	if err = waitConnected(ctx, a.db, b.id); err != nil {
		return err
	}
	if err = verifyControlPlane(ctx, a, b); err != nil {
		return err
	}
	pass("status, administrative authentication, credential reload, and API guards")
	if _, err = a.db.ExecContext(ctx, `INSERT INTO items VALUES('from-a','alpha',1,'A insert',?)`, now()); err != nil {
		return err
	}
	if err = waitCounter(ctx, b.db, a.db, a.id); err != nil {
		return err
	}
	if err = expectItem(ctx, b.db, "from-a", "alpha", 1, "A insert"); err != nil {
		return err
	}
	pass("A to B insert")
	if _, err = b.db.ExecContext(ctx, `INSERT INTO items VALUES('from-b','bravo',2,'B insert',?)`, now()); err != nil {
		return err
	}
	if err = waitCounter(ctx, a.db, b.db, b.id); err != nil {
		return err
	}
	if err = expectItem(ctx, a.db, "from-b", "bravo", 2, "B insert"); err != nil {
		return err
	}
	pass("B to A insert")
	if err = a.db.PauseReplication(ctx); err != nil {
		return err
	}
	if err = b.db.PauseReplication(ctx); err != nil {
		return err
	}
	_, _ = a.db.ExecContext(ctx, `INSERT INTO items VALUES('offline-a','away',3,'offline',?)`, now())
	_, _ = b.db.ExecContext(ctx, `INSERT INTO items VALUES('offline-b','back',4,'offline',?)`, now())
	if err = b.db.ResumeReplication(ctx); err != nil {
		return err
	}
	if err = a.db.ResumeReplication(ctx); err != nil {
		return err
	}
	if err = waitBoth(ctx, a, b); err != nil {
		return err
	}
	pass("offline catch-up")
	if _, err = a.db.ExecContext(ctx, `INSERT INTO items VALUES('shared','base',10,'base',?)`, now()); err != nil {
		return err
	}
	if err = waitCounter(ctx, b.db, a.db, a.id); err != nil {
		return err
	}
	_ = a.db.PauseReplication(ctx)
	_ = b.db.PauseReplication(ctx)
	_, _ = a.db.ExecContext(ctx, `UPDATE items SET name='name-from-a',updated_at=? WHERE id='shared'`, now())
	_, _ = b.db.ExecContext(ctx, `UPDATE items SET quantity=77,updated_at=? WHERE id='shared'`, now())
	_ = b.db.ResumeReplication(ctx)
	_ = a.db.ResumeReplication(ctx)
	if err = waitBoth(ctx, a, b); err != nil {
		return err
	}
	if err = expectItemFields(ctx, a.db, b.db, "shared", "name-from-a", 77); err != nil {
		return err
	}
	pass("per-field merge")
	_ = a.db.PauseReplication(ctx)
	_ = b.db.PauseReplication(ctx)
	_, _ = a.db.ExecContext(ctx, `UPDATE items SET note='winner-a',updated_at=? WHERE id='shared'`, now())
	time.Sleep(3 * time.Millisecond)
	_, _ = b.db.ExecContext(ctx, `UPDATE items SET note='winner-b',updated_at=? WHERE id='shared'`, now())
	_ = b.db.ResumeReplication(ctx)
	_ = a.db.ResumeReplication(ctx)
	if err = waitBoth(ctx, a, b); err != nil {
		return err
	}
	if err = compareAll(ctx, a.db, b.db); err != nil {
		return err
	}
	pass("same-field deterministic convergence")
	before := eventCount(ctx, b.db)
	_ = a.db.SyncReplicationPeer(ctx, b.id)
	_ = a.db.SyncReplicationPeer(ctx, b.id)
	time.Sleep(300 * time.Millisecond)
	if after := eventCount(ctx, b.db); after != before {
		return fmt.Errorf("duplicate sync changed event count %d -> %d", before, after)
	}
	pass("duplicate-safe resync")
	_ = a.db.PauseReplication(ctx)
	_ = b.db.PauseReplication(ctx)
	_, _ = b.db.ExecContext(ctx, `UPDATE items SET note='older update',updated_at=? WHERE id='shared'`, now())
	time.Sleep(3 * time.Millisecond)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM items WHERE id='shared'`)
	_ = b.db.ResumeReplication(ctx)
	_ = a.db.ResumeReplication(ctx)
	if err = waitBoth(ctx, a, b); err != nil {
		return err
	}
	if exists(ctx, a.db, "shared") || exists(ctx, b.db, "shared") {
		return errors.New("tombstone failed to prevent resurrection")
	}
	pass("delete tombstone")
	if err = verifySnapshotCreation(ctx, a.db); err != nil {
		return err
	}
	pass("consistent snapshot creation and metadata")
	if err = a.db.Close(); err != nil {
		return err
	}
	a.db = nil
	if err = b.db.Close(); err != nil {
		return err
	}
	b.db = nil
	if err = reopenNode(&b); err != nil {
		return err
	}
	if err = reopenNode(&a); err != nil {
		return err
	}
	if err = waitConnected(ctx, a.db, b.id); err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO items VALUES('after-reopen','restart',9,'ok',?)`, now())
	if err != nil {
		return err
	}
	if err = waitCounter(ctx, b.db, a.db, a.id); err != nil {
		return err
	}
	if err = compareAll(ctx, a.db, b.db); err != nil {
		return err
	}
	pass("automatic reopen recovery")
	for _, db := range []*sqliteseal.DB{a.db, b.db} {
		var result string
		if err = db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
			return fmt.Errorf("integrity check: %s %v", result, err)
		}
	}
	if err = runAutomaticSnapshotBootstrap(ctx, runDir, pki, signPriv, signPub, psk); err != nil {
		return err
	}
	pass("automatic snapshot bootstrap after retained-history loss")
	fmt.Println("PASS: two encrypted nodes converged in every scenario")
	return nil
}
func openNode(ctx context.Context, n *node, listen string) error {
	opts := sqliteseal.Options{Key: n.key, JournalMode: "WAL", Replication: &sqliteseal.ReplicationRuntimeOptions{Credentials: n.creds, MembershipVerifier: n.verify, Logf: func(f string, a ...any) { fmt.Printf(n.name+": "+f+"\n", a...) }}}
	db, err := sqliteseal.OpenWithOptions(n.path, opts)
	if err != nil {
		return err
	}
	n.db = db
	if _, err = db.ExecContext(ctx, `CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT,quantity INTEGER,note TEXT,updated_at TEXT)`); err != nil {
		return err
	}
	return db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{NodeUUID: n.id, NodeName: n.name, ReplicationDomain: domain, ListenAddress: listen, Level: n.level, AuthMode: sqliteseal.ReplicationAuthPSK, CredentialName: credential}, []sqliteseal.ReplicatedTable{{Name: "items"}})
}
func reopenNode(n *node) error {
	db, err := sqliteseal.OpenWithOptions(n.path, sqliteseal.Options{Key: n.key, JournalMode: "WAL", Replication: &sqliteseal.ReplicationRuntimeOptions{Credentials: n.creds, MembershipVerifier: n.verify}})
	n.db = db
	return err
}
func peer(n node, addr string, role sqliteseal.ReplicationConnectionRole, listens bool) sqliteseal.PeerConfig {
	return sqliteseal.PeerConfig{NodeUUID: n.id, IncarnationUUID: mustStatus(context.Background(), n.db).IncarnationUUID, NodeName: n.name, Address: addr, ListenEnabled: listens, Role: role, AuthMode: sqliteseal.ReplicationAuthPSK, CredentialName: credential, Enabled: true, HeartbeatInterval: 150 * time.Millisecond, HeartbeatTimeout: 5 * time.Second}
}
func mustStatus(ctx context.Context, db *sqliteseal.DB) sqliteseal.ReplicationStatus {
	s, e := db.ReplicationStatus(ctx)
	if e != nil {
		panic(e)
	}
	return s
}
func waitConnected(ctx context.Context, db *sqliteseal.DB, peer string) error {
	return poll(ctx, func() bool {
		s, e := db.ReplicationStatus(ctx)
		if e != nil {
			return false
		}
		for _, p := range s.Peers {
			if p.NodeUUID == peer && p.State == "connected" {
				return true
			}
		}
		return false
	}, "peer connection")
}
func waitCounter(ctx context.Context, dst, src *sqliteseal.DB, origin string) error {
	s, e := src.ReplicationStatus(ctx)
	if e != nil {
		return e
	}
	err := dst.WaitForReplication(ctx, origin, origin, s.LastOriginCounter)
	if err != nil {
		ds, _ := dst.ReplicationStatus(context.Background())
		ss, _ := src.ReplicationStatus(context.Background())
		return fmt.Errorf("wait origin %s counter %d: %w; dst=%+v src=%+v", origin, s.LastOriginCounter, err, ds, ss)
	}
	return nil
}
func waitBoth(ctx context.Context, a, b node) error {
	if err := waitCounter(ctx, a.db, b.db, b.id); err != nil {
		return err
	}
	if err := waitCounter(ctx, b.db, a.db, a.id); err != nil {
		return err
	}
	return compareAll(ctx, a.db, b.db)
}
func poll(ctx context.Context, fn func() bool, label string) error {
	for {
		if fn() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s: %w", label, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func now() string   { return time.Now().UTC().Format(time.RFC3339Nano) }
func pass(s string) { fmt.Println("PASS:", s) }
func expectItem(ctx context.Context, db *sqliteseal.DB, id, name string, q int, note string) error {
	var got item
	if err := db.QueryRowContext(ctx, `SELECT id,name,quantity,note,updated_at FROM items WHERE id=?`, id).Scan(&got.ID, &got.Name, &got.Quantity, &got.Note, &got.Updated); err != nil {
		return err
	}
	if got.Name != name || got.Quantity != q || got.Note != note {
		return fmt.Errorf("item mismatch: %+v", got)
	}
	return nil
}
func expectItemFields(ctx context.Context, a, b *sqliteseal.DB, id, name string, q int) error {
	for _, db := range []*sqliteseal.DB{a, b} {
		var n string
		var got int
		if err := db.QueryRowContext(ctx, `SELECT name,quantity FROM items WHERE id=?`, id).Scan(&n, &got); err != nil {
			return err
		}
		if n != name || got != q {
			return fmt.Errorf("field merge mismatch name=%s quantity=%d", n, got)
		}
	}
	return nil
}
func rows(ctx context.Context, db *sqliteseal.DB) ([]item, error) {
	rs, err := db.QueryContext(ctx, `SELECT id,name,quantity,note,updated_at FROM items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []item
	for rs.Next() {
		var x item
		if err = rs.Scan(&x.ID, &x.Name, &x.Quantity, &x.Note, &x.Updated); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rs.Err()
}
func compareAll(ctx context.Context, a, b *sqliteseal.DB) error {
	x, e := rows(ctx, a)
	if e != nil {
		return e
	}
	y, e := rows(ctx, b)
	if e != nil {
		return e
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	if string(xb) != string(yb) {
		return fmt.Errorf("databases diverged\nA=%s\nB=%s", xb, yb)
	}
	return nil
}
func exists(ctx context.Context, db *sqliteseal.DB, id string) bool {
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE id=?`, id).Scan(&n)
	return n > 0
}
func eventCount(ctx context.Context, db *sqliteseal.DB) int {
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM replication_changes`).Scan(&n)
	return n
}
func signManifest(m sqliteseal.MembershipManifest, key ed25519.PrivateKey) []byte {
	sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].NodeUUID < m.Nodes[j].NodeUUID })
	m.Signature = nil
	b, _ := json.Marshal(m)
	return ed25519.Sign(key, b)
}
func freeAddress() (string, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return "", e
	}
	a := l.Addr().String()
	_ = l.Close()
	return a, nil
}

type generatedPKI struct {
	a, b  tls.Certificate
	roots *x509.CertPool
}

func makePKI() (generatedPKI, ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	pub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SQLiteSeal local test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, caTpl, caTpl, pub, caKey)
	if e != nil {
		return generatedPKI{}, nil, nil, nil, e
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		return generatedPKI{}, nil, nil, nil, e
	}
	issue := func(serial int64, name string) (tls.Certificate, error) {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, e := x509.CreateCertificate(rand.Reader, tpl, ca, p, caKey)
		if e != nil {
			return tls.Certificate{}, e
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}, nil
	}
	a, e := issue(2, "node-a")
	if e != nil {
		return generatedPKI{}, nil, nil, nil, e
	}
	b, e := issue(3, "node-b")
	if e != nil {
		return generatedPKI{}, nil, nil, nil, e
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	_, e = rand.Read(psk)
	return generatedPKI{a, b, roots}, signPriv, signPub, psk, e
}
