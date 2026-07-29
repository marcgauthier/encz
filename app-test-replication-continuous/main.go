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
	"sync"
	"sync/atomic"
	"time"

	sqliteseal "github.com/marcgauthier/SQLiteSeal"
)

const (
	nodeAID    = "10000000-0000-4000-8000-000000000001"
	nodeBID    = "20000000-0000-4000-8000-000000000002"
	domain     = "continuous-replication-test"
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
	ID        string
	NodeID    string
	Payload   string
	UpdatedAt string
}

func main() {
	duration := flag.Duration("duration", 5*time.Minute, "duration to execute continuous bulk inserts")
	interval := flag.Duration("interval", 10*time.Second, "interval between bulk inserts")
	batchSize := flag.Int("batch-size", 500, "number of items created per node each interval")
	flag.Parse()

	if err := run(*duration, *interval, *batchSize); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(duration, interval time.Duration, batchSize int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDir := filepath.Join("runs", time.Now().Format("20060102-150405.000"))
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return err
	}
	fmt.Printf("Artifacts directory: %s\n", runDir)
	fmt.Printf("Starting continuous replication test (Duration: %v, Interval: %v, Batch Size: %d rows/node/tick)\n\n", duration, interval, batchSize)

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
		return fmt.Errorf("open A: %w", err)
	}
	defer func() {
		if a.db != nil {
			_ = a.db.Close()
		}
	}()

	if err = openNode(ctx, &b, addr); err != nil {
		return fmt.Errorf("open B: %w", err)
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

	manifest := sqliteseal.MembershipManifest{
		Epoch:      2,
		Domain:     domain,
		PolicyHash: "continuous-test-policy-v1",
		Nodes: []sqliteseal.MembershipNode{
			{NodeUUID: a.id, Level: a.level, IncarnationUUID: mustStatus(ctx, a.db).IncarnationUUID, State: "active", ListenEnabled: false, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{b.id: sqliteseal.ReplicationDial}},
			{NodeUUID: b.id, Level: b.level, IncarnationUUID: mustStatus(ctx, b.db).IncarnationUUID, State: "active", ListenEnabled: true, RoleByPeer: map[string]sqliteseal.ReplicationConnectionRole{a.id: sqliteseal.ReplicationAccept}},
		},
	}
	manifest.Signature = signManifest(manifest, signPriv)

	if err = a.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate A: %w", err)
	}
	if err = b.db.ApplyMembershipManifest(ctx, manifest); err != nil {
		return fmt.Errorf("activate B: %w", err)
	}

	if err = waitConnected(ctx, a.db, b.id); err != nil {
		return fmt.Errorf("connecting nodes: %w", err)
	}
	fmt.Println("Nodes A and B connected and replication active.")

	startTime := time.Now()
	endTime := startTime.Add(duration)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var sequenceA int64
	var sequenceB int64

	fmt.Println("----------------------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-10s | %-38s | %-38s\n", "Elapsed", "Node A (UUID: ...0001)", "Node B (UUID: ...0002)")
	fmt.Printf("%-10s | %-18s %-19s | %-18s %-19s\n", "", "Created (Local)", "Received (Remote)", "Created (Local)", "Received (Remote)")
	fmt.Println("----------------------------------------------------------------------------------------------------------------------")

	// Perform initial tick at t=0s
	tickNum := 0
	performInsertAndLog(ctx, a, b, batchSize, &sequenceA, &sequenceB, startTime, tickNum)

loop:
	for {
		select {
		case t := <-ticker.C:
			tickNum++
			performInsertAndLog(ctx, a, b, batchSize, &sequenceA, &sequenceB, startTime, tickNum)
			if t.After(endTime) || t.Equal(endTime) {
				break loop
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	fmt.Println("----------------------------------------------------------------------------------------------------------------------")
	fmt.Printf("\n5 minutes elapsed. Stopping insertions. Waiting for replication to drain and sync...\n")

	// Drain / catch up phase
	drainStart := time.Now()
	if err = waitBoth(ctx, a, b); err != nil {
		return fmt.Errorf("drain sync failed: %w", err)
	}
	fmt.Printf("Replication drained and synchronized in %v.\n\n", time.Since(drainStart).Round(time.Millisecond))

	// Final stats print
	countALocal, countARemote, err := getNodeCounts(ctx, a.db, a.id, b.id)
	if err != nil {
		return fmt.Errorf("count A error: %w", err)
	}
	countBLocal, countBRemote, err := getNodeCounts(ctx, b.db, b.id, a.id)
	if err != nil {
		return fmt.Errorf("count B error: %w", err)
	}

	fmt.Println("Final Node Statistics:")
	fmt.Printf("  Node A Total Rows: %d (Created Locally: %d, Received from B: %d)\n", countALocal+countARemote, countALocal, countARemote)
	fmt.Printf("  Node B Total Rows: %d (Created Locally: %d, Received from A: %d)\n", countBLocal+countBRemote, countBLocal, countBRemote)

	// Compare database contents
	fmt.Println("\nComparing database contents between Node A and Node B...")
	if err = compareAll(ctx, a.db, b.db); err != nil {
		return fmt.Errorf("data mismatch verification failed: %w", err)
	}

	// Integrity checks
	for _, n := range []node{a, b} {
		var result string
		if err = n.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
			return fmt.Errorf("integrity check failed on %s: result=%s err=%v", n.name, result, err)
		}
	}

	fmt.Println("\nSUCCESS: Databases are 100% identical across all rows, payload, and timestamps!")
	return nil
}

func performInsertAndLog(ctx context.Context, a, b node, batchSize int, seqA, seqB *int64, startTime time.Time, tickNum int) {
	var wg sync.WaitGroup
	var errA, errB error

	wg.Add(2)
	go func() {
		defer wg.Done()
		errA = bulkInsert(ctx, a.db, a.id, batchSize, seqA)
	}()
	go func() {
		defer wg.Done()
		errB = bulkInsert(ctx, b.db, b.id, batchSize, seqB)
	}()
	wg.Wait()

	if errA != nil {
		fmt.Fprintf(os.Stderr, "Error inserting into Node A: %v\n", errA)
	}
	if errB != nil {
		fmt.Fprintf(os.Stderr, "Error inserting into Node B: %v\n", errB)
	}

	// Query counts
	countALocal, countARemote, _ := getNodeCounts(ctx, a.db, a.id, b.id)
	countBLocal, countBRemote, _ := getNodeCounts(ctx, b.db, b.id, a.id)

	elapsed := time.Since(startTime).Truncate(time.Second)
	fmt.Printf("%-10s | %-18d %-19d | %-18d %-19d\n",
		fmt.Sprintf("[%02d:%02d]", int(elapsed.Minutes()), int(elapsed.Seconds())%60),
		countALocal, countARemote,
		countBLocal, countBRemote,
	)
}

func bulkInsert(ctx context.Context, db *sqliteseal.DB, nodeID string, count int, seqCounter *int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO items(id, node_id, payload, updated_at) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := 0; i < count; i++ {
		seq := atomic.AddInt64(seqCounter, 1)
		id := fmt.Sprintf("%s-%010d", nodeID[:8], seq)
		payload := fmt.Sprintf("payload-data-item-%d-from-%s", seq, nodeID[:8])
		if _, err := stmt.ExecContext(ctx, id, nodeID, payload, now()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func getNodeCounts(ctx context.Context, db *sqliteseal.DB, localNodeID, remoteNodeID string) (localCount int, remoteCount int, err error) {
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE node_id = ?`, localNodeID).Scan(&localCount)
	if err != nil {
		return 0, 0, err
	}
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE node_id = ?`, remoteNodeID).Scan(&remoteCount)
	if err != nil {
		return 0, 0, err
	}
	return localCount, remoteCount, nil
}

func openNode(ctx context.Context, n *node, listen string) error {
	opts := sqliteseal.Options{
		Key:         n.key,
		JournalMode: "WAL",
		Replication: &sqliteseal.ReplicationRuntimeOptions{
			Credentials:        n.creds,
			MembershipVerifier: n.verify,
		},
	}
	db, err := sqliteseal.OpenWithOptions(n.path, opts)
	if err != nil {
		return err
	}
	n.db = db
	if _, err = db.ExecContext(ctx, `CREATE TABLE items(id TEXT PRIMARY KEY, node_id TEXT, payload TEXT, updated_at TEXT)`); err != nil {
		return err
	}
	return db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{NodeUUID: n.id, NodeName: n.name, ReplicationDomain: domain, ListenAddress: listen, Level: n.level, AuthMode: sqliteseal.ReplicationAuthPSK, CredentialName: credential}, []sqliteseal.ReplicatedTable{{Name: "items"}})
}

func peer(n node, addr string, role sqliteseal.ReplicationConnectionRole, listens bool) sqliteseal.PeerConfig {
	return sqliteseal.PeerConfig{NodeUUID: n.id, IncarnationUUID: mustStatus(context.Background(), n.db).IncarnationUUID, NodeName: n.name, Address: addr, ListenEnabled: listens, Role: role, AuthMode: sqliteseal.ReplicationAuthPSK, CredentialName: credential, Enabled: true}
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
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func rows(ctx context.Context, db *sqliteseal.DB) ([]item, error) {
	rs, err := db.QueryContext(ctx, `SELECT id, node_id, payload, updated_at FROM items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []item
	for rs.Next() {
		var x item
		if err = rs.Scan(&x.ID, &x.NodeID, &x.Payload, &x.UpdatedAt); err != nil {
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
		return fmt.Errorf("databases diverged! Node A row count: %d, Node B row count: %d", len(x), len(y))
	}
	return nil
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
