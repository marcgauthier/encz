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
	domain     = "10nodes-replication-test"
	credential = "local-link"
	totalNodes = 10
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
	index               int
	name, id, key, path string
	db                  *sqliteseal.DB
	creds               *credentials
	verify              verifier
	insertTarget        int
	updateTarget        int
	seq                 int64
	updatesDone         int64
}

type item struct {
	ID        string `json:"id"`
	NodeID    string `json:"node_id"`
	Payload   string `json:"payload"`
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
}

func main() {
	duration := flag.Duration("duration", 3*time.Minute, "overall test duration")
	interval := flag.Duration("interval", 10*time.Second, "tick interval for inserts & updates")
	flag.Parse()

	if err := run(*duration, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(duration, interval time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDir := filepath.Join("runs", time.Now().Format("20060102-150405.000"))
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return err
	}
	fmt.Printf("Artifacts directory: %s\n", runDir)
	fmt.Printf("Starting 10-Node Mesh Replication Test (Duration: %v, Interval: %v)\n\n", duration, interval)

	pki, signPriv, signPub, psk, err := make10NodePKI()
	if err != nil {
		return fmt.Errorf("make PKI: %w", err)
	}

	// 10 Node UUIDs
	nodeUUIDs := make([]string, totalNodes)
	for i := 0; i < totalNodes; i++ {
		nodeUUIDs[i] = fmt.Sprintf("%08d-0000-4000-8000-%012d", i+1, i+1)
	}

	// Listen addresses (Node 1 acts as primary listener hub, other nodes listen too for mesh)
	addrs := make([]string, totalNodes)
	for i := 0; i < totalNodes; i++ {
		addr, err := freeAddress()
		if err != nil {
			return err
		}
		addrs[i] = addr
	}

	// Workload profiles:
	// Nodes 0, 1, 2 (Heavy): 300 inserts, 30 updates
	// Nodes 3, 4, 5 (Medium): 100 inserts, 15 updates
	// Nodes 6, 7, 8 (Light): 20 inserts, 5 updates
	// Node 9 (Zero): 0 inserts, 0 updates (Read-only node)
	workloads := []struct{ inserts, updates int }{
		{300, 30}, {300, 30}, {300, 30}, // Heavy
		{100, 15}, {100, 15}, {100, 15}, // Medium
		{20, 5}, {20, 5}, {20, 5}, // Light
		{0, 0}, // Zero-insert node
	}

	nodes := make([]*node, totalNodes)
	for i := 0; i < totalNodes; i++ {
		name := fmt.Sprintf("node-%02d", i+1)
		nodes[i] = &node{
			index:        i,
			name:         name,
			id:           nodeUUIDs[i],
			key:          fmt.Sprintf("key-for-%s", name),
			path:         filepath.Join(runDir, name+".db"),
			creds:        &credentials{cert: pki.certs[i], roots: pki.roots, psk: psk},
			verify:       verifier{key: signPub},
			insertTarget: workloads[i].inserts,
			updateTarget: workloads[i].updates,
		}
	}

	// Open all nodes
	for i := 0; i < totalNodes; i++ {
		if err = openNode(ctx, nodes[i], addrs[i]); err != nil {
			return fmt.Errorf("open node %s: %w", nodes[i].name, err)
		}
		defer func(n *node) {
			if n.db != nil {
				_ = n.db.Close()
			}
		}(nodes[i])
	}

	// Configure peers for fully connected star/mesh topology
	// Node 0 dials everyone else; Nodes 1..9 dial Node 0 and listening peers
	for i := 0; i < totalNodes; i++ {
		for j := 0; j < totalNodes; j++ {
			if i == j {
				continue
			}
			// Role of j as seen from node i
			role := sqliteseal.ReplicationAccept
			if i > j {
				role = sqliteseal.ReplicationDial
			}
			peerCfg := sqliteseal.PeerConfig{
				NodeUUID:          nodes[j].id,
				IncarnationUUID:   mustStatus(ctx, nodes[j].db).IncarnationUUID,
				NodeName:          nodes[j].name,
				Address:           addrs[j],
				ListenEnabled:     true,
				Role:              role,
				AuthMode:          sqliteseal.ReplicationAuthPSK,
				CredentialName:    credential,
				Enabled:           true,
				HeartbeatInterval: 150 * time.Millisecond,
				HeartbeatTimeout:  5 * time.Second,
			}
			if err = nodes[i].db.UpsertReplicationPeer(ctx, peerCfg); err != nil {
				return fmt.Errorf("upsert peer on %s for %s: %w", nodes[i].name, nodes[j].name, err)
			}
		}
	}

	// Build & apply MembershipManifest across all 10 nodes
	manifestNodes := make([]sqliteseal.MembershipNode, totalNodes)
	for i := 0; i < totalNodes; i++ {
		roleMap := make(map[string]sqliteseal.ReplicationConnectionRole)
		for j := 0; j < totalNodes; j++ {
			if i == j {
				continue
			}
			// Role of connection from node i to node j
			if i > j {
				roleMap[nodes[j].id] = sqliteseal.ReplicationDial
			} else {
				roleMap[nodes[j].id] = sqliteseal.ReplicationAccept
			}
		}
		manifestNodes[i] = sqliteseal.MembershipNode{
			NodeUUID:        nodes[i].id,
			Level:           i,
			IncarnationUUID: mustStatus(ctx, nodes[i].db).IncarnationUUID,
			State:           "active",
			ListenEnabled:   true,
			RoleByPeer:      roleMap,
		}
	}

	manifest := sqliteseal.MembershipManifest{
		Epoch:      2,
		Domain:     domain,
		PolicyHash: "10nodes-test-policy-v1",
		Nodes:      manifestNodes,
	}
	manifest.Signature = signManifest(manifest, signPriv)

	for i := 0; i < totalNodes; i++ {
		if err = nodes[i].db.ApplyMembershipManifest(ctx, manifest); err != nil {
			return fmt.Errorf("apply manifest to %s: %w", nodes[i].name, err)
		}
	}

	// Wait for peer connections to establish
	fmt.Println("Connecting 10-node replication cluster...")
	for i := 0; i < totalNodes; i++ {
		for j := 0; j < totalNodes; j++ {
			if i > j {
				if err = waitConnected(ctx, nodes[i].db, nodes[j].id); err != nil {
					return fmt.Errorf("wait connected %s -> %s: %w", nodes[i].name, nodes[j].name, err)
				}
			}
		}
	}
	fmt.Println("All 10 nodes fully connected & replication active.")
	fmt.Println("\nWorkload profiles:")
	fmt.Println("  Nodes 1-3 (Heavy):  300 inserts, 30 updates per 10s tick")
	fmt.Println("  Nodes 4-6 (Medium): 100 inserts, 15 updates per 10s tick")
	fmt.Println("  Nodes 7-9 (Light):   20 inserts,  5 updates per 10s tick")
	fmt.Println("  Node 10   (Zero):     0 inserts,  0 updates (Read-Only Listener)")

	startTime := time.Now()
	endTime := startTime.Add(duration)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	tickNum := 0
	performMeshTick(ctx, nodes, startTime, tickNum)

loop:
	for {
		select {
		case t := <-ticker.C:
			tickNum++
			performMeshTick(ctx, nodes, startTime, tickNum)
			if t.After(endTime) || t.Equal(endTime) {
				break loop
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	fmt.Println("\n=====================================================================================================")
	fmt.Println("Duration reached. Stopping inserts and updates. Draining replication streams across 10 nodes...")

	drainStart := time.Now()
	if err = waitMeshSync(ctx, nodes); err != nil {
		return fmt.Errorf("mesh sync failed: %w", err)
	}
	fmt.Printf("All 10 nodes fully synchronized in %v.\n\n", time.Since(drainStart).Round(time.Millisecond))

	// Print final stats table
	fmt.Println("Final Node Statistics:")
	fmt.Printf("%-8s | %-12s | %-15s | %-15s | %-15s\n", "Node", "Total Rows", "Created Locally", "Remote Received", "Updates Made")
	fmt.Println("----------------------------------------------------------------------------------")
	for i := 0; i < totalNodes; i++ {
		local, remote, _ := getNodeCounts(ctx, nodes[i].db, nodes[i].id)
		fmt.Printf("%-8s | %-12d | %-15d | %-15d | %-15d\n",
			nodes[i].name, local+remote, local, remote, atomic.LoadInt64(&nodes[i].updatesDone))
	}

	// Full dataset comparison across all 10 nodes
	fmt.Println("\nVerifying data consistency across all 10 database nodes...")
	firstRows, err := rows(ctx, nodes[0].db)
	if err != nil {
		return fmt.Errorf("read rows node-01: %w", err)
	}
	firstJson, _ := json.Marshal(firstRows)

	for i := 1; i < totalNodes; i++ {
		nodeRows, err := rows(ctx, nodes[i].db)
		if err != nil {
			return fmt.Errorf("read rows %s: %w", nodes[i].name, err)
		}
		nodeJson, _ := json.Marshal(nodeRows)
		if string(firstJson) != string(nodeJson) {
			if len(firstRows) != len(nodeRows) {
				return fmt.Errorf("DATABASE DIVERGENCE DETECTED: row count mismatch between node-01 (%d rows) and %s (%d rows)",
					len(firstRows), nodes[i].name, len(nodeRows))
			}
			for k := 0; k < len(firstRows); k++ {
				if firstRows[k] != nodeRows[k] {
					return fmt.Errorf("DATABASE DIVERGENCE DETECTED between node-01 and %s at row #%d (ID: %s):\n  node-01: %+v\n  %s: %+v",
						nodes[i].name, k, firstRows[k].ID, firstRows[k], nodes[i].name, nodeRows[k])
				}
			}
		}
	}

	// Integrity checks
	for i := 0; i < totalNodes; i++ {
		var result string
		if err = nodes[i].db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil || result != "ok" {
			return fmt.Errorf("integrity check failed on %s: result=%s err=%v", nodes[i].name, result, err)
		}
	}

	fmt.Printf("\nSUCCESS: All 10 database nodes contain identical data (%d total rows)!\n", len(firstRows))
	return nil
}

func performMeshTick(ctx context.Context, nodes []*node, startTime time.Time, tickNum int) {
	var wg sync.WaitGroup

	for i := 0; i < totalNodes; i++ {
		n := nodes[i]
		if n.insertTarget > 0 || n.updateTarget > 0 {
			wg.Add(1)
			go func(targetNode *node) {
				defer wg.Done()
				_ = executeNodeWorkload(ctx, targetNode)
			}(n)
		}
	}
	wg.Wait()

	elapsed := time.Since(startTime).Truncate(time.Second)
	fmt.Printf("\n--- [%02d:%02d] Tick #%d Summary ---\n", int(elapsed.Minutes()), int(elapsed.Seconds())%60, tickNum)
	fmt.Printf("%-8s | %-12s | %-15s | %-15s | %-15s\n", "Node", "Total Rows", "Created (Local)", "Received (Rem)", "Updates Made")
	fmt.Println("----------------------------------------------------------------------------------")
	for i := 0; i < totalNodes; i++ {
		local, remote, _ := getNodeCounts(ctx, nodes[i].db, nodes[i].id)
		fmt.Printf("%-8s | %-12d | %-15d | %-15d | %-15d\n",
			nodes[i].name, local+remote, local, remote, atomic.LoadInt64(&nodes[i].updatesDone))
	}
}

func executeNodeWorkload(ctx context.Context, n *node) error {
	// 1. Bulk Inserts
	if n.insertTarget > 0 {
		tx, err := n.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO items(id, node_id, payload, note, updated_at) VALUES(?, ?, ?, ?, ?)`)
		if err != nil {
			tx.Rollback()
			return err
		}

		for i := 0; i < n.insertTarget; i++ {
			time.Sleep(10 * time.Microsecond)
			seq := atomic.AddInt64(&n.seq, 1)
			id := fmt.Sprintf("%s-%010d", n.id[:8], seq)
			payload := fmt.Sprintf("payload-%s-%d", n.name, seq)
			note := fmt.Sprintf("created by %s", n.name)
			if _, err := stmt.ExecContext(ctx, id, n.id, payload, note, now()); err != nil {
				stmt.Close()
				tx.Rollback()
				return err
			}
		}
		stmt.Close()
		if err = tx.Commit(); err != nil {
			return err
		}
	}

	// 2. Random Updates on items (including items originated by remote nodes)
	if n.updateTarget > 0 {
		// Select random sample of item IDs
		rs, err := n.db.QueryContext(ctx, `SELECT id FROM items ORDER BY random() LIMIT ?`, n.updateTarget)
		if err == nil {
			var ids []string
			for rs.Next() {
				var id string
				if err = rs.Scan(&id); err == nil {
					ids = append(ids, id)
				}
			}
			rs.Close()

			if len(ids) > 0 {
				tx, err := n.db.BeginTx(ctx, nil)
				if err == nil {
					stmt, err := tx.PrepareContext(ctx, `UPDATE items SET note = ?, updated_at = ? WHERE id = ?`)
					if err == nil {
						for _, id := range ids {
							time.Sleep(10 * time.Microsecond)
							newNote := fmt.Sprintf("updated by %s at %s", n.name, time.Now().Format("15:04:05.000000"))
							if _, err = stmt.ExecContext(ctx, newNote, now(), id); err == nil {
								atomic.AddInt64(&n.updatesDone, 1)
							}
						}
						stmt.Close()
					}
					_ = tx.Commit()
				}
			}
		}
	}

	return nil
}

func getNodeCounts(ctx context.Context, db *sqliteseal.DB, nodeID string) (localCount int, remoteCount int, err error) {
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE node_id = ?`, nodeID).Scan(&localCount)
	if err != nil {
		return 0, 0, err
	}
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM items WHERE node_id != ?`, nodeID).Scan(&remoteCount)
	if err != nil {
		return 0, 0, err
	}
	return localCount, remoteCount, nil
}

func waitMeshSync(ctx context.Context, nodes []*node) error {
	syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	drainStart := time.Now()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	doneCh := make(chan error, 1)
	go func() {
		for i := 0; i < totalNodes; i++ {
			for j := 0; j < totalNodes; j++ {
				if i == j {
					continue
				}
				if err := waitCounter(syncCtx, nodes[i].db, nodes[j].db, nodes[j].id); err != nil {
					doneCh <- fmt.Errorf("sync wait %s -> %s: %w", nodes[i].name, nodes[j].name, err)
					return
				}
			}
		}
		doneCh <- nil
	}()

	for {
		select {
		case err := <-doneCh:
			if err == nil {
				// Final status print
				printMeshSyncProgress(syncCtx, nodes, drainStart, true)
			}
			return err
		case <-ticker.C:
			printMeshSyncProgress(syncCtx, nodes, drainStart, false)
		case <-syncCtx.Done():
			return syncCtx.Err()
		}
	}
}

func printMeshSyncProgress(ctx context.Context, nodes []*node, startTime time.Time, finished bool) {
	totalPairs := totalNodes * (totalNodes - 1)
	syncedPairs := 0
	var totalLag int64 = 0
	var maxLag int64 = 0

	// Gather stats across all nodes
	for i := 0; i < totalNodes; i++ {
		for j := 0; j < totalNodes; j++ {
			if i == j {
				continue
			}
			// Node j is source (origin), Node i is dst (tracking)
			srcStats, err1 := nodes[j].db.ReplicationSyncStats(ctx)
			dstStats, err2 := nodes[i].db.ReplicationSyncStats(ctx)
			if err1 != nil || err2 != nil {
				continue
			}

			targetCounter := srcStats.LastOriginCounter
			var currentCounter int64 = 0
			for _, pc := range dstStats.PeerCursors {
				if pc.OriginNodeUUID == nodes[j].id {
					currentCounter = pc.ContiguousCounter
					break
				}
			}

			if currentCounter >= targetCounter {
				syncedPairs++
			} else {
				lag := targetCounter - currentCounter
				totalLag += lag
				if lag > maxLag {
					maxLag = lag
				}
			}
		}
	}

	elapsed := time.Since(startTime).Round(time.Second)
	if finished {
		fmt.Printf("[Drain Progress %02d:%02d] Complete! All %d/%d node pairs fully synchronized (0 remaining lag).\n",
			int(elapsed.Minutes()), int(elapsed.Seconds())%60, syncedPairs, totalPairs)
	} else {
		fmt.Printf("[Drain Progress %02d:%02d] %d/%d node pairs synchronized (total lag: %d events, max lag: %d events)...\n",
			int(elapsed.Minutes()), int(elapsed.Seconds())%60, syncedPairs, totalPairs, totalLag, maxLag)
	}
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
	if _, err = db.ExecContext(ctx, `CREATE TABLE items(id TEXT PRIMARY KEY, node_id TEXT, payload TEXT, note TEXT, updated_at TEXT)`); err != nil {
		return err
	}
	return db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{
		NodeUUID:          n.id,
		NodeName:          n.name,
		ReplicationDomain: domain,
		Level:             n.index,
		ListenAddress:     listen,
		AuthMode:          sqliteseal.ReplicationAuthPSK,
		CredentialName:    credential,
	}, []sqliteseal.ReplicatedTable{{Name: "items"}})
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
	rs, err := db.QueryContext(ctx, `SELECT id, node_id, payload, note, updated_at FROM items ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []item
	for rs.Next() {
		var x item
		if err = rs.Scan(&x.ID, &x.NodeID, &x.Payload, &x.Note, &x.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rs.Err()
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

type pki10Node struct {
	certs []tls.Certificate
	roots *x509.CertPool
}

func make10NodePKI() (pki10Node, ed25519.PrivateKey, ed25519.PublicKey, []byte, error) {
	pub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SQLiteSeal 10Node test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, e := x509.CreateCertificate(rand.Reader, caTpl, caTpl, pub, caKey)
	if e != nil {
		return pki10Node{}, nil, nil, nil, e
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		return pki10Node{}, nil, nil, nil, e
	}

	certs := make([]tls.Certificate, totalNodes)
	for i := 0; i < totalNodes; i++ {
		p, k, _ := ed25519.GenerateKey(rand.Reader)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: fmt.Sprintf("node-%02d", i+1)},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, e := x509.CreateCertificate(rand.Reader, tpl, ca, p, caKey)
		if e != nil {
			return pki10Node{}, nil, nil, nil, e
		}
		certs[i] = tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	_, e = rand.Read(psk)
	return pki10Node{certs: certs, roots: roots}, signPriv, signPub, psk, e
}
