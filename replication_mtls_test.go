package sqliteseal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

type mtlsTestCredentials struct {
	certificate tls.Certificate
	roots       *x509.CertPool
}

func (p mtlsTestCredentials) PSK(context.Context, string) ([]byte, error) {
	return nil, errors.New("PSK is not configured")
}
func (p mtlsTestCredentials) TLSConfig(_ context.Context, _ string, server bool) (*tls.Config, error) {
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{p.certificate}}
	if server {
		configuration.ClientAuth = tls.RequireAndVerifyClientCert
		configuration.ClientCAs = p.roots
	} else {
		configuration.RootCAs = p.roots
		configuration.ServerName = "localhost"
	}
	return configuration, nil
}

type mtlsTestAuthorizer struct {
	domain      string
	commonNames map[string]string
	credentials map[string]string
}

func (a mtlsTestAuthorizer) AuthorizeReplicationCertificate(_ context.Context, credential, node, domain string, certificate *x509.Certificate) error {
	if domain != a.domain || certificate == nil || certificate.Subject.CommonName != a.commonNames[node] || credential != a.credentials[node] {
		return errors.New("certificate identity mapping rejected")
	}
	return nil
}

func TestReplicationMTLSEndToEndAndAdministrativePeerTest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	certA, certB, roots := makeReplicationTestCertificates(t)
	address := replicationTestAddress(t)
	domain := "mtls-test"
	nodeA := "00000000-0000-4000-8000-000000000061"
	nodeB := "00000000-0000-4000-8000-000000000062"
	authorizer := mtlsTestAuthorizer{domain: domain, commonNames: map[string]string{nodeA: "node-a", nodeB: "node-b"}, credentials: map[string]string{nodeA: "a-cert", nodeB: "b-cert"}}
	open := func(name string, certificate tls.Certificate) *DB {
		db, err := OpenWithOptions(filepath.Join(t.TempDir(), name+".db"), Options{Key: "key", Replication: &ReplicationRuntimeOptions{Credentials: mtlsTestCredentials{certificate: certificate, roots: roots}, MembershipVerifier: acceptingMembershipVerifier{}, CertificateAuthorizer: authorizer}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
			t.Fatal(err)
		}
		return db
	}
	a := open("mtls-a", certA)
	b := open("mtls-b", certB)
	if err := a.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: nodeA, NodeName: "node-a", ReplicationDomain: domain, AuthMode: ReplicationAuthMTLS, CredentialName: "a-cert"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if err := b.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: nodeB, NodeName: "node-b", ReplicationDomain: domain, ListenAddress: address, AuthMode: ReplicationAuthMTLS, CredentialName: "b-cert"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	statusA, err := a.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	statusB, err := b.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: nodeB, IncarnationUUID: statusB.IncarnationUUID, NodeName: "node-b", Address: address, CredentialName: "b-cert", ListenEnabled: true, Role: ReplicationDial, AuthMode: ReplicationAuthMTLS}); err != nil {
		t.Fatal(err)
	}
	if err = b.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: nodeA, IncarnationUUID: statusA.IncarnationUUID, NodeName: "node-a", Address: "127.0.0.1:1", CredentialName: "a-cert", ListenEnabled: false, Role: ReplicationAccept, AuthMode: ReplicationAuthMTLS}); err != nil {
		t.Fatal(err)
	}
	manifest := MembershipManifest{Epoch: 2, Domain: domain, PolicyHash: "mtls-policy", Nodes: []MembershipNode{
		{NodeUUID: nodeA, IncarnationUUID: statusA.IncarnationUUID, State: "active", ListenEnabled: false, RoleByPeer: map[string]ReplicationConnectionRole{nodeB: ReplicationDial}},
		{NodeUUID: nodeB, IncarnationUUID: statusB.IncarnationUUID, State: "active", ListenEnabled: true, RoleByPeer: map[string]ReplicationConnectionRole{nodeA: ReplicationAccept}},
	}}
	if err = b.ApplyMembershipManifest(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if err = a.ApplyMembershipManifest(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	if err = a.TestReplicationPeer(ctx, nodeB); err != nil {
		t.Fatalf("administrative mTLS test: %v", err)
	}
	if _, err = a.Exec(`INSERT INTO items VALUES('one','authenticated')`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var name string
		err = b.QueryRow(`SELECT name FROM items WHERE id='one'`).Scan(&name)
		if err == nil && name == "authenticated" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mTLS replication did not converge: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func replicationTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func makeReplicationTestCertificates(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "replication-test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, commonName string) tls.Certificate {
		leafPublic, leafPrivate, issueErr := ed25519.GenerateKey(rand.Reader)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, issueErr := x509.CreateCertificate(rand.Reader, template, ca, leafPublic, private)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafPrivate}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return issue(2, "node-a"), issue(3, "node-b"), roots
}
