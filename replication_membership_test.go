package sqliteseal

import (
	"context"
	"path/filepath"
	"testing"
)

type acceptingMembershipVerifier struct{}

func (acceptingMembershipVerifier) VerifyMembership(context.Context, []byte, []byte) error {
	return nil
}

func TestReplicationRejectsIncompleteMembershipManifest(t *testing.T) {
	ctx := context.Background()
	db, err := OpenWithOptions(filepath.Join(t.TempDir(), "membership.db"), Options{Key: "key", Replication: &ReplicationRuntimeOptions{MembershipVerifier: acceptingMembershipVerifier{}}})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE items(id TEXT PRIMARY KEY,name TEXT)`); err != nil {
		t.Fatal(err)
	}
	localID := "00000000-0000-4000-8000-000000000031"
	if err = db.InitializeReplication(ctx, LocalNodeConfig{NodeUUID: localID, NodeName: "local", ReplicationDomain: "test"}, []ReplicatedTable{{Name: "items"}}); err != nil {
		t.Fatal(err)
	}
	if err = db.UpsertReplicationPeer(ctx, PeerConfig{NodeUUID: "00000000-0000-4000-8000-000000000032", IncarnationUUID: "00000000-0000-4000-8000-000000000033", NodeName: "peer", Address: "127.0.0.1:1", Role: ReplicationDial, AuthMode: ReplicationAuthPSK, ListenEnabled: true}); err != nil {
		t.Fatal(err)
	}
	status, err := db.ReplicationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest := MembershipManifest{Epoch: 2, Domain: "test", PolicyHash: "policy", Nodes: []MembershipNode{{NodeUUID: localID, IncarnationUUID: status.IncarnationUUID, State: "active"}}}
	if err = db.ApplyMembershipManifest(ctx, manifest); err == nil {
		t.Fatal("incomplete membership manifest accepted")
	}
}
