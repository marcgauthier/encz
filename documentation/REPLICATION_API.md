# Replication API and local verification

SQLiteSeal supports direct, masterless replication between explicitly
configured encrypted databases. Every node remains writable while disconnected;
committed row changes are captured by generated SQLite triggers and merge per
field with a persisted Hybrid Logical Clock.

Application DDL is not replicated. All nodes must create or migrate the same
schema locally, and a schema-hash mismatch prevents a session from exchanging
data.

## Runtime providers

Replication secrets are process-local. Implement
`ReplicationCredentialProvider` to return a relationship PSK and hardened
client/server `*tls.Config` values, and implement `MembershipVerifier` to
authenticate the operator-provided membership manifest. For mTLS, also provide
`ReplicationCertificateAuthorizer`; it must bind the verified leaf certificate
to the claimed credential reference, node UUID, and replication domain. SQLiteSeal stores only
credential reference names.

Pass both providers when opening the database:

```go
db, err := sqliteseal.OpenWithOptions(path, sqliteseal.Options{
    Key: masterKey,
    Replication: &sqliteseal.ReplicationRuntimeOptions{
        Credentials:        credentials,
        MembershipVerifier:    membershipVerifier,
        CertificateAuthorizer: certificateAuthorizer, // required for mTLS
    },
})
```

On a previously configured database, opening automatically validates the
external identity guard and starts eligible listener and dial workers. Missing
or invalid runtime credentials leave networking fail-closed.

## Initial configuration

Create the identical application schema on every node, then opt tables in:

```go
err := db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{
    NodeUUID:          nodeID,
    NodeName:          "site-a",
    ReplicationDomain: "production",
    ListenAddress:     "127.0.0.1:9443", // empty for a dial-only node
    AuthMode:          sqliteseal.ReplicationAuthPSK,
    CredentialName:    "site-a-site-b",
}, []sqliteseal.ReplicatedTable{{Name: "items"}})
```

Existing rows are captured as initial immutable insert events. Replicated
primary keys become immutable. Protocol v1 rejects tables without a primary
key, non-primary unique indexes, and foreign keys.

Use `UpsertReplicationPeer` to stage each peer's identity, endpoint,
complementary dial/accept role, and credential reference. Staging never enables
a peer. `ApplyMembershipManifest` authenticates a newer complete membership
epoch and activates networking. Every active node must receive the same
canonical manifest and signature.

## Operation

- `ReplicationStatus` reports identity, schema and membership guards, effective
  listener address, peer sessions, cursors, gaps, and blocked state.
- `PauseReplication` closes sessions while local writes continue to capture.
- `ResumeReplication` restores listeners and dial workers.
- `SyncReplicationPeer` wakes a configured peer immediately.
- `WaitForReplication` waits for a durable contiguous origin counter and is
  useful for bounded read-your-write behavior.
- `ReloadReplicationCredentials` closes existing sessions and forces them to
  authenticate with newly supplied operator credentials.

Frames are canonical JSON objects encoded as independent gzip members with a
four-byte big-endian compressed-length prefix. Production sessions require TLS. PSK sessions use mutual role-separated proofs over both fresh nonces, a server-issued session UUID, timestamps, membership and schema guards, and TLS exporter material. Authentication transcripts are freshness-checked and replay-cached. mTLS sessions additionally require explicit certificate-to-node authorization. Received events must come directly
from their authenticated origin. Duplicate delivery is idempotent, and
per-field winners compare HLC physical time, logical time, then origin UUID.

## Two-node verifier

`app-test-replication` creates two encrypted databases and ephemeral local test
credentials. It verifies both replication directions, offline catch-up,
independent and conflicting field updates, duplicate delivery, tombstones, and
automatic reopen recovery:

```bash
cd app-test-replication
go run .
```

The app exits non-zero on the first failure and retains encrypted database
artifacts under its ignored `runs/` directory.
