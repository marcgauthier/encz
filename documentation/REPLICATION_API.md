# Replication API and local verification

> [!WARNING]
> The Go replication API is under active development and is not ready for
> production use. This does not apply to SQLiteSeal's stable core use as an
> encrypted SQLite replacement.

SQLiteSeal supports direct, masterless replication between explicitly
configured encrypted databases. Every node remains writable while disconnected;
committed row changes are captured by generated SQLite triggers and merge per
field with a persisted Hybrid Logical Clock.

Replicated table definitions are negotiated before row exchange. Nodes advertise the
tables and columns selected by the application; missing tables and columns are
created automatically, while declared-type conflicts are resolved by the lowest
membership-authenticated node level. Schema hashes remain useful diagnostics and
event provenance, but peers do not require equal hashes.

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

Pass each node's table selection to `InitializeReplication`. A selected table may
already exist locally, or it may be absent and acquire its definition from a
connected member:

```go
err := db.InitializeReplication(ctx, sqliteseal.LocalNodeConfig{
    NodeUUID:          nodeID,
    NodeName:          "site-a",
    ReplicationDomain: "production",
    Level:             0, // lower values have schema authority
    ListenAddress:     "127.0.0.1:9443", // empty for a dial-only node
    AuthMode:          sqliteseal.ReplicationAuthPSK,
    CredentialName:    "site-a-site-b",
}, []sqliteseal.ReplicatedTable{{Name: "items"}})
```

Existing rows are captured as initial immutable insert events and replicated
primary keys become immutable. Tables without a primary key remain unsupported.
Foreign keys and ordinary, compound, collation-aware, or partial unique indexes
are opt-in:

```go
sqliteseal.ReplicatedTable{
    Name:             "users",
    ConstraintPolicy: sqliteseal.ReplicationConstraintsManaged,
}
```

Managed unique claims use deterministic LWW by HLC physical time, HLC logical
time, and origin UUID. The winning row is retained and losing logical rows are
deleted with durable `unique_deleted` versions. This is independent of network
arrival order. Expression-based unique indexes remain unsupported.

Use `UpsertReplicationPeer` to stage each peer's identity, endpoint,
complementary dial/accept role, and credential reference. Staging never enables
a peer. `ApplyMembershipManifest` authenticates a newer complete membership
epoch and activates networking. Every active node must receive the same canonical manifest and signature. Each
`MembershipNode.Level` must match the immutable local level configured at
initialization; duplicate levels are allowed.

`PeerConfig.HeartbeatInterval` is the maximum idle interval between complete
synchronization rounds and defaults to 15 seconds. `HeartbeatTimeout` defaults
to three times that interval (45 seconds with the default interval) and must be
greater than the interval. After authentication, all schema, synchronization,
acknowledgement, and snapshot traffic refreshes sliding socket read and write
deadlines. A stalled or half-open session is closed when the timeout expires;
the dial side then reconnects normally. Operating-system TCP keepalive is also
enabled on a best-effort basis. Updating connection or heartbeat settings with
`UpsertReplicationPeer` closes the current session so the new settings take
effect immediately. Use `SyncReplicationPeer` when an application needs to
wake a peer before its next heartbeat interval.

Outbound reconnects use `PeerConfig.ReconnectInitial` (default one second) and
`ReconnectMaximum` (default one minute). The unjittered delay doubles after
each consecutive failure and is capped at the maximum. A nil
`ReconnectJitterPercent` selects the 20 percent default; a pointer to zero
disables jitter, and other values must be from 0 through 100. Jitter is sampled
symmetrically around the unjittered delay, with the upper bound capped by
`ReconnectMaximum`.

The selected retry time and consecutive failure count are persisted. Reopening
the database honors a pending retry instead of creating a reconnect storm; an
overdue retry runs immediately, and an implausibly distant stored retry is
clamped to the configured maximum. `UpsertReplicationPeer`,
`ReloadReplicationCredentials`, `ResumeReplication`, membership activation,
and `SyncReplicationPeer` clear a pending delay and wake the affected dialer.
`ReplicationPeerStatus` exposes `NextRetryAt`, `ConsecutiveFailures`, and the
most recent `ConnectedAt` time for operational monitoring.

`PeerConfig.MaxSnapshotBytes` bounds each snapshot accepted from or generated
for that peer. Zero selects the 256 MiB default; negative values are invalid,
and operators must explicitly configure a larger value on both peers for
larger snapshots. The limit is independent of the per-frame limits because a
snapshot is transferred as many bounded frames.

### Schema reconciliation

Before exchanging row events, peers exchange the structured schema declarations
known to them. Declarations include each origin node's selected tables, selected
columns, primary key, constraint policy, declared SQLite column types, schema
revision, and authenticated node level.

The effective schema is deterministic:

- The table and column set is the additive union of all non-retired declarations.
- A missing selected table is created from an available declaration.
- A missing selected column is added with `ALTER TABLE`.
- If one column has different declared types, declarations at the numerically
  lowest level have authority; declarations at higher levels do not outvote
  them.
- If two or more nodes at that lowest level declare different types, there is
  no winner. The conflict is stored in `replication_schema_conflicts`, exposed
  by `ReplicationStatus.SchemaConflicts`, and the peer session remains
  `schema_pending`. The nodes retry after learning a declaration from a lower
  level.
- Primary-key, constraint-policy, and explicit-recreation-policy disagreements
  are not resolved automatically.

Schema reconciliation is additive: it creates tables and columns and can rebuild
a supported table to apply an authoritative declared type. It does not interpret
absence as a request to drop a table or column. Type conversion uses SQLite's
normal conversion behavior and fails closed when the existing table has
constraints that cannot be rebuilt safely.

## Operation

- `ReplicationConflicts` reports durable FK dependencies that still await
  related rows.
- `RetryReplicationDeferred` retries those dependencies immediately.
- `ApplyReplicationMigration` coordinates local DDL, capture-trigger rebuilding,
  and schema fencing; replication remains paused until `ResumeReplication`.
- `ReplicationStatus` reports node levels, effective schema, structured schema conflicts, membership guards, peer sessions, cursors, gaps, and blocked state. Equal-level type conflicts put only that peer session in `schema_pending`.
- `ReplicationSyncStats` reports local generation counter and per-origin tracking cursors across all tracked peer origin nodes.
- `PauseReplication` closes sessions while local writes continue to capture.
- `ResumeReplication` restores listeners and dial workers.
- `SyncReplicationPeer` wakes a configured peer immediately.
- `WaitForReplication` waits for a durable contiguous origin counter and is
  useful for bounded read-your-write behavior.
- `ReloadReplicationCredentials` closes existing sessions, rebuilds listeners, clears replay state, and forces re-authentication with newly supplied operator credentials.
- `TestReplicationPeer` performs a TLS-bound administrative authentication, identity and membership check without registering a data session or exchanging events.

Frames are canonical JSON objects encoded as independent gzip members with a
four-byte big-endian compressed-length prefix. Production sessions require TLS. PSK sessions use mutual role-separated proofs over both fresh nonces, a server-issued session UUID, timestamps, membership policy, node levels, and schema declarations, and TLS exporter material. Authentication transcripts are freshness-checked and replay-cached. mTLS sessions additionally require explicit certificate-to-node authorization. Received events must come directly
from their authenticated origin. Duplicate delivery is idempotent, and
per-field winners compare HLC physical time, logical time, then origin UUID.

Each authenticated synchronization round exchanges the complete per-origin cursor vector and bounded durable gap requests. Above-gap events remain durable in `pending` state and are materialized only after the missing prefix commits. Responses are batch-bounded and advertise continuation with `more`. When retained history cannot fill a requested range, the peers create and transfer a fresh consistent logical snapshot in bounded, individually hashed chunks. The receiver verifies the canonical content hash, session-authenticated creator, membership guards and the schema negotiated before transfer before atomically installing application rows, field versions, tombstones, and baseline cursors. A snapshot cannot be created while local gaps remain and cannot overwrite a node that has produced local-origin history.

## Snapshots

`CreateReplicationSnapshot` creates a ready session-authenticated logical
snapshot and returns its identity, schema hash, content hash, creation time, and
uncompressed size. Creation writes canonical format-version-1 JSON directly to
a restricted temporary file while reading one consistent SQLite transaction;
it hashes and size-checks the stream before atomically publishing the file.
Snapshot files are stored beside the database under the
`.replication-snapshots` directory and referenced from
`replication_snapshots.storage_uri`.

Normal peer synchronization transfers the file in 64 KiB individually hashed
chunks without reading the full snapshot into memory. The receiver writes and
hashes a temporary file, validates canonical JSON and all snapshot records in a
streaming pass, then streams them again into one atomic SQLite transaction.
Memory is bounded by a chunk, one logical row, and small schema/cursor metadata.
Interrupted or rejected transfers remove their temporary files; reconnection
starts that snapshot transfer again at offset zero. Automatic synchronization
creates a fresh snapshot when retained events cannot repair a cursor.
Manual/offline export and `external_signature` import remain a separate phase.

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
