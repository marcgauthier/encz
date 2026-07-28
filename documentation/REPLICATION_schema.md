# Masterless Replication Schema

## 1. Purpose and scope

This document defines the durable metadata needed to replicate application
data between independently writable nodes. Every node uses the same
application schema; this design validates schema compatibility during
connection setup but does not replicate DDL or schema changes.

The fixed tables are:

1. `replication_changes` — immutable common event headers.
2. `replication_change_acks` — durable acknowledgements received from remote
   nodes.
3. `replication_nodes` — node identity, connection, and authentication
   details.
4. `replication_local_state` — the local node's counter, HLC, incarnation, and
   restore safety state.
5. `replication_field_versions` — the winning version of every replicated
   field.
6. `replication_row_versions` — the deterministic live/deleted state of every
   replicated row.
7. `replication_origin_cursors` — contiguous synchronization progress for
   every node and event origin.
8. `replication_origin_gaps` — missing counter ranges detected in an origin's
   event stream.
9. `replication_snapshots` — bootstrap and compaction baselines.
10. `replication_peer_connections` — directional persistent-TCP connection
    configuration and reconnect state for each remote node.
11. `replication_rejected_events` — bounded forensic evidence for malformed or
    duplicate-identity events that cannot be inserted into the change log.

In addition, every replicated application table has one required generated
typed `<application_table>__replication_changes` table. SQLiteSeal also
generates `AFTER INSERT`, `AFTER UPDATE`, and `AFTER DELETE` triggers on that
application table. These table-specific payload tables and triggers are part of
the required replication schema, not optional caches.

All replication-owned tables, including generated per-table payload tables,
must be excluded from change-capture triggers. Writes to them are restricted to
the generated triggers and replication service.

## 2. Common conventions

- Node and event identities are UUIDs stored as canonical lower-case text.
- All time values are UTC ISO 8601 strings, for example
  `2026-07-25T14:03:27.123456Z`.
- Application table names are stored in `table_name`; `table` is avoided
  because it is an SQL keyword.
- Row identities are stored as canonical JSON in `row_key_json`. This supports
  UUID, text, integer, and composite primary keys without relying on SQLite's
  local `rowid`.
- Row values are stored with SQLite types in the generated per-table payload
  table and encoded as typed canonical JSON only for hashing and transport.
  The payload hash is calculated from uncompressed RFC 8785 canonical JSON
  after NFC normalization, so gzip implementation details do not affect event
  identity.
- JSON must preserve value types and must distinguish an omitted field from an
  explicit SQL `NULL`.
- Every changed field uses an explicit typed-value envelope in canonical JSON.
  The envelope includes a presence marker, a type tag, and a value. For
  example, `{"present":true,"type":"null","value":null}` means set the
  column to SQL `NULL`; absence from `changed_fields_json` means no change.
  Binary values use canonical unpadded Base64url and integers outside the
  interoperable JSON integer range use a canonical decimal string with an
  explicit integer type tag.
- The application schema itself is not replicated. `schema_version` and
  `schema_hash` values are compatibility guards; peers with different values
  must stop data exchange until administrators install the same schema.
- Replication messages are canonical JSON, compressed as one independent gzip
  member per message, and carried in length-prefixed frames over a persistent
  bidirectional TCP connection. gRPC and Protocol Buffers are not used.
- Foreign-key enforcement must be enabled on every SQLite connection with
  `PRAGMA foreign_keys = ON`.
- Protocol version 1 creates one row-sized event per trigger firing. An optional
  `transaction_uuid` correlates events from one local transaction but does not
  provide atomic multi-row application on receivers.

## 3. Table 1: `replication_changes`

`replication_changes` is an append-only common-header log. Every trigger-captured
row change inserts one header here and one typed payload in that application
table's generated replication table, in the same transaction as the
application row change. A received remote event inserts both records before,
or atomically with, applying its winning values.

### Columns

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `change_seq` | INTEGER | Yes | Local auto-incrementing storage sequence. It is useful for scans but is not globally unique and must not be used for conflict resolution. |
| `change_uuid` | TEXT | Yes | Globally unique UUID for this immutable change event. |
| `origin_node_uuid` | TEXT | Yes | Permanent UUID of the node that created the event. For a remote event it must match the authenticated peer. |
| `origin_counter` | INTEGER | Yes | Strictly increasing counter allocated by the origin node. The pair `(origin_node_uuid, origin_counter)` is unique. |
| `transaction_uuid` | TEXT | No | Correlates row events committed by one local application transaction; it does not imply atomic remote application. |
| `operation` | TEXT | Yes | One of `insert`, `update`, or `delete`. |
| `table_name` | TEXT | Yes | Name of the replicated application table or entity. |
| `row_key_json` | TEXT | Yes | Canonical JSON representation of the row's primary key. |
| `changed_fields_json` | TEXT | Until compacted | Canonical JSON array of field names changed by the event. Insert normally lists all fields; delete may use an empty array because the operation applies to the row. |
| `is_explicit_recreation` | INTEGER | Yes | `1` only for an explicitly authorized insert of a tombstoned identity; normal trigger-captured updates always use `0`. |
| `hlc_physical_utc_us` | INTEGER | Yes | Physical component of the event's Hybrid Logical Clock, as Unix microseconds in UTC. |
| `hlc_logical` | INTEGER | Yes | Logical component of the event's Hybrid Logical Clock. |
| `schema_version` | INTEGER | Yes | Replicated application schema version used to encode the event. |
| `schema_hash` | TEXT | Yes | SHA-256 of the exact replicated schema descriptor used to encode the event. |
| `canonicalization_version` | INTEGER | Yes | Canonical envelope and typed-value encoding version. |
| `merge_policy_version` | INTEGER | Yes | Version of the row-state and field comparison rules. |
| `replication_domain` | TEXT | Yes | Domain/environment identifier that prevents accidental exchange between unrelated databases. |
| `created_at_utc` | TEXT | Yes | UTC time at which the origin committed the change. |
| `stored_at_utc` | TEXT | Yes | UTC time at which this node durably stored the event. |
| `source_node_uuid` | TEXT | No | Immediate peer from which this node received the event. It is `NULL` for a locally originated event. |
| `payload_hash` | TEXT | Yes | Lower-case SHA-256 hex digest of the canonical, uncompressed immutable event payload. |
| `payload_uncompressed_bytes` | INTEGER | Yes | Exact expanded canonical payload size; it is checked against the configured per-event limit before allocation or decoding. |
| `origin_signature` | BLOB | No | Optional signature made by the origin over the immutable event envelope when signed-at-rest event verification is enabled. |
| `apply_state` | TEXT | Yes | Local processing state: `pending`, `applied`, `ignored`, or `quarantined`. This is local metadata and is not part of the signed event payload. |
| `quarantine_reason` | TEXT | No | Diagnostic reason when `apply_state` is `quarantined`. |
| `payload_state` | TEXT | Yes | `retained` while row payloads are present or `compacted` after an accepted snapshot makes them unnecessary. |
| `compacted_by_snapshot_uuid` | TEXT | No | Snapshot whose baseline and state justify removing the large payload fields. |
| `compacted_at_utc` | TEXT | No | Local time at which payload compaction occurred. |

### Important rules

- `change_seq` is the requested auto-increment counter, but it is local to the
  database. Masterless replication also needs `origin_counter`, because two
  offline nodes can allocate the same local integer.
- A duplicate `change_uuid`, or duplicate `(origin_node_uuid,
  origin_counter)`, is accepted only when its `payload_hash` matches the
  stored event. A different hash is an integrity failure.
- The generated typed payload row contains the full row image and a canonical
  field-version provenance map. This allows an accepted explicit recreation or
  missing-row repair without assigning the current event's version to
  unchanged fields. When a row already exists, only presence-marked fields
  participate in the merge; the full image never overwrites unrelated winners.
- `changed_fields_json` is also the authoritative presence bitmap. A listed
  field whose typed value is `null` clears the application column. A field not
  listed is omitted and must retain its current value. SQL `NULL` must never be
  overloaded to mean "field absent" in a merge query or aggregate.
- The event envelope is immutable. Only local processing and compaction
  metadata may change after insertion. Safe compaction deletes the associated
  generated typed payload row and may clear `changed_fields_json`; it preserves
  event identity, schema guard, origin counter, HLC, expanded size, and hash.
- `source_node_uuid` identifies the immediate sender and must equal
  `origin_node_uuid` for every remote event. It is `NULL` for a locally
  originated event. This full-mesh design does not forward events.
- An event is eligible for acknowledgement only after it has been validated,
  durably stored, applied or deterministically ignored, and committed.

## 4. Table 2: `replication_change_acks`

This table records acknowledgements received from remote nodes. Its rows are
written on the sending node after a remote node reports that a change was
durably processed.

### Columns

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `ack_seq` | INTEGER | Yes | Local auto-incrementing acknowledgement sequence. |
| `change_uuid` | TEXT | Yes | UUID of the acknowledged event. |
| `acknowledging_node_uuid` | TEXT | Yes | UUID of the remote node that acknowledged the event. |
| `ack_state` | TEXT | Yes | Durable remote result: `applied` or `ignored`. Quarantined or merely received events are not acknowledged. |
| `acknowledged_at_utc` | TEXT | No | UTC time reported by the remote node, if supplied. |
| `recorded_at_utc` | TEXT | Yes | Local UTC time at which this node committed the acknowledgement. |

### Important rules

- `(change_uuid, acknowledging_node_uuid)` is unique. Repeated
  acknowledgements update the existing row or are ignored; they never create
  duplicate logical acknowledgements.
- An acknowledgement means durable processing, not merely network receipt.
- Acknowledgements must be committed before the sender treats an event as
  delivered.
- A direct peer acknowledgement proves only that the named peer processed the
  event. It does not prove that every node downstream of that peer processed
  it.
- Event-log compaction must consider all active domain members and snapshot
  baselines. One acknowledgement row alone is not sufficient proof that an
  event can be deleted.

## 5. Table 3: `replication_nodes`

This table is the durable node registry. It stores both the local node and all
approved remote nodes. Historical node rows should be disabled or retired,
not deleted, because change and acknowledgement history refers to them.

### Columns

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `node_uuid` | TEXT | Yes | Permanent UUID of the node. |
| `incarnation_uuid` | TEXT | Yes | UUID for the currently enrolled installation of the node. It detects cloned or restored installations unexpectedly using the same node identity. |
| `node_name` | TEXT | Yes | Unique human-readable name, such as `SITE-TORONTO-01`. |
| `replication_domain` | TEXT | Yes | Domain/environment to which the node belongs. |
| `is_local` | INTEGER | Yes | `1` for this database's node and `0` for a remote node. Exactly one active row should be local. |
| `membership_state` | TEXT | Yes | One of `joining`, `active`, or `retired`. Retired records remain for historical verification. |
| `membership_epoch` | INTEGER | Yes | Monotonic administrative membership generation in which this node's current state was established. |
| `listen_enabled` | INTEGER | Yes | Whether this node accepts inbound replication TCP connections. A node behind a firewall may set this to `0` and operate as an outbound-only dialer. |
| `hostname` | TEXT | No | Advertised DNS host name for inbound connections. Required with an address or IP when `listen_enabled = 1`. |
| `ip_address` | TEXT | No | Advertised IPv4 or IPv6 address when a fixed address is used. |
| `port` | INTEGER | No | Advertised TCP listener port. Required when `listen_enabled = 1`. |
| `protocol` | TEXT | Yes | `tls_tcp` for TLS-protected TCP or `tcp` for isolated development use. |
| `wire_encoding` | TEXT | Yes | Must be `json`. It is explicit so a connection can reject an incompatible peer. |
| `wire_compression` | TEXT | Yes | Must be `gzip`. Each framed message is compressed independently. |
| `auth_mode` | TEXT | Yes | Authentication method: `psk` or `mtls`. |
| `credential_name` | TEXT | No | Non-secret external reference used to request the user-provided PSK or certificate configuration. |
| `next_credential_name` | TEXT | No | Optional second user-provided reference during an operator-controlled replacement overlap. |
| `tls_server_name` | TEXT | No | Expected TLS server name. |
| `tls_cert_fingerprint` | TEXT | No | Pinned certificate fingerprint when certificate pinning is used. |
| `origin_verify_key_name` | TEXT | No | Non-secret external reference for a user-provided public snapshot/event verification key. |
| `enabled` | INTEGER | Yes | Whether synchronization with the node is currently allowed. Only active nodes should be enabled. |
| `rebootstrap_required` | INTEGER | Yes | When `1`, the node cannot resume incremental synchronization until it installs an approved snapshot or complete replay. |
| `joined_at_utc` | TEXT | No | Time at which the node became an active domain member. |
| `retired_at_utc` | TEXT | No | Retirement time. A retired node must re-enrol with a new identity and re-bootstrap before returning. |
| `created_at_utc` | TEXT | Yes | Node registration time. |
| `updated_at_utc` | TEXT | Yes | Last configuration update time. |
| `last_seen_at_utc` | TEXT | No | Last successful authenticated contact time. Diagnostic only. |

### Credential handling

The replication database stores only non-secret credential references and
optional public fingerprints. The user or operator supplies PSKs, certificate
chains, private keys, trusted roots, trust/revocation policy, and signing keys
through configuration or an external provider. SQLiteSeal loads, validates,
and uses supplied material; it never creates, issues, distributes, rotates,
renews, or revokes it. A replacement becomes active only after an explicit
configuration reload or restart.

No PSK, password, private key, or reusable proof is stored in these tables.
Database encryption at rest remains required for application and operational
metadata, but it is not a credential-management mechanism.

### Dynamic membership rules

Adding or removing a node is a replication-domain administration operation,
not an application-schema change. Protocol version 1 uses an authenticated
membership manifest supplied and distributed by the operator. SQLiteSeal
validates its signature or configured authentication, monotonic epoch, domain,
and complete member set; it does not create or distribute the manifest.

A node is added in `joining` state, receives a snapshot or complete event-log
replay, catches up its origin cursors, and only then becomes `active`. A node is
removed by changing it to `retired`, disabling it, and setting
`rebootstrap_required`. Historical node rows must not be deleted. A retired
installation that returns must use a new node UUID and bootstrap again.

`membership_epoch` makes membership decisions orderable and prevents a stale
configuration from silently reactivating an old member. Every node also stores
and negotiates the manifest hash. Compaction and retirement are disabled until
all active nodes advertise the same epoch and hash. A conflicting manifest
fails closed and requires operator correction; SQLiteSeal does not implement a
membership consensus service.

Membership configuration must also create one
`replication_peer_connections` row on every existing node for the new peer and
one row on the new node for every existing peer. The connection roles must form
a reachable pair: exactly one side normally dials and the other accepts.

## 6. Table 4: `replication_local_state`

This single-row table stores state that belongs to this database installation.
It cannot safely be inferred from the event log after events are compacted,
and it must be updated in the same transaction as every local change.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `state_id` | INTEGER | Yes | Fixed primary key with value `1`, enforcing one local-state row. |
| `local_node_uuid` | TEXT | Yes | Node identity used to originate local events. |
| `local_incarnation_uuid` | TEXT | Yes | Installation incarnation expected to match the local node registry entry. |
| `replication_domain` | TEXT | Yes | Domain in which local events may be exchanged. |
| `last_origin_counter` | INTEGER | Yes | Last counter committed by this origin. The next local event receives this value plus one. |
| `last_hlc_physical_utc_us` | INTEGER | Yes | Last committed HLC physical component. |
| `last_hlc_logical` | INTEGER | Yes | Last committed HLC logical component. |
| `membership_epoch` | INTEGER | Yes | Highest membership generation accepted by this node. |
| `membership_manifest_hash` | TEXT | Yes | SHA-256 of the operator-provided authenticated membership manifest accepted at that epoch. |
| `database_generation` | INTEGER | Yes | Monotonic generation changed by controlled database replacement. |
| `restore_epoch` | INTEGER | Yes | Incremented or reconciled after restore before networking is enabled. |
| `network_enabled` | INTEGER | Yes | Safety fence. It must be `0` after an uncertain restore, clone, or identity mismatch. |
| `schema_version` | INTEGER | Yes | Local application schema compatibility version; it is compared, not replicated. |
| `schema_hash` | TEXT | Yes | SHA-256 hash of the canonical replicated-table descriptor. |
| `created_at_utc` | TEXT | Yes | Time at which local replication state was initialized. |
| `updated_at_utc` | TEXT | Yes | Last state update time. |

The local counter and HLC are allocated transactionally from this row. The
`AUTOINCREMENT` value in `replication_changes` cannot replace them because
received remote events also consume local storage sequence numbers. Restore
and incarnation fields prevent a rolled-back database from reusing an existing
`(origin_node_uuid, origin_counter)` for different content.

Because an old database backup rolls these fields back together, startup also
compares them with an authenticated external identity guard excluded from
database backups. If its generation or counter high-water mark is ahead of the
database, networking stays disabled until operator reconciliation or a new
identity and snapshot bootstrap.

The guard is advanced atomically only after a successful local database
commit. A database counter ahead of the guard after a crash advances the guard
during recovery. A guard ahead of the database is a rollback fence. The guard
contains no PSK, certificate private key, or application row data.

## 7. Table 5: `replication_field_versions`

This table materializes the winning version for each field of each replicated
row. It makes per-field merge decisions independent of event arrival order and
avoids replaying the complete changelog for every update.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `table_name` | TEXT | Yes | Replicated application table or entity. |
| `row_key_json` | TEXT | Yes | Canonical row primary key. |
| `field_name` | TEXT | Yes | Application field whose winner is recorded. |
| `winner_hlc_physical_utc_us` | INTEGER | Yes | Winning event's HLC physical component. |
| `winner_hlc_logical` | INTEGER | Yes | Winning event's HLC logical component. |
| `winner_origin_node_uuid` | TEXT | Yes | Origin UUID used as the deterministic final tie-breaker. |
| `winner_change_uuid` | TEXT | Yes | Event that supplied the winning value. |
| `winner_changed_at_utc` | TEXT | Yes | Auditable origin change time. |
| `value_hash` | TEXT | No | Optional hash of the current canonical field value for validation and repair. |
| `updated_at_utc` | TEXT | Yes | Time this materialized winner was stored locally. |

The primary key is `(table_name, row_key_json, field_name)`. Incoming fields
are compared by the total order `(HLC physical, HLC logical, origin node UUID)`.
Only a strictly greater version replaces the current winner. Equal versions
with different event content are integrity failures.

## 8. Table 6: `replication_row_versions`

Field versions do not decide whether a row exists. This table is a row-level
Last-Write-Wins register that gives insert/update versus delete a deterministic
answer and retains deletion tombstones.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `table_name` | TEXT | Yes | Replicated application table or entity. |
| `row_key_json` | TEXT | Yes | Canonical row primary key. |
| `row_state` | TEXT | Yes | Winning existence state: `live` or `deleted`. |
| `winner_hlc_physical_utc_us` | INTEGER | Yes | Winning row-state HLC physical component. |
| `winner_hlc_logical` | INTEGER | Yes | Winning row-state HLC logical component. |
| `winner_origin_node_uuid` | TEXT | Yes | Winning row-state origin and deterministic tie-breaker. |
| `winner_change_uuid` | TEXT | Yes | Event that established the row state. |
| `winner_changed_at_utc` | TEXT | Yes | Auditable origin time of the winning row-state event. |
| `prunable_after_snapshot_uuid` | TEXT | No | Snapshot that includes this state and may participate in proving a tombstone safe to prune. |
| `updated_at_utc` | TEXT | Yes | Time this materialized state was stored locally. |

An insert or update is a `live` candidate only when no tombstone exists. A
delete is a `deleted` candidate. Once a tombstone wins, an ordinary update can
never change row state, even if its HLC is greater. Recreation requires a
strictly newer event with `is_explicit_recreation = 1`, emitted only by an
authorized insert/recreation path. If that event wins, the full row and its
per-field versions in the generated typed payload table reconstruct the row.

A deleted row remains represented here even after its application row is
removed. Its tombstone cannot be pruned until the domain-wide cursor and
snapshot rules prove that no supported member can later introduce an older
operation.

## 9. Table 7: `replication_origin_cursors`

Every node needs a cursor vector, not one global cursor. Counters from different
origins are unrelated. This table stores the highest contiguous durable counter
known for each `(tracking node, origin node)` pair.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `tracking_node_uuid` | TEXT | Yes | Node whose durable knowledge is described. The local node records itself and authenticated cursor advertisements from peers. |
| `origin_node_uuid` | TEXT | Yes | Origin whose counter sequence is being tracked. |
| `contiguous_counter` | INTEGER | Yes | Highest counter for which every event from `1` through this value is durably represented. |
| `highest_seen_counter` | INTEGER | Yes | Highest counter observed, even when lower gaps remain. |
| `baseline_snapshot_uuid` | TEXT | No | Installed snapshot that represents counters at or below its baseline. |
| `requires_snapshot` | INTEGER | Yes | Indicates that retained events cannot fill the node's gap and a snapshot is required. |
| `updated_at_utc` | TEXT | Yes | Last durable cursor update time. |

When `tracking_node_uuid` is the local node, the row describes locally received
history. When it is a peer, the row records that peer's last authenticated
cursor advertisement. A cursor advances only across an uninterrupted sequence;
it never jumps over a missing or quarantined event. Per-event acknowledgement
rows may be compacted after equivalent contiguous cursor progress is durable.

## 10. Table 8: `replication_origin_gaps`

This table records missing ranges above a contiguous cursor. Gaps could be
calculated by scanning the event log, but durable ranges make restart-safe
repair efficient for large histories.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `tracking_node_uuid` | TEXT | Yes | Node whose missing range is being tracked, normally the local node. |
| `origin_node_uuid` | TEXT | Yes | Origin with missing counters. |
| `gap_start_counter` | INTEGER | Yes | First missing origin counter, inclusive. |
| `gap_end_counter` | INTEGER | Yes | Last missing origin counter, inclusive. |
| `detected_at_utc` | TEXT | Yes | Time the gap was first detected. |
| `last_requested_at_utc` | TEXT | No | Last repair request time. |
| `request_count` | INTEGER | Yes | Number of repair requests made for the range. |

Overlapping or adjacent gaps should be merged. A gap is shortened or removed
as missing events arrive. If no active node retains the range, the corresponding
cursor is marked `requires_snapshot`.

## 11. Table 9: `replication_snapshots`

A snapshot lets a new or long-offline node bootstrap without retaining and
replaying the event log forever. Snapshot creation must use one consistent read
transaction.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `snapshot_uuid` | TEXT | Yes | Globally unique snapshot identity. |
| `created_by_node_uuid` | TEXT | Yes | Node that created and authenticated the snapshot. |
| `replication_domain` | TEXT | Yes | Domain to which the snapshot belongs. |
| `membership_epoch` | INTEGER | Yes | Membership generation represented by the snapshot. |
| `membership_manifest_hash` | TEXT | Yes | Hash of the exact operator-provided membership manifest represented by the snapshot. |
| `schema_version` | INTEGER | Yes | Application schema compatibility version. |
| `schema_hash` | TEXT | Yes | Canonical replicated-schema hash. |
| `baseline_cursors_gzip` | BLOB | Yes | Gzip-compressed canonical JSON cursor vector from the same consistent read view as the snapshot. |
| `baseline_cursors_uncompressed_bytes` | INTEGER | Yes | Exact expanded baseline-cursor size, validated before decompression and bounded by policy. |
| `content_hash` | TEXT | Yes | SHA-256 hash of the complete canonical logical snapshot. |
| `snapshot_auth_mode` | TEXT | Yes | `session` for transfer over the authenticated live peer session, or `external_signature` for manual/offline portability. |
| `creator_signing_key_id` | TEXT | No | User-provided external signing-key reference; required only for `external_signature`. |
| `creator_signature` | BLOB | No | Signature or MAC over the immutable snapshot manifest and content hash; required only for `external_signature`. |
| `content_size_bytes` | INTEGER | Yes | Uncompressed logical snapshot size for validation and limits. |
| `storage_uri` | TEXT | No | Optional local or remote location of the snapshot payload. |
| `snapshot_state` | TEXT | Yes | One of `creating`, `ready`, `installed`, `superseded`, or `invalid`. |
| `installed_by_node_uuid` | TEXT | No | Local node that installed this snapshot, when applicable. |
| `created_at_utc` | TEXT | Yes | Snapshot creation time. |
| `verified_at_utc` | TEXT | No | Time at which signature, hashes, schema, and baseline were verified. |
| `installed_at_utc` | TEXT | No | Time at which snapshot activation completed. |

The logical snapshot contains application rows, `replication_field_versions`,
`replication_row_versions`, and its cursor vector. It does not copy the source
node's local identity, credentials, origin counter, HLC state, or encryption
keys. After installation, the destination requests only events above the
baseline cursors.

A snapshot transferred on a live connection is authenticated by that
user-provided TLS/PSK or mTLS session and needs no additional signing key. A
snapshot exported for manual or offline import must use `external_signature`
with a verification credential supplied by the user. SQLiteSeal neither
creates nor manages that credential.

## 12. Table 10: `replication_peer_connections`

Connection direction is local and pair-specific, so it does not belong solely
in the global node record. This table contains one row for every active remote
node, interpreted from the point of view of the local node.

| Column | Type | Required | Description |
| --- | --- | --- | --- |
| `peer_node_uuid` | TEXT | Yes | Remote node for this persistent connection. It is the primary key. |
| `connection_role` | TEXT | Yes | `dial` means this local node initiates and reconnects; `accept` means it only accepts this peer's inbound connection. |
| `enabled` | INTEGER | Yes | Whether the connection is currently permitted. Joining or retired peers use `0`. |
| `reconnect_enabled` | INTEGER | Yes | Must be `1` for `dial` and `0` for `accept`. |
| `connect_timeout_ms` | INTEGER | Yes | Timeout for an outbound TCP and authentication attempt. |
| `heartbeat_interval_ms` | INTEGER | Yes | Idle interval before sending an application heartbeat. |
| `heartbeat_timeout_ms` | INTEGER | Yes | Maximum interval without valid traffic before declaring the session broken. |
| `tcp_keepalive_seconds` | INTEGER | Yes | Operating-system TCP keepalive interval. Application heartbeats remain required. |
| `reconnect_initial_ms` | INTEGER | Yes | Initial retry delay after a failed or broken outbound connection. |
| `reconnect_max_ms` | INTEGER | Yes | Maximum exponential-backoff delay. |
| `reconnect_jitter_percent` | INTEGER | Yes | Random jitter applied to retries to prevent every node reconnecting simultaneously. |
| `max_compressed_frame_bytes` | INTEGER | Yes | Maximum accepted compressed frame length. |
| `max_uncompressed_message_bytes` | INTEGER | Yes | Maximum JSON size after gzip decompression, protecting against compression bombs. |
| `max_events_per_batch` | INTEGER | Yes | Maximum event count in one event-batch message or one merge batch. |
| `max_batch_uncompressed_bytes` | INTEGER | Yes | Maximum total uncompressed canonical event bytes accepted in one batch. |
| `max_inflight_events` | INTEGER | Yes | Maximum sent but not durably acknowledged events on this session. |
| `max_inflight_bytes` | INTEGER | Yes | Maximum sent but not durably acknowledged uncompressed bytes on this session. |
| `max_gap_ranges_per_request` | INTEGER | Yes | Maximum missing ranges in one gap-repair request. |
| `max_events_per_gap_response` | INTEGER | Yes | Maximum events returned for one repair response before continuation is required. |
| `session_state` | TEXT | Yes | Current local state: `disconnected`, `connecting`, `connected`, or `disabled`. |
| `last_session_uuid` | TEXT | No | Most recent authenticated TCP session identifier. |
| `last_session_direction` | TEXT | No | `outbound` or `inbound`, for diagnostics. |
| `connected_at_utc` | TEXT | No | Start time of the current or most recent session. |
| `disconnected_at_utc` | TEXT | No | Time the most recent session ended. |
| `next_retry_at_utc` | TEXT | No | Scheduled outbound retry. It remains `NULL` for an `accept` row. |
| `consecutive_failures` | INTEGER | Yes | Failed attempts since the last successful authenticated session. |
| `last_error` | TEXT | No | Sanitized diagnostic error; it must not contain credentials or message data. |
| `updated_at_utc` | TEXT | Yes | Last configuration or runtime-state update. |

### Persistent connection behavior

Every pair of active nodes must have one authenticated, bidirectional TCP
connection. Either endpoint may send changes, acknowledgements, cursor vectors,
gap requests, snapshots, or heartbeats regardless of which endpoint opened the
socket.

Connection roles are interpreted as follows:

- `dial`: this node opens the connection. If it fails or later breaks, this node
  retries indefinitely using exponential backoff capped by
  `reconnect_max_ms`, with jitter. A successful authenticated session resets
  `consecutive_failures`.
- `accept`: this node never attempts an outbound connection to that peer. If
  the session breaks, it keeps its listener available and waits for the peer to
  come back online and connect again.
- If the peer's `replication_nodes.listen_enabled` is `0`, the local role must
  be `accept`; attempting to dial that peer is a configuration error.
- A local node that has `listen_enabled = 0` must be `dial` toward every peer,
  and each target peer must advertise a listener. Two non-listening nodes
  cannot form a direct connection and therefore cannot satisfy full-mesh
  replication without a relay, which is outside this schema.
- For two listening nodes, configuration assigns one side `dial` and the other
  `accept`. If stale configuration briefly causes simultaneous connections,
  both sides keep the session initiated by the lexicographically smaller
  `(dialer_node_uuid, session_uuid)` and close the duplicate.

When an active connection disappears, only its configured `dial` side starts a
reconnect loop. The `accept` side does not probe or dial a peer that is not
listening. The DDL validation triggers reject an enabled `dial` row whose peer
does not advertise a listener and an enabled `accept` row when the local node
does not listen.

### JSON-over-TCP framing

TCP is a byte stream and does not preserve message boundaries. Each message is
encoded as:

1. A four-byte unsigned big-endian length containing the compressed payload
   size.
2. Exactly that many bytes containing one gzip member.
3. The gzip member decompresses to one UTF-8 canonical JSON object.

The length prefix is not compressed. Receivers reject zero-length frames,
frames above `max_compressed_frame_bytes`, invalid gzip data, decompressed data
above `max_uncompressed_message_bytes`, invalid UTF-8, duplicate JSON keys, or
non-canonical message envelopes. Compression is per message, not across the
entire TCP stream, so a damaged frame does not corrupt later compression state.

Every JSON envelope contains at least:

- `protocol_version`
- `message_uuid`
- `message_type`
- `sender_node_uuid`
- `sender_incarnation_uuid`
- `replication_domain`
- `sent_at_utc`
- `body`
- `payload_hash`
- `signature` when origin signing is required

The first messages authenticate both endpoints and exchange node identity,
incarnation, membership epoch, schema compatibility values, cursor vectors,
and size limits. Application data exchange starts only after validation.
Production connections use `tls_tcp`; plain `tcp` is restricted to explicitly
approved isolated environments.

## 13. SQLite DDL

Create `replication_nodes` first because the other tables reference it.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE replication_nodes (
    node_uuid              TEXT PRIMARY KEY,
    incarnation_uuid       TEXT NOT NULL UNIQUE,
    node_name              TEXT NOT NULL UNIQUE,
    replication_domain     TEXT NOT NULL,
    is_local               INTEGER NOT NULL DEFAULT 0
                           CHECK (is_local IN (0, 1)),
    membership_state       TEXT NOT NULL DEFAULT 'joining'
                           CHECK (membership_state IN ('joining', 'active', 'retired')),
    membership_epoch       INTEGER NOT NULL DEFAULT 1
                           CHECK (membership_epoch > 0),
    listen_enabled         INTEGER NOT NULL DEFAULT 0
                           CHECK (listen_enabled IN (0, 1)),
    hostname               TEXT,
    ip_address             TEXT,
    port                   INTEGER
                           CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    protocol               TEXT NOT NULL DEFAULT 'tls_tcp'
                           CHECK (protocol IN ('tcp', 'tls_tcp')),
    wire_encoding          TEXT NOT NULL DEFAULT 'json'
                           CHECK (wire_encoding = 'json'),
    wire_compression       TEXT NOT NULL DEFAULT 'gzip'
                           CHECK (wire_compression = 'gzip'),
    auth_mode              TEXT NOT NULL
                           CHECK (auth_mode IN ('psk', 'mtls')),
    credential_name        TEXT,
    next_credential_name   TEXT,
    tls_server_name        TEXT,
    tls_cert_fingerprint   TEXT,
    origin_verify_key_name TEXT,
    enabled                INTEGER NOT NULL DEFAULT 0
                           CHECK (enabled IN (0, 1)),
    rebootstrap_required   INTEGER NOT NULL DEFAULT 1
                           CHECK (rebootstrap_required IN (0, 1)),
    joined_at_utc          TEXT,
    retired_at_utc         TEXT,
    created_at_utc         TEXT NOT NULL,
    updated_at_utc         TEXT NOT NULL,
    last_seen_at_utc       TEXT,
    UNIQUE (node_uuid, incarnation_uuid),
    CHECK (
        listen_enabled = 0
        OR (port IS NOT NULL AND (hostname IS NOT NULL OR ip_address IS NOT NULL))
    ),
    CHECK (enabled = 0 OR membership_state = 'active'),
    CHECK (
        (membership_state = 'retired' AND retired_at_utc IS NOT NULL
         AND enabled = 0 AND rebootstrap_required = 1)
        OR membership_state <> 'retired'
    ),
    CHECK (auth_mode <> 'mtls' OR protocol = 'tls_tcp'),
    CHECK (
        auth_mode <> 'psk'
        OR is_local = 1
        OR credential_name IS NOT NULL
    )
);

CREATE UNIQUE INDEX ux_replication_nodes_one_local
    ON replication_nodes (is_local)
    WHERE is_local = 1 AND retired_at_utc IS NULL;

CREATE INDEX ix_replication_nodes_domain_enabled
    ON replication_nodes (replication_domain, enabled);

CREATE TABLE replication_peer_connections (
    peer_node_uuid                 TEXT PRIMARY KEY,
    connection_role               TEXT NOT NULL
                                  CHECK (connection_role IN ('dial', 'accept')),
    enabled                       INTEGER NOT NULL DEFAULT 0
                                  CHECK (enabled IN (0, 1)),
    reconnect_enabled             INTEGER NOT NULL
                                  CHECK (reconnect_enabled IN (0, 1)),
    connect_timeout_ms            INTEGER NOT NULL DEFAULT 10000
                                  CHECK (connect_timeout_ms > 0),
    heartbeat_interval_ms         INTEGER NOT NULL DEFAULT 15000
                                  CHECK (heartbeat_interval_ms > 0),
    heartbeat_timeout_ms          INTEGER NOT NULL DEFAULT 45000
                                  CHECK (heartbeat_timeout_ms > heartbeat_interval_ms),
    tcp_keepalive_seconds         INTEGER NOT NULL DEFAULT 30
                                  CHECK (tcp_keepalive_seconds > 0),
    reconnect_initial_ms          INTEGER NOT NULL DEFAULT 1000
                                  CHECK (reconnect_initial_ms > 0),
    reconnect_max_ms              INTEGER NOT NULL DEFAULT 60000
                                  CHECK (reconnect_max_ms >= reconnect_initial_ms),
    reconnect_jitter_percent      INTEGER NOT NULL DEFAULT 20
                                  CHECK (reconnect_jitter_percent BETWEEN 0 AND 100),
    max_compressed_frame_bytes    INTEGER NOT NULL DEFAULT 8388608
                                  CHECK (max_compressed_frame_bytes > 0),
    max_uncompressed_message_bytes INTEGER NOT NULL DEFAULT 33554432
                                  CHECK (max_uncompressed_message_bytes >= max_compressed_frame_bytes),
    max_events_per_batch           INTEGER NOT NULL DEFAULT 500
                                  CHECK (max_events_per_batch > 0),
    max_batch_uncompressed_bytes   INTEGER NOT NULL DEFAULT 16777216
                                  CHECK (max_batch_uncompressed_bytes > 0
                                         AND max_batch_uncompressed_bytes <= max_uncompressed_message_bytes),
    max_inflight_events            INTEGER NOT NULL DEFAULT 2000
                                  CHECK (max_inflight_events >= max_events_per_batch),
    max_inflight_bytes             INTEGER NOT NULL DEFAULT 67108864
                                  CHECK (max_inflight_bytes >= max_batch_uncompressed_bytes),
    max_gap_ranges_per_request     INTEGER NOT NULL DEFAULT 128
                                  CHECK (max_gap_ranges_per_request > 0),
    max_events_per_gap_response    INTEGER NOT NULL DEFAULT 2000
                                  CHECK (max_events_per_gap_response > 0),
    session_state                 TEXT NOT NULL DEFAULT 'disabled'
                                  CHECK (session_state IN ('disconnected', 'connecting', 'connected', 'disabled')),
    last_session_uuid             TEXT,
    last_session_direction        TEXT
                                  CHECK (last_session_direction IS NULL OR last_session_direction IN ('outbound', 'inbound')),
    connected_at_utc              TEXT,
    disconnected_at_utc           TEXT,
    next_retry_at_utc             TEXT,
    consecutive_failures          INTEGER NOT NULL DEFAULT 0
                                  CHECK (consecutive_failures >= 0),
    last_error                    TEXT,
    updated_at_utc                TEXT NOT NULL,
    FOREIGN KEY (peer_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (
        (connection_role = 'dial' AND reconnect_enabled = 1)
        OR (connection_role = 'accept' AND reconnect_enabled = 0)
    ),
    CHECK (connection_role = 'dial' OR next_retry_at_utc IS NULL),
    CHECK (enabled = 1 OR session_state = 'disabled')
);

CREATE INDEX ix_replication_peer_connections_state
    ON replication_peer_connections (enabled, session_state, next_retry_at_utc);

CREATE TRIGGER replication_peer_connections_validate_insert
BEFORE INSERT ON replication_peer_connections
WHEN NEW.enabled = 1
BEGIN
    SELECT CASE
        WHEN NEW.connection_role = 'dial' AND NOT EXISTS (
            SELECT 1 FROM replication_nodes
            WHERE node_uuid = NEW.peer_node_uuid
              AND listen_enabled = 1
              AND enabled = 1
              AND membership_state = 'active'
        ) THEN RAISE(ABORT, 'dial peer is not an active listening node')
        WHEN NEW.connection_role = 'accept' AND NOT EXISTS (
            SELECT 1 FROM replication_nodes
            WHERE is_local = 1
              AND listen_enabled = 1
              AND enabled = 1
              AND membership_state = 'active'
              AND retired_at_utc IS NULL
        ) THEN RAISE(ABORT, 'local node must listen for an accept connection')
    END;
END;

CREATE TRIGGER replication_peer_connections_validate_update
BEFORE UPDATE OF peer_node_uuid, connection_role, enabled
ON replication_peer_connections
WHEN NEW.enabled = 1
BEGIN
    SELECT CASE
        WHEN NEW.connection_role = 'dial' AND NOT EXISTS (
            SELECT 1 FROM replication_nodes
            WHERE node_uuid = NEW.peer_node_uuid
              AND listen_enabled = 1
              AND enabled = 1
              AND membership_state = 'active'
        ) THEN RAISE(ABORT, 'dial peer is not an active listening node')
        WHEN NEW.connection_role = 'accept' AND NOT EXISTS (
            SELECT 1 FROM replication_nodes
            WHERE is_local = 1
              AND listen_enabled = 1
              AND enabled = 1
              AND membership_state = 'active'
              AND retired_at_utc IS NULL
        ) THEN RAISE(ABORT, 'local node must listen for an accept connection')
    END;
END;

CREATE TRIGGER replication_nodes_protect_active_listener
BEFORE UPDATE OF listen_enabled, enabled, membership_state
ON replication_nodes
WHEN EXISTS (
    SELECT 1
    FROM replication_peer_connections AS connection
    WHERE connection.enabled = 1
      AND (
          (NEW.is_local = 1
           AND connection.connection_role = 'accept'
           AND (NEW.listen_enabled = 0
                OR NEW.enabled = 0
                OR NEW.membership_state <> 'active'))
          OR
          (connection.peer_node_uuid = NEW.node_uuid
           AND connection.connection_role = 'dial'
           AND (NEW.listen_enabled = 0
                OR NEW.enabled = 0
                OR NEW.membership_state <> 'active'))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'disable dependent peer connections before disabling this listener');
END;

CREATE TABLE replication_changes (
    change_seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    change_uuid            TEXT NOT NULL UNIQUE,
    origin_node_uuid       TEXT NOT NULL,
    origin_counter         INTEGER NOT NULL CHECK (origin_counter > 0),
    transaction_uuid       TEXT,
    operation              TEXT NOT NULL
                           CHECK (operation IN ('insert', 'update', 'delete')),
    table_name             TEXT NOT NULL,
    row_key_json           TEXT NOT NULL CHECK (json_valid(row_key_json)),
    changed_fields_json    TEXT
                           CHECK (
                               changed_fields_json IS NULL
                               OR (
                                   json_valid(changed_fields_json)
                                   AND json_type(changed_fields_json) = 'array'
                               )
                           ),
    is_explicit_recreation INTEGER NOT NULL DEFAULT 0
                           CHECK (is_explicit_recreation IN (0, 1)),
    hlc_physical_utc_us     INTEGER NOT NULL CHECK (hlc_physical_utc_us >= 0),
    hlc_logical            INTEGER NOT NULL CHECK (hlc_logical >= 0),
    schema_version         INTEGER NOT NULL CHECK (schema_version > 0),
    schema_hash            TEXT NOT NULL
                           CHECK (
                               length(schema_hash) = 64
                               AND schema_hash = lower(schema_hash)
                               AND schema_hash NOT GLOB '*[^0-9a-f]*'
                           ),
    canonicalization_version INTEGER NOT NULL
                           CHECK (canonicalization_version > 0),
    merge_policy_version   INTEGER NOT NULL
                           CHECK (merge_policy_version > 0),
    replication_domain     TEXT NOT NULL,
    created_at_utc         TEXT NOT NULL,
    stored_at_utc          TEXT NOT NULL,
    source_node_uuid       TEXT,
    payload_hash           TEXT NOT NULL
                           CHECK (
                               length(payload_hash) = 64
                               AND payload_hash = lower(payload_hash)
                               AND payload_hash NOT GLOB '*[^0-9a-f]*'
                           ),
    payload_uncompressed_bytes INTEGER NOT NULL
                           CHECK (payload_uncompressed_bytes >= 0),
    origin_signature       BLOB,
    apply_state            TEXT NOT NULL DEFAULT 'pending'
                           CHECK (
                               apply_state IN (
                                   'pending', 'applied', 'ignored', 'quarantined'
                               )
                           ),
    quarantine_reason      TEXT,
    payload_state          TEXT NOT NULL DEFAULT 'retained'
                           CHECK (payload_state IN ('retained', 'compacted')),
    compacted_by_snapshot_uuid TEXT,
    compacted_at_utc       TEXT,
    FOREIGN KEY (origin_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (source_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (compacted_by_snapshot_uuid)
        REFERENCES replication_snapshots (snapshot_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE (origin_node_uuid, origin_counter),
    CHECK (
        (apply_state = 'quarantined' AND quarantine_reason IS NOT NULL)
        OR
        (apply_state <> 'quarantined' AND quarantine_reason IS NULL)
    ),
    CHECK (
        operation = 'insert'
        OR is_explicit_recreation = 0
    ),
    CHECK (
        (payload_state = 'retained'
         AND changed_fields_json IS NOT NULL
         AND compacted_by_snapshot_uuid IS NULL
         AND compacted_at_utc IS NULL)
        OR
        (payload_state = 'compacted'
         AND changed_fields_json IS NULL
         AND compacted_by_snapshot_uuid IS NOT NULL
         AND compacted_at_utc IS NOT NULL)
    )
);

CREATE INDEX ix_replication_changes_origin_counter
    ON replication_changes (origin_node_uuid, origin_counter);

CREATE INDEX ix_replication_changes_delivery
    ON replication_changes (apply_state, change_seq);

CREATE INDEX ix_replication_changes_row
    ON replication_changes (table_name, row_key_json);

CREATE TABLE replication_change_acks (
    ack_seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
    change_uuid             TEXT NOT NULL,
    acknowledging_node_uuid TEXT NOT NULL,
    ack_state               TEXT NOT NULL
                            CHECK (ack_state IN ('applied', 'ignored')),
    acknowledged_at_utc     TEXT,
    recorded_at_utc         TEXT NOT NULL,
    FOREIGN KEY (change_uuid)
        REFERENCES replication_changes (change_uuid)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    FOREIGN KEY (acknowledging_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE (change_uuid, acknowledging_node_uuid)
);

CREATE INDEX ix_replication_change_acks_node
    ON replication_change_acks (acknowledging_node_uuid, change_uuid);

CREATE TABLE replication_local_state (
    state_id                 INTEGER PRIMARY KEY CHECK (state_id = 1),
    local_node_uuid          TEXT NOT NULL UNIQUE,
    local_incarnation_uuid   TEXT NOT NULL UNIQUE,
    replication_domain      TEXT NOT NULL,
    last_origin_counter      INTEGER NOT NULL DEFAULT 0
                             CHECK (last_origin_counter >= 0),
    last_hlc_physical_utc_us INTEGER NOT NULL DEFAULT 0
                             CHECK (last_hlc_physical_utc_us >= 0),
    last_hlc_logical         INTEGER NOT NULL DEFAULT 0
                             CHECK (last_hlc_logical >= 0),
    membership_epoch         INTEGER NOT NULL DEFAULT 1
                             CHECK (membership_epoch > 0),
    membership_manifest_hash TEXT NOT NULL
                             CHECK (
                                 length(membership_manifest_hash) = 64
                                 AND membership_manifest_hash = lower(membership_manifest_hash)
                                 AND membership_manifest_hash NOT GLOB '*[^0-9a-f]*'
                             ),
    database_generation      INTEGER NOT NULL DEFAULT 1
                             CHECK (database_generation > 0),
    restore_epoch            INTEGER NOT NULL DEFAULT 0
                             CHECK (restore_epoch >= 0),
    network_enabled          INTEGER NOT NULL DEFAULT 0
                             CHECK (network_enabled IN (0, 1)),
    schema_version           INTEGER NOT NULL CHECK (schema_version > 0),
    schema_hash              TEXT NOT NULL
                             CHECK (length(schema_hash) = 64 AND schema_hash = lower(schema_hash)),
    created_at_utc           TEXT NOT NULL,
    updated_at_utc           TEXT NOT NULL,
    FOREIGN KEY (local_node_uuid, local_incarnation_uuid)
        REFERENCES replication_nodes (node_uuid, incarnation_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE replication_field_versions (
    table_name                   TEXT NOT NULL,
    row_key_json                 TEXT NOT NULL CHECK (json_valid(row_key_json)),
    field_name                   TEXT NOT NULL,
    winner_hlc_physical_utc_us   INTEGER NOT NULL CHECK (winner_hlc_physical_utc_us >= 0),
    winner_hlc_logical           INTEGER NOT NULL CHECK (winner_hlc_logical >= 0),
    winner_origin_node_uuid      TEXT NOT NULL,
    winner_change_uuid           TEXT NOT NULL,
    winner_changed_at_utc        TEXT NOT NULL,
    value_hash                   TEXT,
    updated_at_utc               TEXT NOT NULL,
    PRIMARY KEY (table_name, row_key_json, field_name),
    FOREIGN KEY (winner_origin_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (winner_change_uuid)
        REFERENCES replication_changes (change_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (value_hash IS NULL OR (length(value_hash) = 64 AND value_hash = lower(value_hash)))
);

CREATE INDEX ix_replication_field_versions_event
    ON replication_field_versions (winner_change_uuid);

CREATE TABLE replication_row_versions (
    table_name                   TEXT NOT NULL,
    row_key_json                 TEXT NOT NULL CHECK (json_valid(row_key_json)),
    row_state                    TEXT NOT NULL CHECK (row_state IN ('live', 'deleted')),
    winner_hlc_physical_utc_us   INTEGER NOT NULL CHECK (winner_hlc_physical_utc_us >= 0),
    winner_hlc_logical           INTEGER NOT NULL CHECK (winner_hlc_logical >= 0),
    winner_origin_node_uuid      TEXT NOT NULL,
    winner_change_uuid           TEXT NOT NULL,
    winner_changed_at_utc        TEXT NOT NULL,
    prunable_after_snapshot_uuid TEXT,
    updated_at_utc               TEXT NOT NULL,
    PRIMARY KEY (table_name, row_key_json),
    FOREIGN KEY (winner_origin_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (winner_change_uuid)
        REFERENCES replication_changes (change_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (prunable_after_snapshot_uuid)
        REFERENCES replication_snapshots (snapshot_uuid)
        ON UPDATE RESTRICT ON DELETE SET NULL
);

CREATE INDEX ix_replication_row_versions_state
    ON replication_row_versions (row_state, winner_hlc_physical_utc_us);

CREATE TABLE replication_snapshots (
    snapshot_uuid          TEXT PRIMARY KEY,
    created_by_node_uuid   TEXT NOT NULL,
    replication_domain    TEXT NOT NULL,
    membership_epoch      INTEGER NOT NULL CHECK (membership_epoch > 0),
    membership_manifest_hash TEXT NOT NULL
                          CHECK (
                              length(membership_manifest_hash) = 64
                              AND membership_manifest_hash = lower(membership_manifest_hash)
                              AND membership_manifest_hash NOT GLOB '*[^0-9a-f]*'
                          ),
    schema_version        INTEGER NOT NULL CHECK (schema_version > 0),
    schema_hash           TEXT NOT NULL
                          CHECK (length(schema_hash) = 64 AND schema_hash = lower(schema_hash)),
    baseline_cursors_gzip BLOB NOT NULL,
    baseline_cursors_uncompressed_bytes INTEGER NOT NULL
                          CHECK (baseline_cursors_uncompressed_bytes >= 0),
    content_hash          TEXT NOT NULL
                          CHECK (length(content_hash) = 64 AND content_hash = lower(content_hash)),
    snapshot_auth_mode    TEXT NOT NULL
                          CHECK (snapshot_auth_mode IN ('session', 'external_signature')),
    creator_signing_key_id TEXT,
    creator_signature     BLOB,
    content_size_bytes    INTEGER NOT NULL CHECK (content_size_bytes >= 0),
    storage_uri           TEXT,
    snapshot_state        TEXT NOT NULL
                          CHECK (snapshot_state IN ('creating', 'ready', 'installed', 'superseded', 'invalid')),
    installed_by_node_uuid TEXT,
    created_at_utc        TEXT NOT NULL,
    verified_at_utc       TEXT,
    installed_at_utc      TEXT,
    FOREIGN KEY (created_by_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (installed_by_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (
        (snapshot_state = 'installed' AND installed_by_node_uuid IS NOT NULL
         AND installed_at_utc IS NOT NULL)
        OR snapshot_state <> 'installed'
    ),
    CHECK (
        (snapshot_auth_mode = 'session'
         AND creator_signing_key_id IS NULL
         AND creator_signature IS NULL)
        OR
        (snapshot_auth_mode = 'external_signature'
         AND creator_signing_key_id IS NOT NULL
         AND creator_signature IS NOT NULL)
    )
);

CREATE TABLE replication_origin_cursors (
    tracking_node_uuid     TEXT NOT NULL,
    origin_node_uuid       TEXT NOT NULL,
    contiguous_counter     INTEGER NOT NULL DEFAULT 0
                           CHECK (contiguous_counter >= 0),
    highest_seen_counter   INTEGER NOT NULL DEFAULT 0
                           CHECK (highest_seen_counter >= contiguous_counter),
    baseline_snapshot_uuid TEXT,
    requires_snapshot      INTEGER NOT NULL DEFAULT 0
                           CHECK (requires_snapshot IN (0, 1)),
    updated_at_utc         TEXT NOT NULL,
    PRIMARY KEY (tracking_node_uuid, origin_node_uuid),
    FOREIGN KEY (tracking_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (origin_node_uuid)
        REFERENCES replication_nodes (node_uuid)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (baseline_snapshot_uuid)
        REFERENCES replication_snapshots (snapshot_uuid)
        ON UPDATE RESTRICT ON DELETE SET NULL
);

CREATE INDEX ix_replication_origin_cursors_origin
    ON replication_origin_cursors (origin_node_uuid, contiguous_counter);

CREATE TABLE replication_origin_gaps (
    tracking_node_uuid     TEXT NOT NULL,
    origin_node_uuid       TEXT NOT NULL,
    gap_start_counter      INTEGER NOT NULL CHECK (gap_start_counter > 0),
    gap_end_counter        INTEGER NOT NULL CHECK (gap_end_counter >= gap_start_counter),
    detected_at_utc        TEXT NOT NULL,
    last_requested_at_utc  TEXT,
    request_count          INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    PRIMARY KEY (tracking_node_uuid, origin_node_uuid, gap_start_counter),
    FOREIGN KEY (tracking_node_uuid, origin_node_uuid)
        REFERENCES replication_origin_cursors (tracking_node_uuid, origin_node_uuid)
        ON UPDATE RESTRICT ON DELETE CASCADE
);

CREATE TABLE replication_rejected_events (
    rejection_uuid          TEXT PRIMARY KEY,
    received_from_node_uuid TEXT,
    claimed_change_uuid     TEXT,
    claimed_origin_node_uuid TEXT,
    claimed_origin_counter  INTEGER,
    message_uuid            TEXT,
    evidence_hash           TEXT NOT NULL
                            CHECK (
                                length(evidence_hash) = 64
                                AND evidence_hash = lower(evidence_hash)
                                AND evidence_hash NOT GLOB '*[^0-9a-f]*'
                            ),
    bounded_evidence        BLOB,
    reason_code             TEXT NOT NULL,
    recorded_at_utc         TEXT NOT NULL,
    CHECK (
        claimed_origin_counter IS NULL
        OR claimed_origin_counter > 0
    )
);

CREATE INDEX ix_replication_rejected_events_claim
    ON replication_rejected_events (
        claimed_origin_node_uuid,
        claimed_origin_counter,
        recorded_at_utc
    );
```

### Generated per-application-table DDL

For each replicated application table, the schema generator emits a quoted,
collision-resistant typed payload table based on this structural template:

```sql
CREATE TABLE "<descriptor_id>__replication_changes" (
    change_uuid              TEXT PRIMARY KEY,
    field_versions_json      TEXT NOT NULL
                             CHECK (json_valid(field_versions_json)),
    -- One typed full-image value for every transmitted application column:
    "<column>__value"        <APPLICATION_DECLARED_TYPE>,
    -- One presence flag for every transmitted non-key column:
    "<column>__present"      INTEGER NOT NULL
                             CHECK ("<column>__present" IN (0, 1)),
    FOREIGN KEY (change_uuid)
        REFERENCES replication_changes (change_uuid)
        ON UPDATE RESTRICT ON DELETE CASCADE
);
```

Primary-key values and all full-row values are stored with their validated
SQLite types. Presence flags say which non-key values the event changes; an
explicit SQL NULL has `present = 1` and a NULL value. `field_versions_json`
contains the canonical provenance of every full-image field so missing-row
repair does not assign the current event version to unchanged values.

The generator also emits `AFTER INSERT`, `AFTER UPDATE`, and `AFTER DELETE`
triggers. Each trigger:

1. Calls fail-closed connection-local context functions and runs only in
   `local` apply mode.
2. Allocates one origin counter and HLC through the coordinated trigger
   context.
3. Inserts one `replication_changes` header.
4. Inserts one typed payload row in the generated table.
5. Updates field and row winners.

The UPDATE trigger derives presence using SQLite value identity (`OLD.column IS
NOT NEW.column`) and has a generated `WHEN` predicate that suppresses the event
when no transmitted value changed. The INSERT trigger marks all transmitted
columns present. The DELETE trigger records the typed OLD full image with no
changed field values. Remote
apply pins a connection in `remote` mode, so these triggers do not create loops.
If the context functions are absent, return an invalid state, or are registered
on the wrong connection, the write aborts.

The DDL uses SQLite's JSON functions in `CHECK` constraints. If SQLite is
compiled without JSON support, validate canonical JSON in the replication
service and remove only those JSON-specific checks.

## 14. Atomic local-change transaction

A local application statement and all replication metadata created by its
trigger firings share one SQLite transaction:

1. Pin one physical connection, set its fail-closed context to `local`, and
   begin a write transaction.
2. Execute the application statement.
3. For each affected row, the generated trigger atomically reads and advances
   `replication_local_state.last_origin_counter` and the persisted HLC.
4. The trigger inserts the immutable `replication_changes` header.
5. The trigger builds and inserts the typed per-table full image, per-field
   provenance, and presence flags referencing that header.
6. The trigger updates winning `replication_field_versions` rows.
7. The trigger updates `replication_row_versions` to `live` for insert, to
   `deleted` for delete, or leaves a tombstoned row deleted for an ordinary
   update. Only a context-authorized explicit recreation may clear a tombstone.
8. The trigger advances the local node's own origin cursor for each event.
9. Commit all application rows and trigger-created metadata together, then
   restore the connection context before returning it to the pool.

A successful application commit must never exist without its event and version
metadata. Counter and HLC values must not be allocated only in memory.

## 15. Incoming event transaction

For a remote change:

1. Authenticate the immediate peer and authorize the claimed origin.
2. Verify that the authenticated peer equals the event origin, then verify
   membership state, incarnation, replication domain, schema version and hash,
   UUID/counter uniqueness, payload hash, and any configured origin signature.
3. Begin one SQLite transaction and record any counter gap above the local
   contiguous cursor.
4. Insert the immutable header and typed per-table payload if absent.
5. Compare the event's row-state candidate against
   `replication_row_versions`.
6. If the winning state is live, compare each changed field with
   `replication_field_versions`. Reconstruct a missing row only for an insert,
   authorized explicit recreation, or repair, using the typed full row and
   embedded field versions without overwriting newer winners.
7. If the winning state is deleted, remove the application row but retain its
   row tombstone and field-version history.
8. Mark the event `applied`, `ignored`, or `quarantined`.
9. Repair gap ranges and advance the local contiguous cursor only through an
   uninterrupted sequence.
10. Commit, then send an acknowledgement only for `applied` or deterministically
    `ignored`.

Receiving the same event again is safe. Matching UUID/counter and payload hash
returns the previously committed result. Different content for an existing
identity cannot satisfy the log's unique constraints, so bounded evidence is
stored in `replication_rejected_events`; the existing event is never changed.

When an acknowledgement or cursor advertisement is received, the sender stores
it in a local transaction. Cursor state is the efficient source for delivery
progress; `replication_change_acks` supplies detailed per-event audit history.

## 16. Adding and removing nodes

To add a node:

1. Generate a new `node_uuid` and `incarnation_uuid`; never copy them from an
   existing database.
2. Distribute an authenticated membership record in `joining` state at a new
   `membership_epoch`.
3. Create complementary `dial`/`accept` connection rows for the new node and
   every active peer. Validate that each pair has one reachable listener.
4. Keep application writes or network synchronization disabled on the new node
   while installing a compatible logical snapshot or replaying every retained
   event.
5. Verify the snapshot, install its cursor baseline, and request all events
   above that baseline.
6. Mark the node and its peer connections `active`/enabled only after catch-up
   succeeds.

To remove a node:

1. Distribute an authenticated `retired` decision at a newer membership epoch.
2. Set `enabled = 0`, `rebootstrap_required = 1`, and `retired_at_utc`,
   then disable every local `replication_peer_connections` row for that node.
3. Preserve the node row, connection history, events, signatures, and cursor
   history.
4. Exclude it from future stability calculations only after every supported
   active node has accepted the retirement decision.

A retired installation cannot simply reconnect. It must receive a new node
identity and bootstrap from an accepted baseline. This prevents an old offline
copy from reintroducing counters or data that the active domain has already
retired.

## 17. Snapshot and compaction rules

Snapshot creation reads application data, field winners, row states, and the
local cursor vector from one consistent transaction. A destination verifies
the domain, membership epoch, schema guard, content hash, origin identity, and
baseline before activation.

An event payload or tombstone may be pruned only when either:

- every active member's cursor is beyond the required per-origin frontier; or
- every lagging supported member must install a snapshot whose baseline and
  state include the event or tombstone.

Per-event acknowledgements alone do not prove a domain-wide safe prune point.
Once payload compaction is safe, the generated typed payload row is deleted and
`changed_fields_json` may be cleared. The event header, schema guard, origin
counter, HLC, expanded size, and payload hash remain available for identity and
audit. If an added node needs history older than the retained
frontier, it must use a snapshot rather than request the discarded payloads.

## 18. Retention and security requirements

- Never use `change_seq`, acknowledgement order, or wall-clock time alone to
  resolve conflicts between origins. Use the event HLC and origin UUID total
  order.
- Never update an event's immutable envelope after it has been stored.
- Never capture replication-table writes as new application changes.
- Never accept an event from an unknown, joining, disabled, retired,
  wrong-incarnation, or wrong-domain origin.
- Require `source_node_uuid = origin_node_uuid` for every remote event.
  Forwarded events are not accepted by this full-mesh protocol.
- Never store plaintext passwords, PSKs, or private signing keys in these
  tables.
- Production TCP sessions must use TLS with PSK authentication inside the TLS
  session or mTLS. Message gzip compression is not encryption.
- Enforce both compressed and decompressed frame limits before parsing JSON.
- Never delete a historical node record merely because a node is offline or
  retired.
- Never enable networking after an uncertain restore until counter continuity
  is proven or the installation receives a new node identity and snapshot.
- Do not compact changes or tombstones without a membership-aware global safe
  frontier or mandatory snapshot/rebootstrap policy.

## 19. Generated merge plans and temporary batch staging

Persistent merge state remains in `replication_changes`,
`replication_field_versions`, and `replication_row_versions`. At startup the
service builds a descriptor for every replicated application table from
`PRAGMA table_xinfo`, `foreign_key_list`, `index_list`, `index_xinfo`, and
normalized table/trigger SQL. It validates the protocol-version-1 supported
constraint profile and `schema_hash`, quotes every SQLite identifier, and
generates the typed capture table, three capture triggers, and parameterized
merge statements. An event-supplied table or field name is accepted only after
lookup in that descriptor and is never interpolated directly into SQL.

A receiver may use the following connection-local TEMP table for a bounded,
set-based merge. It is scratch state, is never acknowledged or synchronized,
and disappears when the writer connection closes:

```sql
CREATE TEMP TABLE replication_apply_batch (
    batch_uuid             TEXT NOT NULL,
    change_uuid            TEXT NOT NULL,
    origin_node_uuid       TEXT NOT NULL,
    origin_counter         INTEGER NOT NULL CHECK (origin_counter > 0),
    operation              TEXT NOT NULL
                           CHECK (operation IN ('insert', 'update', 'delete')),
    table_name             TEXT NOT NULL,
    row_key_json           TEXT NOT NULL CHECK (json_valid(row_key_json)),
    field_name             TEXT NOT NULL,
    value_present          INTEGER NOT NULL DEFAULT 1
                           CHECK (value_present = 1),
    typed_value_json       TEXT NOT NULL CHECK (json_valid(typed_value_json)),
    hlc_physical_utc_us    INTEGER NOT NULL CHECK (hlc_physical_utc_us >= 0),
    hlc_logical            INTEGER NOT NULL CHECK (hlc_logical >= 0),
    PRIMARY KEY (batch_uuid, change_uuid, table_name, row_key_json, field_name)
) WITHOUT ROWID;

CREATE INDEX replication_apply_batch_winner
    ON replication_apply_batch (
        batch_uuid,
        table_name,
        row_key_json,
        field_name,
        hlc_physical_utc_us DESC,
        hlc_logical DESC,
        origin_node_uuid DESC
    );
```

One staging row means the field is present. A typed NULL envelope remains a
present value and clears the application column if it wins. Omitted fields
have no staging row. Delete and live row-state candidates are selected by a
separate generated statement using the same version tuple; they must not be
inferred from the presence or absence of field rows.

The TEMP table may be replaced by equivalent in-memory bindings or an audited
deterministic SQLite aggregate. Regardless of implementation, event insertion,
winning application values, field versions, row versions, gap/cursor changes,
and final apply state commit in one writer transaction.

## 20. Schema and type self-test

Before `network_enabled` may become `1`, every generated table plan and type
adapter must pass a round-trip self-test. The test uses a rollback-only
transaction or a dedicated disposable database and verifies:

- simple and composite canonical primary keys;
- omitted fields versus explicit SQL `NULL`;
- signed integer limits and integers encoded outside JSON's interoperable
  numeric range;
- exact decimals, floating-point policy, Unicode normalization, UUIDs, dates,
  timestamps, structured JSON, and BLOB Base64url conversion;
- full-row reconstruction without overwriting a newer unrelated field;
- identifier quoting and every generated prepared statement.

The descriptor validation also rejects protocol-version-1 unsupported schemas:
non-primary-key UNIQUE constraints, CHECK constraints spanning replicated
columns, foreign keys between independently writable replicated rows,
transmitted generated/hidden columns, mutable primary keys, and non-SQLiteSeal
triggers that mutate another replicated table. Generated columns may exist only
when excluded from transmission and recomputed locally.

The production self-test must not consume `last_origin_counter`, advance the
HLC, or create a row in `replication_changes`. Failure keeps networking
disabled and reports a table- and adapter-specific health error.

## 21. Gap audit and bounded repair query

Incremental maintenance of `replication_origin_gaps` is authoritative during
normal receive processing. A periodic reconciliation query detects internal
discontinuities in the retained event identities:

```sql
WITH ordered AS (
    SELECT
        origin_node_uuid,
        origin_counter,
        LEAD(origin_counter) OVER (
            PARTITION BY origin_node_uuid
            ORDER BY origin_counter
        ) AS next_counter
    FROM replication_changes
    WHERE apply_state <> 'quarantined'
)
SELECT
    origin_node_uuid,
    origin_counter + 1 AS gap_start_counter,
    next_counter - 1 AS gap_end_counter
FROM ordered
WHERE next_counter > origin_counter + 1
ORDER BY origin_node_uuid, gap_start_counter;
```

The audit also compares the first retained counter with the local contiguous
cursor or installed snapshot baseline so a missing prefix is not overlooked.
Quarantined identities block cursor advancement and are handled explicitly;
they must not be silently converted into an ordinary repairable gap.

Gap requests and responses are limited by
`max_gap_ranges_per_request`, `max_events_per_gap_response`, negotiated batch
bytes, and in-flight limits. A truncated response carries a continuation
cursor. If the requested payload was compacted and cannot be reconstructed,
the response is `snapshot_required`, never an empty successful response.

## 22. SQLite writer and required trigger capture

All writes to application data and replication metadata use one coordinated
SQLite writer. Every connection enables `PRAGMA foreign_keys = ON`.
File-backed databases should use WAL, an explicitly selected `synchronous`
policy, and a bounded `busy_timeout`. Replicated writes should use
`BEGIN IMMEDIATE` when early lock acquisition is appropriate. After
`SQLITE_BUSY`, the service retries the entire idempotent transaction with
bounded backoff and emits no acknowledgment before commit.

Every replicated application table must have its generated typed payload table
and INSERT/UPDATE/DELETE triggers. Startup verifies their normalized definitions
before enabling writes or networking. Every pooled connection registers the
fail-closed local/remote apply-mode functions used by those triggers. Remote
apply pins a connection and sets `remote` mode only for the duration of its
transaction; returning a connection to the pool while remote mode is active is
a fatal invariant violation.
