Masterless Replication Algorithm

Document: REPLICATION_plan.md

Status: Implementation specification

Scope: Multi-node, offline-capable database replication over persistent TCP

Capture model: One generated typed replication table and three interception
triggers for each replicated application table

Conflict model: Last-Write-Wins per field using a Hybrid Logical Clock

Transport: Length-prefixed gzip-compressed JSON over TCP, with TLS plus a
user-provided pre-shared key or user-provided mutual-TLS credentials

1. Purpose

This document specifies a deterministic masterless replication algorithm for nodes that may independently modify their local databases, operate while disconnected, and later exchange changes.

Every node is writable. There is no permanently designated primary node. A node records each committed local change as an immutable replication event, exchanges events with its peers, and merges received events into its local database.

For every replicated application table, SQLiteSeal generates a durable typed
capture table plus `AFTER INSERT`, `AFTER UPDATE`, and `AFTER DELETE` triggers.
The triggers intercept application mutations inside the caller's SQLite
transaction. A trigger firing creates one row-level replication event and its
typed payload. The application mutation and capture rows therefore commit or
roll back together.

The design provides:

Offline operation.

Eventual convergence between healthy nodes.

Per-field conflict resolution.

Real-world UTC timestamps for auditing.

Hybrid Logical Clock ordering for deterministic conflict resolution.

Duplicate-safe and retry-safe delivery.

Detection and repair of missing events.

Row deletion through tombstones.

UUID-based primary keys to avoid offline key collisions.

Persistent bidirectional TCP connections using gzip-compressed JSON frames, protected by TLS.

Authentication using either a pre-shared key or mutual TLS certificates.

SQLiteSeal consumes credentials supplied through configuration or an external
secret provider. It does not issue, create, rotate, distribute, or revoke
certificates or pre-shared keys.

Log compaction and new-node bootstrap procedures.

Direct full-mesh peer exchange with configured dialer and listener roles.

This document describes the algorithm and required functions. It does not prescribe a programming language or database library. The wire representation is canonical JSON compressed independently with gzip.

2. Design Principles

2.1 Every node is a master

Each node may accept local writes whether or not its peers are online. A node must not require a quorum to commit a local application change unless the application defines a separate consistency requirement.

2.2 Local writes are committed atomically with their replication event

The application data change, generated per-table capture row, global event
header, local counter update, field-version update, and any tombstone update
must be committed in one local database transaction by the generated trigger
path.

A successful application commit must never exist without a corresponding replication event.

A replication event must never be visible as committed if the corresponding application mutation was rolled back.

2.3 Events are immutable

Once created, an event must not be edited. Corrections are represented by newer events.

An event keeps the identity of the node that originally created it, and it is exchanged directly with that authenticated origin in the full mesh.

2.4 Conflict resolution occurs per field

An update to one field must not overwrite unrelated fields changed independently on another node.

For example, if Node A changes a customer's telephone number while Node B changes the same customer's mailing address, both changes should survive synchronization.

2.5 Delivery ordering and conflict ordering are separate concepts

The node counter is used for event identity, synchronization, gap detection, and delivery ordering within one event origin.

The Hybrid Logical Clock is used to decide which value wins during a conflict.

A node counter from Node A must never be numerically compared with a node counter from Node B to determine which change is newer.

2.6 Retries are normal

Network connections can fail at any point. Every synchronization operation must be safe to retry.

Receiving the same event more than once must not produce additional application changes, additional locally originated events, or inconsistent cursor advancement.

2.7 All nodes eventually converge

If all valid events are eventually delivered to every node, every node must independently calculate the same winning value for every replicated field and row tombstone.

2.8 SQLite has one coordinated writer

Every application write, remote apply, cursor update, snapshot activation, and
compaction operation must pass through one local writer coordinator. The
coordinator owns or pins the SQLite write connection and serializes write
transactions; network readers and decompression workers may run concurrently,
but they may not write through independent pooled connections.

Every database connection must enable foreign keys. File-backed databases
should use WAL mode, an explicitly selected synchronous policy, and a bounded
busy timeout. Replicated transactions should use `BEGIN IMMEDIATE` when early
write-lock acquisition is needed. `SQLITE_BUSY` is retried with bounded
backoff before any network acknowledgment, and a retry must rerun the complete
transaction rather than only its final statement.

3. Terminology

Term

Meaning

Node

An independently writable replication participant.

Node ID

A permanent unique identifier assigned to a node.

Origin node

The node that originally created an event.

Peer

A remote node participating in synchronization.

Event

An immutable record describing one trigger-intercepted row mutation.

Origin counter

A strictly increasing counter allocated by the origin node.

Event ID

The unique pair of origin node ID and origin counter.

UTC change time

The wall-clock time recorded when the local change was committed.

HLC

Hybrid Logical Clock composed of physical time and a logical counter.

Field version

The winning HLC and origin node associated with one database field.

Tombstone

Persistent metadata representing a deleted row.

Cursor vector

A map showing which contiguous events are known for every origin node.

Gap

A missing counter between already received counters from the same origin.

Snapshot

A consistent representation of current application data and version metadata.

PSK

A pre-shared secret used to authenticate an approved peer.

mTLS

Mutual TLS, where both ends present and validate certificates.

4. Node Identity

Every node must have a permanent node_id.

The node ID must:

Be globally unique within the replication domain.

Remain unchanged across service restarts.

Remain unchanged across software upgrades.

Be protected from accidental regeneration.

Be included in every locally originated event.

Be bound to the node's PSK identity or mTLS certificate identity.

Be rejected if another active peer presents the same identity unexpectedly.

A UUID is recommended for the internal node identity. A separate human-readable node name may be maintained for administration.

Example conceptual identity:

Attribute

Example

Node ID

06e24593-749c-49a6-a64a-89c0cb180124

Display name

SITE-OTTAWA-01

Replication domain

PRODUCTION

Enabled

true

Cloning a database or virtual machine must not create two active nodes with the same node ID. A clone operation must include an explicit node re-enrollment procedure.

5. Primary Keys

Replicated rows must use keys that can be independently generated without coordination.

Recommended key types are:

UUID version 4.

UUID version 7.

Another globally unique text or binary identifier.

Auto-incrementing integers must not be used as the sole replicated primary key when multiple nodes can create rows while disconnected.

If an existing application requires integer identifiers, it should add a separate globally unique replication identity or allocate non-overlapping key ranges by node. A globally unique identifier is simpler and safer.

Composite primary keys are supported, but their canonical serialization must be identical on every node.

6. Time Model

6.1 Time synchronization

Every node should synchronize its operating-system clock with an approved time source.

Preferred arrangements include:

Common organizational NTP servers.

Domain or enterprise time infrastructure.

Approved local NTP servers at disconnected sites.

A trusted GPS-backed or hardware time source where required.

Nodes should not normally set their clocks directly from replication peers. Replication peers may report clock observations, but system time should be disciplined by the approved time service.

6.2 UTC change time

Every locally originated event records the actual UTC time at which the change is committed.

The UTC change time is intended for:

Audit history.

User-visible change history.

Troubleshooting.

Replication-latency measurement.

Administrative reporting.

The time should be stored with at least millisecond precision. Higher precision may be retained if it is reliable across all supported platforms.

UTC time alone must not be the only conflict-resolution value because:

Two events can occur during the same clock tick.

Nodes can have small clock offsets.

A system clock can move backward after correction.

A disconnected node may have an inaccurate clock.

Virtual machines may experience clock discontinuities.

6.3 Hybrid Logical Clock

Every event also receives a Hybrid Logical Clock value containing:

Component

Purpose

Physical component

UTC Unix time represented as a fixed integer unit, preferably milliseconds.

Logical component

Counter used when physical time does not advance or when remote time must be incorporated.

Origin node ID

Deterministic final tie-breaker when both HLC components are equal.

The complete deterministic comparison key is:

HLC physical time.

HLC logical counter.

Origin node ID.

The greater comparison key wins.

6.4 Local HLC generation

When a node creates a local event:

Read the current system UTC time.

Compare it with the last persisted local HLC physical value.

If system time is greater, use system time and reset the logical component to zero.

If system time is equal to or less than the last HLC physical value, retain the last physical value and increment the logical component.

Persist the new HLC in the same transaction as the event.

The HLC state must survive service restarts.

6.5 Receiving a remote HLC

Before or while applying a received event, the receiving node incorporates the remote HLC into its local HLC state.

The new local physical component is the maximum of:

Current system UTC time.

Last local HLC physical component.

Remote HLC physical component.

The logical component is then selected so the resulting local HLC is greater than both the previous local HLC and the received HLC.

This guarantees that future local events do not appear causally older than events already observed.

6.6 Clock health policy

Each node should monitor:

Current NTP synchronization status.

Estimated clock offset.

Time since last successful synchronization.

Backward system-clock adjustments.

Difference between remote HLC physical time and local system time.

Difference between remote reported UTC time and local receipt time.

Protocol version 1 has one domain-wide `maximum_future_skew` setting, defaulting
to five minutes. A valid event beyond that limit is durably quarantined without
changing its HLC, applying its payload, acknowledging it, or advancing its
origin cursor. It is retried when wall time enters the allowed window. Capping
or rewriting a remote HLC is forbidden because nodes could otherwise choose
different winners. A permanent administrative rejection requires retirement
and rebootstrap of the offending origin; it is not converted locally into a
different conflict result.

7. Replication Event Model

A replication event represents one intercepted row mutation. One application
transaction may produce several events, all carrying the same optional
`transaction_uuid`, but protocol version 1 does not promise atomic visibility
of the complete multi-row application transaction on a receiver.

Each event must contain the following metadata.

7.1 Event envelope

Field

Required

Description

Event ID

Yes

Unique identity derived from origin node ID and origin counter.

Origin node ID

Yes

Permanent identity of the node that created the event.

Origin counter

Yes

Strictly increasing counter allocated by the origin node.

UTC change time

Yes

Human-auditable time of the committed local change.

HLC physical value

Yes

Physical component used for ordering.

HLC logical value

Yes

Logical component used for ordering.

Schema version

Yes

Application replication schema version used by the event.

Schema hash

Yes

SHA-256 of the exact replicated-table, generated-trigger, type-adapter, and
policy descriptor used to encode the event.

Canonicalization and merge-policy versions

Yes

Version the typed envelope and deterministic row/field merge rules.

Replication domain

Yes

Prevents accidental exchange across environments.

Transaction ID

Optional

Diagnostic identifier correlating row events created by one local
transaction. It does not make the group an atomic wire or remote-apply unit.

Event type

Yes

Insert, update, delete, or another explicitly supported type.

Operation

Yes

Exactly one row operation contained in the event.

Payload hash

Yes

Integrity check over the canonical event payload.

Created by software version

Recommended

Diagnostic metadata.

Trace ID

Optional

Correlates application and replication logs.

7.2 Row operation

Each event's one row operation identifies:

Table or replicated entity.

Canonical primary key.

Operation type.

Changed fields.

Optional previous-value hash.

Optional business transaction context.

Only fields changed by the local transaction should appear in an update operation.

An omitted field means no change.

An explicit null value means the field is being set to database null.

7.3 Field value representation

The wire representation must preserve the intended database type.

At minimum, the serialization format must distinguish:

Null.

Boolean.

Signed integer.

Unsigned integer where supported.

Floating-point value.

Decimal value.

Text.

Binary data.

UTC date and time.

Date without time.

UUID.

Structured JSON value.

Values must not be converted through ambiguous locale-dependent strings.

Decimal values should use a canonical decimal representation rather than binary floating-point when exact financial or measurement precision is required.

Binary data may be transferred inline only below a configured limit. Large objects should use a separate content-transfer mechanism with a content hash and reference.

The implementation must maintain a schema-derived type-adapter registry. Each
adapter defines how one SQLite declared/application type is converted to and
from its canonical wire value. At minimum, adapters must define exact handling
for SQL `NULL`, signed integers beyond JSON's interoperable numeric range,
floating-point special values, decimals, BLOBs, UUIDs, dates, timestamps, and
structured JSON. BLOBs use canonical unpadded Base64url. Large integers and
exact decimals use canonical decimal strings with explicit type tags.

Every changed value uses an explicit presence marker. A present value tagged
as `null` means set the column to SQL `NULL`; a field absent from the changed
field set means no change. A merge function must never use SQL `coalesce` or a
NULL-skipping aggregate to infer field presence.

7.4 Canonical representation

The event must have a canonical representation for:

Payload hashing.

PSK message authentication.

Duplicate detection.

Integrity verification.

Reproducible diagnostics.

Canonicalization must define:

Field ordering.

Primary-key ordering.

Numeric representation.

Date and time format.

Unicode normalization.

Null representation.

Binary encoding.

Treatment of unknown fields.

Protocol version 1 uses RFC 8785 JSON Canonicalization Scheme after all input
strings and identifiers have been normalized to Unicode NFC. Typed envelopes
encode signed integers outside the interoperable JSON range and exact decimals
as canonical decimal strings. Non-finite floats are rejected. UUIDs are
canonical lower-case strings and are compared by their 16-byte value. SHA-256
over the uncompressed canonical event envelope is the payload hash.

The canonical primary-key object is constructed in schema primary-key order,
not caller insertion order. Unknown envelope fields are rejected unless a
negotiated protocol version explicitly defines them. The same canonical bytes
are used for hashing, duplicate comparison, signatures, storage keys, and
transmission. The immutable hashed envelope includes the schema version,
schema hash, canonicalization version, merge-policy version, event identity,
origin, counter, HLC, operation, row identity, typed payload, and explicit
recreation flag. Local receipt, apply, quarantine, acknowledgment, and
compaction metadata are excluded.

8. Local Persistent State

Each node requires the following categories of internal state.

8.1 Node state

Stores:

Permanent node ID.

Current local origin counter.

Last persisted local HLC.

Replication-domain identifier.

Current schema version.

Current schema hash.

Software protocol version.

Node enrollment status.

8.2 Replication event log and typed per-table payloads

Stores all locally originated and received events that have not yet been safely compacted.

`replication_changes` stores the common immutable event envelope. A generated
typed `<application_table>__replication_changes` table stores the full row
image, explicit changed-column presence flags, and embedded field-version
provenance for that table. The per-table row has a one-to-one foreign key to
the global event header. These per-table tables are required durable protocol
state, not optional performance caches.

The combination of origin node ID and origin counter must be unique.

The event log should retain:

Original immutable event payload.

Payload hash.

First received time on this node.

Validation state.

Application state.

Quarantine reason, if any.

Source peer from which it was first received.

Immediate source-peer and acknowledgment metadata.

8.3 Field-version metadata

Stores the winning version for every replicated field.

The logical key consists of:

Table or entity.

Canonical primary key.

Column or field name.

The stored value consists of:

Winning HLC physical component.

Winning HLC logical component.

Winning origin node ID.

Winning event ID.

UTC change time.

Optional value hash.

This table is required even when several fields are transported together in one event.

8.4 Row tombstones

Stores the winning deletion version for deleted rows.

A tombstone contains:

Table or entity.

Canonical primary key.

Deletion HLC.

Origin node ID.

Event ID.

UTC deletion time.

Optional reason.

Tombstone retention state.

8.5 Peer and origin cursors

A node must track synchronization progress separately for every origin represented in the replication domain.

A cursor must mean the highest contiguous counter received and durably stored from that origin.

It must not simply be the highest counter ever observed.

8.6 Gap tracking

When an event arrives above the next expected origin counter, the node records the missing range.

For example, if counters 100 and 102 are present but 101 is absent:

Highest observed counter is 102.

Highest contiguous counter is 100.

Missing range is 101 through 101.

Gap metadata may be represented explicitly or derived from the event log.

8.7 Peer configuration

Stores:

Peer node ID.

Endpoint address.

Enabled state.

Expected replication domain.

Authentication mode.

PSK key identifier or expected certificate identity.

Certificate trust configuration.

Direct-origin enforcement policy.

Whether the node listens for inbound TCP connections.

Local per-peer connection role: dial or accept.

JSON/gzip frame-size limits.

Heartbeat, TCP keepalive, and reconnect policy.

Last successful synchronization time.

Last error.

Administrative status.

9. Capturing Local Changes

9.1 Required transaction boundary

A local application statement and every trigger firing it causes perform the
following within one database transaction:

Validate the application mutation.

Apply the application data mutation.

For each affected row, let the generated trigger allocate the next origin
counter, generate the HLC, and record UTC time.

Update the affected field-version records.

Update or clear a row tombstone when appropriate.

Build the immutable replication event.

Store the replication event.

Persist the node counter and HLC state.

Commit.

If any step fails, the entire transaction must roll back.

9.2 Event creation source

Events are generated by SQLite triggers. Enabling replication for an
application table generates:

An `AFTER INSERT` trigger.

An `AFTER UPDATE` trigger.

An `AFTER DELETE` trigger.

A typed durable `<application_table>__replication_changes` table.

The triggers allocate the origin counter and HLC, insert the global event
header, insert the typed table-specific payload, and update field and row
versions in the same transaction as the application mutation. Trigger names
and table names are generated from a collision-resistant descriptor ID and are
always quoted.

9.3 Suppressing event loops

When applying a remote event, the node must mark the operation as replication-originated.

The local capture mechanism must not create a new origin event for that remote application.

The original event remains identified by its original node and original counter.

9.4 Row-sized events and transaction correlation

Every trigger firing creates exactly one event for one row. Several events
created in one local SQLite transaction commit atomically at their origin and
may share a `transaction_uuid`, but they are independently transmitted,
merged, and acknowledged.

Applications that require an invariant spanning several rows must model that
invariant as one replicated row or use an application-level workflow. Remote
atomic visibility of arbitrary multi-row transactions is outside protocol
version 1 and must not be advertised.

9.5 Generated table merge plans

At initialization, `BuildTableMergePlan` introspects every replicated table
using `PRAGMA table_xinfo`, the configured replication descriptor, and any
declared type adapters. It generates and prepares the statements needed to:

Canonicalize simple and composite primary keys.

Read the application row and current row-state winner.

Insert or update application columns without overwriting omitted fields.

Compare and upsert field-version winners.

Apply and clear row tombstones.

Reconstruct a missing row from a full row image and its embedded field
versions.

Plans are cached in memory and rebuilt whenever the local schema version or
schema hash changes. Identifiers come only from the validated schema
descriptor and are quoted as SQLite identifiers; event-supplied identifiers
must never be interpolated into SQL.

The same descriptor generates the typed capture table and the three capture
triggers. Startup compares their normalized SQL and descriptor version with
the expected generated definitions and fails closed if they were removed or
modified.

9.6 Replication write boundary

All INSERT, UPDATE, and DELETE statements against a replicated table are
intercepted by its generated triggers, including statements issued through the
exposed `database/sql` handle. Every SQLite connection registers fail-closed,
connection-local replication context functions before it may execute SQL.

The triggers execute only when `ReplicationApplyMode()` reports `local`.
Remote apply, bootstrap, repair, and materialized-state rebuild code pins one
connection, sets its mode to `remote`, performs one transaction, and restores
the mode before returning the connection to the pool. A missing or invalid
context function aborts the write; it never silently bypasses capture.

The writer coordinator remains required for replication maintenance,
counter/HLC allocation, and remote application. Trigger interception is the
safety boundary that prevents an ordinary direct application write from
escaping capture.

9.7 Schema and type round-trip self-test

Before networking is enabled, `SelfTestReplicatedTable` validates every
replicated table and adapter using a rolled-back transaction or a dedicated
test database. It must encode and decode representative values, round-trip a
composite primary key, distinguish omitted fields from explicit NULL, verify
BLOB and large-integer fidelity, build every prepared statement, and confirm
that the resulting canonical bytes and value types match the descriptor.

Startup fails closed if a required table fails. The test result may be exposed
as health status, but it must not create a durable replication event in the
production event log.

10. Conflict Resolution

10.1 Version comparison

For each incoming field, compare the incoming version with the current winning field version.

Comparison order:

Higher HLC physical component wins.

If equal, higher HLC logical component wins.

If equal, lexicographically greater canonical origin node ID wins.

This creates a total deterministic order.

10.2 Independent field merge

Each field in an incoming update is evaluated separately.

Possible results for one incoming event include:

All fields accepted.

All fields ignored.

Some fields accepted and others ignored.

Update rejected due to a newer row tombstone.

Event quarantined due to validation or clock policy.

10.3 Insert handling

An insert is treated as a set of initial field assignments.

If the row does not exist and no newer tombstone blocks it, the row is created and accepted fields are applied.

If the row already exists, the incoming insert is merged by field using normal version comparison. It must not blindly replace the existing row.

10.4 Update handling

For each incoming field:

Read the current field version.

Read the current row tombstone, if any.

Reject the field if the tombstone version is equal or newer.

Compare the incoming field version with the current field version.

Apply the value only if the incoming version wins.

Store the incoming version as the new field version.

10.5 Delete handling

A delete creates or updates a row tombstone.

The incoming delete version is compared with:

The current tombstone version.

Relevant current field versions.

If the delete wins, the visible row is removed or marked deleted, and the tombstone becomes authoritative.

The implementation may physically remove application data while retaining the tombstone in replication metadata, or it may retain a soft-deleted application row.

10.6 Re-creation after deletion

A previously deleted identity may be re-created only by an event whose version is greater than the tombstone version.

The re-creation must be explicit. An old delayed update must never resurrect a deleted row.

When a valid re-creation wins:

The tombstone is cleared or superseded.

Accepted field versions are installed.

The row becomes visible again.

Applications that do not permit identity reuse should prohibit re-creation entirely and require a new UUID.

An ordinary `update` is never an explicit recreation. Protocol version 1 adds
an `is_explicit_recreation` flag, which is false for trigger-captured UPDATE
events and true only when the application explicitly inserts a previously
deleted permitted identity through the recreation API. A newer ordinary update
against a tombstone remains ignored regardless of its HLC.

10.7 Exact ties

An exact HLC tie across different nodes is resolved using the canonical node ID.

An exact tie including the same node ID should indicate one of:

Duplicate delivery of the same event.

Corrupt or conflicting event data.

Reuse of a node identity.

Reuse of an origin counter.

If the same event ID is received with a different payload hash, it is a severe
integrity error. The original log row remains unchanged and bounded evidence of
the conflicting event is stored in `replication_rejected_events`.

10.8 Set-based batch merge

Validated events may be decoded into a connection-local TEMP staging table and
merged in bounded batches. One staging row represents one present field and
contains the table identity, canonical row key, typed value, event identity,
HLC components, origin UUID, and origin counter. Explicit NULL remains a
present typed value.

For each `(table, row key, field)` partition, a SQL window expression or an
equivalent deterministic aggregate selects the greatest version tuple:

`(hlc_physical_utc_us, hlc_logical, origin_node_uuid)`.

The generated table plan then compares the batch winner with
`replication_field_versions` and writes only strictly newer winners. Row-state
candidates are selected and compared independently. This imports the useful
set-based merge technique without treating a typed per-table patch table as
the authoritative log.

Staging, immutable-event insertion, application-row materialization,
field-version updates, row-version updates, cursor/gap changes, and apply-state
changes must commit atomically. Batching may be debounced briefly to combine
arrivals, but an event must not be acknowledged before its batch commits. A
restart worker reapplies any durable `pending` events, so a crash cannot leave
the application tables permanently behind the event log.

10.9 Supported relational-schema profile

Per-field LWW is guaranteed only for schemas closed under field-wise merge.
Protocol version 1 therefore rejects replication enablement when a table has:

A non-primary-key UNIQUE constraint or unique index.

A CHECK constraint involving more than one replicated column.

A foreign key between independently writable replicated rows.

A generated or hidden column included as a transmitted field.

A trigger not owned by SQLiteSeal that mutates another replicated table.

Generated columns may exist but are excluded from transmitted fields and are
recomputed locally. Primary keys must be globally unique and immutable. A
deployment needing cross-row uniqueness, replicated foreign keys, multi-column
invariants, or cross-table trigger effects must model the invariant in one
replicated row or wait for a separately versioned deterministic merge policy.
`BuildReplicationSchemaDescriptor` validates this profile using
`PRAGMA table_xinfo`, `foreign_key_list`, `index_list`, `index_xinfo`, and the
normalized table and trigger SQL before networking can be enabled.

11. Synchronization Protocol

11.1 Connection model

Synchronization uses one persistent, authenticated, bidirectional TCP
connection between every pair of active nodes. gRPC and Protocol Buffers are
not used. Messages are UTF-8 canonical JSON objects, compressed as independent
gzip members and carried in length-prefixed frames.

Each peer relationship is configured locally with one connection role:

Dial.

The local node initiates the TCP connection. If the attempt fails or an
established session breaks, it retries indefinitely using exponential backoff
with jitter and a configured maximum delay.

Accept.

The local node never initiates a connection to this peer. It keeps its listener
available and waits for that peer to connect. If the connection breaks, this
side does not probe or dial the peer.

A node behind a firewall may set listen_enabled to false. It must be the dial
side for every peer, and every target must listen. On each remote node, the
connection entry for that non-listening node is accept, so those nodes wait for
it to come back online and reconnect. Two non-listening nodes cannot maintain a
direct connection and are an invalid full-mesh configuration.

When both nodes listen, configuration normally assigns one side to dial and the
other to accept. If simultaneous connections occur during configuration
changes, both endpoints deterministically retain one session using the ordered
pair of dialer node ID and session ID and close the duplicate.

The TCP connection is bidirectional regardless of who opened it. Either node
may send changes, acknowledgements, cursor vectors, gap requests, snapshots,
flow-control messages, and heartbeats.

TCP framing is:

A four-byte unsigned big-endian compressed length.

Exactly that many bytes containing one gzip member.

One canonical UTF-8 JSON object after decompression.

Receivers must enforce compressed and decompressed limits, reject invalid gzip,
invalid UTF-8, duplicate JSON keys, non-canonical envelopes, and zero-length
frames. Compression is per message rather than across the TCP stream.

Operating-system TCP keepalive and application heartbeats are both required.
A heartbeat timeout closes the failed session, after which the configured dial
side reconnects.

11.2 Session phases

A synchronization session contains the following phases:

Establish TLS.

Authenticate the peer.

Authorize the peer.

Exchange node identity.

Verify replication domain.

Negotiate protocol capabilities.

Compare schema version and schema hash.

Exchange clock observations and HLC state.

Exchange cursor vectors.

Calculate missing events and missing ranges.

Stream events.

Validate and apply received events.

Send durable acknowledgments.

Repair gaps.

Exchange final cursor state.

Retain the authenticated TCP session for continuous bidirectional synchronization. If it breaks, only the configured dial side starts the reconnect loop.

11.3 Capability exchange

Peers should advertise:

Protocol version.

Minimum supported protocol version.

Software version.

Replication schema version.

Schema hash.

Wire encoding and compression, which must be canonical JSON and gzip for this protocol.

Maximum message size.

Maximum event operations.

Supported authentication mode.

Snapshot support.

Gap-repair support.

Tombstone policy version.

HLC time unit.

Canonicalization version.

A session must stop safely when incompatible capabilities could produce incorrect data.

11.4 Schema verification

Before exchanging mutable data, peers compare:

Replication schema version.

Schema hash.

Canonicalization version.

Replicated table and field definitions.

Type mappings.

Merge-policy version.

A mismatch may be handled by:

Rejecting synchronization.

Allowing a documented backward-compatible mode.

Translating through an explicitly versioned migration layer.

Allowing only snapshot or upgrade operations.

Silent best-effort field mapping is not acceptable.

11.5 Cursor-vector exchange

Each peer sends a map containing, for every known origin:

Highest contiguous counter durably stored.

Highest observed counter.

Known missing ranges, when supported.

Earliest retained counter.

Snapshot baseline identifier, when applicable.

This allows each side to determine which events the other side lacks.

11.6 Event selection

A sender should transmit:

Events above the receiver's contiguous cursor.

Events explicitly requested as missing gaps.

Events within retained history that are not acknowledged by the receiver.

Events should be streamed in origin-counter order within each origin.

Events from different origins may be interleaved.

11.7 Direct origin exchange

Full-mesh nodes exchange an event directly with the node that originated it.
The authenticated peer node ID must equal the event origin node ID. A receiver
rejects an event that claims another origin.

Direct-origin exchange removes the need to trust an intermediary to preserve
or authenticate another node's immutable event envelope. If forwarding is ever
added as a separate future mode, origin signatures and forwarding authorization
become mandatory and require a new protocol capability version.

11.8 Durable acknowledgment

A receiver acknowledges an event only after:

The event has been fully received.

Authentication and authorization checks have passed.

The event has passed schema and integrity validation.

The event has been durably stored.

The event has been applied or deterministically marked ignored.

The database transaction has committed.

An acknowledgment must not be sent merely because bytes were received.

11.9 Contiguous cursor advancement

After committing an event, the receiver recalculates the highest contiguous counter for that origin.

The cursor advances only through uninterrupted counters.

Out-of-order events may be stored and applied, but the contiguous cursor cannot skip a missing counter.

11.10 Gap repair

When a gap is detected, the receiver sends a missing-range request.

The sender responds with:

Requested events.

A statement that the events are unavailable due to compaction.

A snapshot offer.

An integrity error if the requested range should exist but cannot be located.

A gap must not remain permanently hidden behind a higher maximum counter.

11.11 Backpressure

The receiver controls how much unacknowledged data the sender may transmit.

Limits should include:

Maximum events in flight.

Maximum bytes in flight.

Maximum event size.

Maximum operations per event.

Maximum processing time before heartbeat or status response.

The sender must stop or slow transmission when the receiver reaches its advertised limits.

11.12 Gap audit and bounded repair

Durable gap rows are updated incrementally as events arrive. In addition, the
node periodically audits them against `replication_changes` using a SQL
`LEAD(origin_counter)` window partitioned by `origin_node_uuid`. The first row
after each discontinuity defines a missing range. Snapshot baseline counters
act as the sequence predecessor when compacted history is no longer present.

One repair request contains no more than the negotiated maximum gap ranges.
One response contains no more than the negotiated event and byte limits and
returns a continuation cursor when more data remains. If any requested counter
is older than retained history, the response explicitly reports
`snapshot_required`; returning an empty success is forbidden. Repair requests
prefer the authenticated event origin in this direct full mesh.

11.13 Read-your-write consistency token

A successful local write may return a signed or integrity-protected session
token containing the replication domain, origin node UUID, origin counter,
schema guard, and expiration time. A request routed to another node may wait
until its local contiguous cursor for that origin is at least the token's
counter and all corresponding events are committed and materialized.

Waiting uses bounded exponential backoff and ends with a distinct consistency
timeout rather than returning silently stale data. Tokens grant no database
authorization and must not expose credentials. Applications that always route
a user to the writing node may omit this feature.

12. TCP/JSON Protocol Responsibilities

Every application message uses a common canonical JSON envelope containing a
protocol version, message UUID, message type, sender node UUID, sender
incarnation UUID, replication domain, UTC send time, body, and payload hash.
Authentication or origin signatures are included where required. Each envelope
is gzip-compressed and written as one TCP frame.

12.1 Session establishment messages

Purpose:

Establish peer identity.

Negotiate protocol versions and frame limits.

Verify replication domain.

Negotiate authentication.

Exchange session nonces.

Bind authentication to the TLS session.

Return an authorized session identifier.

12.2 Synchronization messages

Purpose:

Exchange cursor vectors.

Send event batches.

Send durable acknowledgments.

Report gaps and request missing ranges.

Exchange heartbeats.

Report flow-control limits.

Notify the peer of schema, clock-health, or membership problems.

12.3 Snapshot messages

Purpose:

Advertise available snapshots and baseline cursors.

Transfer snapshot chunks in bounded JSON/gzip frames.

Acknowledge chunks so interrupted transfer can resume.

Validate chunk hashes and complete snapshot integrity before activation.

12.4 Health and status messages

Purpose:

Report connection and replication health.

Report local node ID, incarnation, and replication domain.

Report software and protocol version.

Report schema compatibility, time synchronization, and replication lag without
exposing sensitive data.

12.5 Administrative peer test

Purpose:

Validate configured dial/listen direction.

Validate TCP and TLS connectivity.

Validate authentication and authorization.

Validate schema compatibility and clock health.

Perform no data mutation.

12.6 Transport adapter boundary

The replication core depends on a narrow authenticated-session adapter rather
than raw socket calls. The adapter exposes send-frame, receive-message,
backpressure, peer-identity, close, and session-state operations. It does not
choose conflict winners or mutate replication tables.

The production adapter is the persistent length-prefixed JSON/gzip/TLS TCP
transport defined here. A test adapter may reorder, duplicate, delay, drop, or
corrupt frames to exercise recovery. Supporting another transport in the
future must not change canonical event bytes, acknowledgment semantics,
identity binding, cursor meaning, or merge ordering.

13. Transport Security

Credential ownership boundary

The user or deployment operator supplies the PSK, certificate chain, private
key, trusted roots, expected peer identity, and any snapshot-signing key through
configuration, file paths, callbacks, or an external secret provider.
SQLiteSeal loads and uses those supplied credentials and reports validation or
loading errors. It does not generate, issue, enroll, distribute, rotate, renew,
or revoke credentials, and it does not operate a certificate authority or
secret-management service. Replacing or revoking a credential is an operator
action; SQLiteSeal observes the new configuration on explicit reload or
restart.

13.1 Mandatory TLS

All production replication TCP connections must be encrypted using TLS.

Plaintext TCP is permitted only in explicitly approved isolated development
environments. gzip compression provides no confidentiality.

The TLS configuration should enforce:

Approved TLS protocol versions.

Approved cipher suites as required by organizational policy.

Server identity validation.

Certificate-expiry validation.

Hostname or explicitly pinned identity validation.

Secure private-key storage.

Disabled anonymous and obsolete cryptographic modes.

13.2 Security mode A: TLS plus pre-shared-key peer authentication

In PSK mode, TLS protects the TCP transport and authenticates the listening endpoint. The pre-shared key authenticates the replication peer at the JSON protocol layer inside the encrypted TLS session.

This avoids sending the PSK itself over the network.

A PSK authentication exchange should include:

Claimed node ID.

PSK key identifier.

Client-generated cryptographic nonce.

Server-generated cryptographic nonce.

Session identifier.

Protocol version.

Replication domain.

TLS channel binding value when available.

HMAC over the canonical authentication transcript.

Expiration time or narrow validity window.

Replay-cache verification.

Both sides should prove knowledge of the PSK when mutual node authentication is required.

The authentication proof must be bound to the specific TLS session so a proof captured from one connection cannot be replayed on another connection.

The user-provided PSK must:

Be high entropy.

Be unique per peer relationship or per node where practical.

Never be logged.

Never be placed directly in a JSON message or frame header.

Be stored using operating-system or hardware-protected secret storage.

Have a key identifier.

Be replaceable through an operator configuration change.

The system should use normal certificate-based TLS for encryption and listener authentication, with the PSK challenge-response mechanism described above for peer authentication. It must not implement a custom encryption protocol.

13.3 Operator-managed credential replacement

PSK and certificate lifecycle management is outside SQLiteSeal. When an
operator replaces a supplied PSK or certificate reference, SQLiteSeal closes
sessions using the old configuration, clears associated replay-cache entries,
loads the newly supplied material, and re-authenticates. An optional pair of
`current` and `next` credential references permits an operator-controlled
overlap, but SQLiteSeal never creates or distributes either credential.

Configuration reload success or failure is audited without logging secret
values, private keys, or reusable authentication proofs.

13.4 Security mode B: mutual TLS

In mTLS mode:

The server presents a certificate validated by the client.

The client presents a certificate validated by the server.

The certificate identity is mapped to an authorized node ID.

The node ID inside the replication protocol must match the certificate authorization mapping.

Validation of the user-provided certificate configuration includes:

Trusted issuing authority.

Validity period.

Intended key usage.

Any revocation status or trust policy supplied by the operator's TLS stack.

Subject alternative name or another explicit node-identity binding.

Replication-domain authorization.

Certificate fingerprint audit information.

Possession of any certificate from the trusted authority should not automatically authorize access to every replication domain.

13.5 Authorization

Authentication proves identity. Authorization determines what the peer may do.

Authorization rules should define:

Whether the peer is enabled.

Which replication domain it belongs to.

Whether the authenticated peer may send events for its own origin; events claiming another origin are rejected.

Which tables or entities it may receive, if filtering is supported.

Whether it may request or provide snapshots.

Whether it may initiate synchronization.

Whether it may use PSK, mTLS, or both.

Maximum resource limits.

Administrative restrictions.

13.6 Message integrity

TLS provides transport integrity. The immutable event should also include a payload hash so corruption or inconsistent duplicate event IDs can be detected after storage.

In PSK mode, an optional event-level HMAC may be retained if events must remain
independently verifiable after transport. Its key and historical verification
set are supplied and replaced by the operator; SQLiteSeal does not manage that
key's lifecycle.

13.7 Replay protection

Transport authentication messages require replay protection using:

Unique nonces.

Session identifiers.

Narrow validity periods.

A replay cache.

TLS-session binding.

Monotonic session sequence values.

Replication events themselves are replay-safe because their event IDs are immutable and unique, but authentication proofs are not safe without explicit replay protection.

14. Required Functions

The following functions are logical responsibilities. Their names are illustrative and do not imply a specific programming-language signature.

14.1 Initialization and node state

Function

Responsibility

InitializeReplicationState

Create or validate internal replication metadata.

LoadNodeIdentity

Load the permanent node ID and replication domain.

EnrollNode

Assign identity and security configuration to a new node.

CloneNodeIdentityReset

Safely replace identity when deploying from a clone.

LoadNodeCounter

Read the last committed local origin counter.

AllocateOriginCounter

Allocate the next counter inside the local write transaction.

LoadHLCState

Read the last persisted local HLC.

PersistNodeState

Atomically persist counter, HLC, and related node metadata.

ValidateInternalState

Detect counter rollback, HLC rollback, duplicate identity, or corrupt metadata.

14.2 Schema management

Function

Responsibility

BuildReplicationSchemaDescriptor

Produce the canonical description of replicated entities and fields.

BuildTableMergePlan

Generate quoted, parameterized prepared statements for one replicated table
from its validated descriptor.

GenerateTableCaptureSchema

Generate the quoted typed payload table and INSERT, UPDATE, and DELETE triggers
for one validated replicated table.

ValidateTableCaptureSchema

Compare installed generated tables/triggers with their canonical descriptor and
fail closed on drift.

RegisterTypeAdapter

Register deterministic SQLite-to-wire and wire-to-SQLite conversions for one
declared application type.

SelfTestReplicatedTable

Round-trip keys and representative field values and validate every generated
statement before networking is enabled.

ComputeSchemaHash

Generate the stable schema hash used during negotiation.

ValidateSchemaCompatibility

Decide whether two schema versions can safely exchange events.

TranslateEventSchema

Reject cross-schema event translation in protocol version 1.

ApplyReplicationMigration

Upgrade replication metadata and application schema consistently.

14.3 Time and HLC

Function

Responsibility

ReadUtcTime

Obtain current UTC time from the operating system.

GenerateLocalHLC

Produce the next HLC for a local event.

MergeRemoteHLC

Incorporate a received HLC into local HLC state.

CompareVersions

Compare physical HLC, logical HLC, and node ID.

CheckClockHealth

Evaluate NTP state, offset, last synchronization, and time jumps.

ValidateRemoteTime

Detect remote events beyond configured skew limits.

RecordClockObservation

Store diagnostic timing information from a peer session.

14.4 Local change capture

Function

Responsibility

BeginReplicatedTransaction

Pin a connection, install local trigger context, and start a transaction in
which trigger firings can create row events.

SetReplicationApplyMode

Set and verify fail-closed connection-local `local` or `remote` trigger mode.

AcquireReplicationWriter

Serialize access to the local SQLite writer and obtain the write connection.

RetryBusyTransaction

Retry the complete transaction after a bounded `SQLITE_BUSY` backoff without
duplicating an origin counter or event.

CaptureChangedFields

Determine exactly which fields changed.

CanonicalizePrimaryKey

Produce a stable representation of the row identity.

NormalizeFieldValue

Convert a value into its canonical typed wire representation.

BuildReplicationEvent

Construct the immutable event envelope and operations.

HashEventPayload

Calculate the canonical event payload hash.

ApplyLocalMutation

Apply the requested application-data change.

UpdateLocalFieldVersions

Record the new winning versions for locally changed fields.

CreateLocalTombstone

Record a locally originated delete.

ClearSupersededTombstone

Handle an explicitly permitted row re-creation.

PersistReplicationEvent

Store the immutable event within the same transaction.

CommitReplicatedTransaction

Commit application data and replication metadata atomically.

RollbackReplicatedTransaction

Roll back every component of the failed local change.

14.5 Session and transport

Function

Responsibility

StartReplicationListener

Start the configured TLS-protected TCP listener when listen_enabled is true.

ConnectToPeer

For a dial-role peer, create and authenticate a TLS-protected TCP connection.

OpenReplicationSession

Begin protocol negotiation and session establishment.

AuthenticatePeerPSK

Validate mutual PSK challenge-response proofs.

AuthenticatePeerCertificate

Validate the peer's mTLS identity.

AuthorizePeer

Apply node, domain, and operation authorization policy.

BindSessionToTransport

Bind authentication proofs to the active TLS session.

NegotiateCapabilities

Agree on protocol, schema, limits, and compression.

CloseReplicationSession

End the session and record final status safely.

ScheduleReconnect

For dial-role peers only, retry indefinitely with exponential backoff, jitter, and a configured maximum delay. Accept-role peers wait for inbound reconnection.

14.6 Cursor and gap management

Function

Responsibility

BuildCursorVector

Build the local per-origin contiguous progress map.

ExchangeCursorVectors

Send and receive cursor state with a peer.

CalculateEventsForPeer

Determine which events the peer lacks.

FindMissingRanges

Identify gaps in an origin-counter sequence.

AuditMissingRangesSQL

Use a partitioned SQL `LEAD` query to reconcile durable gap rows with retained
events and snapshot baselines.

RecordObservedCounter

Record an out-of-order received counter.

AdvanceContiguousCursor

Move the cursor only through uninterrupted counters.

RequestGapRepair

Ask the peer for specific missing ranges.

AnswerGapRequest

Return retained events or indicate snapshot requirement.

ContinueGapResponse

Resume a bounded missing-range response from its authenticated continuation
cursor.

PersistPeerAcknowledgment

Record durable peer progress for compaction decisions.

14.7 Event transmission

Function

Responsibility

SendEventsToPeer

Send selected immutable events as bounded JSON/gzip frames with flow control.

BuildEventBatch

Construct a batch within negotiated event-count and uncompressed-byte limits.

ReceivePeerMessages

Read framed JSON/gzip messages containing events, acknowledgments, gaps, snapshots, and heartbeats.

ApplyBackpressure

Limit events and bytes in flight.

SendHeartbeat

Keep the persistent TCP session alive and exchange health information.

SendDurableAcknowledgment

Acknowledge only after durable processing.

ResumeInterruptedSession

Continue from committed cursors after failure.

CreateReadYourWriteToken

Create an integrity-protected `(domain, origin, counter, schema, expiry)`
session token after a local commit.

WaitForReadYourWrite

Wait with bounded backoff until the local durable and materialized cursor
satisfies a session token.

14.8 Event validation and deduplication

Function

Responsibility

ValidateEventEnvelope

Validate required metadata and ranges.

ValidateEventSchema

Ensure the event matches an accepted schema.

ValidateEventTypes

Validate field names and typed values.

ValidateEventHash

Verify canonical payload integrity.

ValidateEventAuthorization

Ensure the authenticated peer is authorized and equals the claimed event origin.

CheckDuplicateEvent

Determine whether the event ID already exists.

CompareDuplicatePayload

Detect the same event ID with different content.

QuarantineEvent

Persist a uniquely identified, structurally valid, temporarily time-skewed
event without applying or acknowledging it.

PersistRejectedEventEvidence

Store bounded forensic evidence for malformed or duplicate-identity input that
cannot be inserted in `replication_changes`.

PersistReceivedEvent

Store the original event before acknowledgment.

14.9 Merge and application

Function

Responsibility

ApplyReceivedEvent

Apply a validated event in one local transaction.

StageReceivedBatch

Decode present typed fields into a connection-local TEMP staging table.

SelectBatchWinners

Choose one deterministic winner per row field and row-state partition using
the common total ordering.

ApplyGeneratedMergePlan

Apply set-based winners using the cached schema-derived statements.

EnterRemoteApplyContext

Suppress creation of a new local-origin event.

LoadCurrentFieldVersion

Read the current winner for a field.

LoadRowTombstone

Read the current delete version for a row.

ShouldApplyField

Decide whether the incoming field wins.

ApplyWinningField

Write the incoming value and its version.

IgnoreLosingField

Record deterministic non-application without changing data.

ShouldApplyDelete

Compare incoming deletion with row and field versions.

ApplyWinningDelete

Delete or hide the row and store the tombstone.

ApplyWinningRecreation

Re-create a row only when newer than the tombstone.

FinalizeRemoteApply

Store result, cursor changes, and diagnostics atomically.

ExitRemoteApplyContext

Restore normal local capture behaviour.

ReplayPendingEvents

After startup or a failed batch, atomically materialize durable pending events
before acknowledging them or reporting the node ready.

14.10 Snapshot and bootstrap

Function

Responsibility

CreateConsistentSnapshot

Capture application state, field versions, tombstones, and baseline cursors consistently.

ScheduleSnapshotBackup

Schedule logical snapshots or local SQLite backups with randomized jitter so
all nodes do not perform maintenance simultaneously.

CreateSQLiteSafetyBackup

Use SQLite's online backup mechanism or an equivalent consistent copy as a
local recovery artifact; do not treat it as a replication baseline until its
logical state and cursor manifest are verified.

DescribeSnapshot

Provide compatibility, size, hash, and cursor metadata.

StreamSnapshot

Transfer a snapshot in verified chunks.

ValidateSnapshot

Verify schema, identity, baseline, and complete hash.

InstallSnapshot

Atomically activate the received snapshot.

ResumeAfterSnapshot

Request events above the snapshot baseline.

BootstrapNewNode

Initialize a node using snapshot plus event catch-up.

14.11 Retention and compaction

Function

Responsibility

CalculateSafePrunePoint

Determine which events are acknowledged or represented in an accepted snapshot.

CompactEventLog

Remove safely obsolete event payloads.

RetainRequiredTombstones

Prevent deletion metadata from disappearing too early.

PruneFieldHistory

Remove superseded history while retaining current winners.

ExpireInactivePeerState

Apply explicit policy for permanently removed peers.

VerifyCompactionSafety

Ensure no active peer requires the data being removed.

14.12 Credential consumption and authentication

Function

Responsibility

LoadTLSConfiguration

Load user-provided trusted roots, certificate chain, and private-key reference.

LoadPSK

Load a user-provided protected pre-shared key by external reference.

CreatePSKChallenge

Generate a cryptographically random challenge.

CreatePSKProof

Produce an HMAC over the canonical session transcript.

VerifyPSKProof

Validate proof, freshness, nonce, and channel binding.

CheckReplayCache

Reject previously used authentication proofs.

ValidatePeerCertificate

Validate certificate chain and identity binding.

MapCertificateToNode

Resolve the authorized node ID from certificate policy.

ReloadCredentials

Reload operator-provided references, close sessions bound to replaced
configuration, and re-authenticate. This function does not create, rotate,
distribute, or revoke credential material.

14.13 Integrity and observability

Function

Responsibility

GetReplicationStatus

Report peer state, cursor state, gaps, and lag.

GetClockStatus

Report NTP and HLC health.

VerifyEventLogIntegrity

Check event IDs, counters, hashes, and continuity.

VerifyMaterializedState

Check application values against winning metadata.

ValidateTypeAdapters

Verify explicit NULL, BLOB, integer, decimal, time, UUID, and structured-JSON
round trips for every replicated table.

AuditReplicationAction

Record security and administrative events.

RecordReplicationMetric

Publish throughput, lag, conflict, and error metrics.

ExportDiagnosticBundle

Produce sanitized troubleshooting information.

14.14 Transport abstraction

Function

Responsibility

OpenTransportAdapter

Open an authenticated replication session without exposing conflict logic to
the transport implementation.

SendTransportFrame

Serialize canonical JSON, gzip one independent message, enforce limits, and
write one length-prefixed frame.

ReceiveTransportMessage

Read, bound, decompress, parse, and validate one framed message.

GetAuthenticatedPeerIdentity

Return the transport-bound node and incarnation identity used for message
authorization.

AdvertiseFlowControl

Publish current event-count and byte capacity to the peer.

15. Idempotency and Failure Recovery

15.1 Duplicate event delivery

If an event ID already exists with the same payload hash:

Treat it as a duplicate.

Do not reapply the mutation.

Do not create a new local event.

Re-send the appropriate durable acknowledgment.

Recalculate cursor advancement if necessary.

15.2 Conflicting duplicate identity

If an existing event ID is received with a different payload hash:

Do not apply it.

Persist a bounded forensic record in `replication_rejected_events`; the
conflicting event cannot be inserted into `replication_changes` because its
UUID or origin counter is already unique there.

Mark the peer or origin as suspect.

Stop cursor advancement for that origin.

Generate a high-severity integrity alert.

Require administrative investigation.

A structurally valid, uniquely identified event quarantined for temporary
clock or policy review remains in `replication_changes` with state
`quarantined`. A duplicate-identity conflict is instead stored only in the
separate rejected-event table. Neither condition advances the origin cursor.

15.3 Failure before transaction commit

If a connection fails before the receiver commits:

No acknowledgment is sent.

The sender retries the event.

The receiver processes it normally on retry.

15.4 Failure after commit but before acknowledgment

If the receiver commits but the acknowledgment is lost:

The sender retransmits the event.

The receiver detects the duplicate.

The receiver returns an acknowledgment without reapplying it.

15.5 Service restart

After restart, the node must recover:

Permanent node identity.

Last committed origin counter.

Last committed HLC.

Event log.

Field versions.

Tombstones.

Cursor and gap state.

Peer acknowledgments.

Quarantined events.

In-memory progress must never be treated as durable progress.

15.6 Database restoration

Restoring an old database backup can roll back counters and replication state.

The database cannot detect its own rollback using fields stored only inside
that database. Each node therefore has an authenticated replication identity
guard outside the SQLite database and outside database backups. It stores the
node UUID, incarnation UUID, database generation, and last committed origin
counter high-water mark. The guard may be supplied by an OS-protected file or
operator state provider; it contains no PSK or certificate private key.

After each successful local database commit, SQLiteSeal advances the external
counter high-water mark using an atomic replace or provider compare-and-set. A
database counter ahead of the guard is safe after a crash and advances the
guard during recovery. A guard ahead of the database proves rollback or an
uncertain commit and keeps networking disabled. This ordering may cause a safe
false-positive fence, but never permits counter reuse.

A restoration procedure must therefore:

Compare the restored generation and counter with the external identity guard.

Prevent the node from immediately reconnecting.

Decide whether the node will retain or replace its identity.

Reconcile events created after the backup.

Avoid reusing an origin counter with different event content.

Prefer assigning a new node identity when safe continuity cannot be proven.

15.7 Startup materialization recovery

Before opening network sessions or reporting readiness, the node scans for
events in `pending` state and verifies that application rows agree with
`replication_field_versions` and `replication_row_versions`. It replays pending
events through the same generated merge plans used for live traffic.

No design may depend on an in-memory debounce queue for correctness. If an
implementation stores an event before its application transaction, the
durable state must explicitly remain `pending`, cursor progress must not pass
it, and no acknowledgment may be emitted. The preferred implementation stores
and applies each received batch in one transaction, leaving startup replay as
defence-in-depth and migration recovery.

16. Tombstone Retention

Tombstones cannot be deleted merely because the application row is gone.

A tombstone may be pruned only when the system can prove that no supported peer can later send an older event that would resurrect the row.

Possible safe conditions include:

Every active peer has acknowledged a cursor beyond the delete event for every relevant origin.

A common snapshot containing the tombstone or its effect has been accepted as the new baseline.

Removed peers have been administratively retired and must re-bootstrap before rejoining.

The configured maximum offline period has expired and the policy requires stale nodes to re-bootstrap.

A node returning after the supported offline period must not synchronize from arbitrarily old logs. It should install a current snapshot.

17. Event Log Compaction

The immutable log may grow indefinitely without compaction.

Compaction must preserve:

Current application state.

Current field-version winners.

Required tombstones.

Cursor continuity or snapshot baseline.

Events still required by any active peer.

Audit data required by policy.

A recommended strategy is:

Create a consistent snapshot.

Record its baseline cursor vector.

Confirm the snapshot hash and completeness.

Ensure active peers either acknowledged old events or can use the snapshot.

Retain a safety window.

Remove event payloads below the safe prune point.

Retain minimal event identity or audit metadata if required.

Require peers older than the retained baseline to re-bootstrap.

17.1 Required typed per-table capture tables

Every replicated application table has one generated durable typed
`<application_table>__replication_changes` table. It is populated by the
generated INSERT, UPDATE, and DELETE triggers and stores the authoritative
typed row payload associated one-to-one with `replication_changes`.

Typed capture tables must:

Be generated from the same validated schema descriptor as the merge plan.

Store explicit field-presence flags so SQL NULL remains a replicable value.

Have a unique reference to the authoritative change UUID and origin counter.

Be written in the same transaction as the authoritative event and apply state.

Be included in schema validation, snapshots, compaction, and recovery.

Be present with an identical descriptor on every peer before synchronization.

Compaction may delete a typed payload only after the global event header is
marked compacted and the accepted snapshot proves the payload is no longer
needed. The table itself is required and is never treated as a disposable
cache.

17.2 Scheduled snapshots and safety backups

Snapshot and backup creation should run periodically with configurable random
jitter so every node does not begin I/O-heavy maintenance at the same instant.
Responsibility may be assigned by an external scheduler or deterministic
administrative policy, but connected-peer leader election must never control
write availability, conflict ordering, membership safety, or compaction proof.

A raw SQLite online backup is useful for local disaster recovery, but it is not
automatically a portable replication snapshot. It becomes an accepted
replication baseline only after the application rows, field versions,
tombstones, schema guard, and cursor vector are captured consistently and the
signed manifest and hashes are verified. Backup completion, duration, size,
failure count, and last successful completion time are exposed as metrics.

18. New-Node Bootstrap

A new node should not replay an unbounded event history when a recent snapshot is available.

Bootstrap sequence:

Enroll the new node with a unique node ID.

Configure PSK or mTLS credentials.

Establish and authenticate the persistent TCP/JSON session.

Verify replication domain and schema compatibility.

Select a compatible snapshot.

Download the snapshot as verified JSON/gzip frames over the TLS connection.

Verify all chunk hashes and the complete snapshot hash.

Install application data, field versions, tombstones, and baseline cursors atomically.

Generate no local-origin events during installation.

Request all events above the snapshot baseline.

Apply catch-up events.

Enter normal synchronization.

A snapshot copied manually must still be authenticated and verified before activation.

19. Full-Mesh Persistent Connections

Every active node maintains one direct TCP connection with every other active
node. The connection count is N times (N minus 1) divided by 2.

For each pair, one endpoint is configured as dial and the other as accept. A
non-listening node is always the dial endpoint. When a connection breaks, only
the dial endpoint attempts reconnection; the accept endpoint waits for the
peer to return and connect.

Before activating a membership change, configuration validation must prove:

Every active node has a peer-connection entry for every other active node.

Every pair has at least one listening endpoint.

Exactly one side normally has the dial role and the other has accept.

A dial endpoint has a usable address and port for the listening peer.

Authentication credentials and replication-domain membership agree.

Protocol version 1 does not run a membership consensus algorithm. The operator
supplies one authenticated membership manifest with a monotonically increasing
epoch to every active node. SQLiteSeal validates and stores the manifest but
does not create or distribute it. Compaction and peer retirement remain
disabled until every active node has advertised the same manifest hash and
epoch. Conflicting manifests fail closed and require operator correction.

Hub-and-spoke, relayed forwarding, and partial-mesh operation are not part of
this design. A deployment in which two nodes are both unable to listen cannot
satisfy the required full mesh without adding an explicitly designed relay
protocol.

20. Conflict Visibility

Last-Write-Wins creates deterministic convergence, but deterministic does not always mean semantically correct.

The system should record conflict information when:

An incoming field loses to a local or previously received value.

A deletion overrides an update.

An update is blocked by a tombstone.

Different nodes update the same field within a configurable time window.

A clock-skew policy influences the decision.

Conflict records may include:

Table and primary key.

Field name.

Winning event ID.

Losing event ID.

Both UTC change times.

Both HLC values.

Both node IDs.

Value hashes.

Resolution rule applied.

Sensitive field values should not be copied into general diagnostic logs unless authorized.

Applications may mark conflicts for manual review. Protocol version 1 does not
support custom merge policies; a later protocol may add only versioned,
deterministic policies negotiated identically by every node.

21. Security and Operational Logging

Audit the following events:

Node enrollment.

Node identity changes.

Peer enablement and disablement.

Authentication success and failure.

Operator-provided credential configuration reload.

Certificate validation failure.

Authorization denial.

Schema mismatch.

Clock-skew violation.

Duplicate event with conflicting hash.

Snapshot creation and installation.

Event-log compaction.

Peer retirement.

Database restoration recovery.

Administrative conflict override.

Never log:

PSK secret values.

Private keys.

Raw authentication proofs that could enable replay.

Unredacted sensitive application data unless explicitly approved.

22. Recommended Metrics

Each node should expose or record:

Connectivity

Peer connection status.

Last successful session.

Reconnect count.

Authentication failures.

TLS failures.

Session duration.

Replication progress

Highest contiguous counter by origin.

Highest observed counter by origin.

Number and size of missing ranges.

Events waiting to send.

Events waiting to apply.

Oldest unsent event age.

Oldest unapplied event age.

Event transmission rate.

Event application rate.

Event batches sent and received.

Events and uncompressed bytes per batch.

Batch validation, staging, commit, and acknowledgment latency.

Retransmission requests and events, by sent and received direction.

Pending events recovered during startup.

Read-your-write wait duration and timeout count.

Conflict and data quality

Fields accepted.

Fields ignored as older.

Deletes accepted.

Updates blocked by tombstones.

Conflicting duplicate event IDs.

Quarantined events.

Schema validation failures.

Time

NTP synchronized state.

Estimated clock offset.

Time since last synchronization.

Maximum observed peer skew.

Remote events rejected or quarantined for future skew.

Current HLC logical counter growth.

Storage

Event-log size.

Field-version record count.

Tombstone count.

Snapshot size.

Last compaction time.

Earliest retained event by origin.

Last successful snapshot and safety-backup timestamps.

Snapshot and backup duration, bytes, and failure count.

SQLite and validation

Writer queue depth and wait time.

`SQLITE_BUSY` count, retries, and exhausted retries.

Replication-table self-test status and last success time.

Type-adapter validation failures by table and declared type.

Generated merge-plan build failures.

Metrics should be exposed in OpenMetrics-compatible form with stable metric
names and bounded labels. Table names may be labels only when the replicated
table set is bounded; row keys, event UUIDs, session UUIDs, error strings, and
other high-cardinality or sensitive values must not be metric labels.

23. Configuration Parameters

Recommended configurable parameters include:

Parameter

Purpose

Node ID

Permanent local identity.

Replication domain

Environment isolation.

Peer endpoints

Authorized remote nodes.

Authentication mode

PSK or mTLS.

PSK key identifiers

Reference current and optional next operator-provided secrets.

Trusted certificate authorities

Certificate validation.

Expected certificate identities

Node authorization.

Maximum future clock skew

Protects against bad clocks.

Maximum past clock skew

Diagnostic or acceptance policy.

Maximum offline period

Determines when snapshot re-bootstrap is required.

Event retention period

Minimum log history.

Tombstone retention policy

Prevents resurrection.

Maximum event size

Resource protection.

Maximum operations per event

Resource protection.

Maximum in-flight events

Backpressure.

Maximum in-flight bytes

Backpressure.

Retry minimum and maximum

Connection recovery.

Snapshot threshold

Decides when replay is less efficient than bootstrap.

Snapshot and safety-backup schedules

Define periodic local recovery and replication-baseline creation.

Maintenance jitter interval

Avoids synchronized backup, snapshot, compaction, and gap-audit load.

Compression policy

Bandwidth optimization.

Maximum events per batch

Bounds validation and merge work per transaction.

Maximum uncompressed batch bytes

Bounds memory, decompression, and transaction size.

Maximum in-flight events and bytes

Provides receiver-driven flow control.

Maximum gap ranges per request

Bounds repair-message complexity.

Maximum events per gap response

Makes repair resumable instead of unbounded.

SQLite journal mode and synchronous policy

Defines durability and reader/writer concurrency behaviour.

SQLite busy timeout and transaction retry limit

Controls bounded recovery from local writer contention.

Merge batch debounce interval

Allows small arrival batches without making correctness depend on memory.

Read-your-write token lifetime and wait timeout

Controls optional session-consistency behaviour.

Type-adapter registry

Defines canonical conversions for application-specific SQLite types.

Quarantine policy

Handling invalid or suspicious events.

Configuration changes affecting convergence or security should be versioned and audited.

24. Correctness Invariants

An implementation should continuously preserve the following invariants:

A local origin counter never decreases.

A local origin counter is never reused for different event content.

An event ID uniquely identifies one immutable payload.

A local application mutation and its event commit atomically.

Every replicated table has its validated typed payload table and three capture
triggers before application writes or networking are enabled.

A remote event never creates a new locally originated copy.

Field-version comparison is identical on every node.

Cursor advancement never skips a gap.

Acknowledgment occurs only after durable processing.

A row cannot be resurrected by an event older than its tombstone.

The authenticated sending peer matches the event origin identity.

HLC state never moves backward.

UTC change time is preserved unchanged during direct transfer.

The same complete event set produces the same materialized database state.

Authentication identity matches the authorized node identity.

Replication domains cannot exchange data accidentally.

Compaction never removes data required by an active supported peer.

A snapshot and its baseline cursor describe one consistent database state.

Every SQLite write affecting replicated state passes through the coordinated
writer and one explicit transaction boundary.

An explicit SQL NULL is a present replicated value; omission alone means no
change.

Every generated merge plan is derived from the locally accepted schema
descriptor and uses only quoted identifiers and bound values.

A node cannot report ready or acknowledge new traffic while durable pending
events remain unreconciled.

An external identity guard ahead of the database always fences networking; a
database counter ahead of the guard advances the guard before networking.

Batching and debouncing affect throughput only; they never change conflict
ordering, atomicity, cursor meaning, or acknowledgment timing.

A read-your-write token is satisfied only by durable, materialized contiguous
progress for its stated origin.

25. Recommended End-to-End Algorithm

Initialization

Open SQLite and configure foreign keys, WAL where applicable, synchronous
policy, and bounded busy handling.

Acquire the coordinated writer and validate replication metadata, node
identity, counter, HLC, restore generation, cursors, and gaps.

Build the canonical replicated-schema descriptor and schema hash.

Register type adapters and generate the prepared merge plan for every
replicated table.

Generate or validate the typed payload table and three capture triggers for
every replicated table and register fail-closed context functions on every
connection.

Run every schema/type round-trip self-test.

Replay or reconcile durable pending events and verify materialized winners.

Only then enable the listener, dial peers, or report the node ready.

Local write

Pin a connection, set local trigger mode, begin a database transaction, and
validate the requested application statement.

Execute the statement. For each affected row, its generated trigger allocates
the next origin counter and HLC, derives changed-field presence, builds and
hashes one immutable row event, stores its common header and typed per-table
payload, and updates field versions or tombstone metadata.

Commit all application changes and trigger-created events together, restore the
connection context, then advance the external identity-guard high-water mark.

Notify the synchronization worker that new data is available.

Return an optional integrity-protected read-your-write token containing the
committed origin and counter.

Session opening

Establish TLS.

Authenticate using PSK challenge-response or mTLS.

Map the authenticated identity to a node ID.

Authorize the peer and replication domain.

Negotiate protocol and resource limits.

Verify schema compatibility.

Exchange time and HLC observations.

Exchange cursor vectors.

Sending

Determine missing events by origin.

Prioritize explicit gaps.

Stream immutable events in origin order.

Respect receiver backpressure.

Retain unacknowledged events for retry.

Persist acknowledgments received from the peer.

Receiving

Receive the complete event.

Validate peer authorization.

Validate event envelope, schema, types, time policy, and hash.

Detect duplicates.

Accumulate only up to the negotiated event and byte limits.

Decode present typed fields into the connection-local staging table.

Select deterministic per-field and row-state batch winners.

Persist and apply the batch using generated merge plans in one transaction.

Merge the remote HLC into local state.

Evaluate every field independently.

Apply winning fields and tombstones.

Mark losing changes as deterministically ignored.

Update gap and contiguous cursor state.

Commit.

Send durable acknowledgment.

Recovery

Reconnect using bounded backoff.

Repeat authentication and negotiation.

Exchange current cursor vectors.

Resend every event not durably acknowledged.

Repair gaps.

Use a snapshot when requested history is no longer retained.

Periodically reconcile durable gap rows with the SQL `LEAD` audit and continue
bounded gap responses until each range is filled or snapshot bootstrap is
explicitly required.

26. Finalized Protocol-Version-1 Decisions

Protocol version 1 fixes the following interoperability decisions:

Node and event identities are canonical lower-case UUID strings; UUIDv7 is
preferred for new application primary keys and UUIDv4 is accepted.

HLC physical time is signed 64-bit Unix microseconds and the logical component
is a non-negative signed 64-bit integer. Overflow fails closed.

Version tuples compare physical time, logical value, then the canonical
16-byte origin UUID. RFC 8785 plus NFC and typed envelopes defines event
canonicalization; SHA-256 defines payload hashing.

An event contains exactly one row operation. `transaction_uuid` is diagnostic
correlation only; remote multi-row atomic visibility is not supported.

BLOBs are inline only up to the configured expanded-value limit. Protocol
version 1 has no external large-object transfer mechanism.

Only direct-origin exchange is supported. Full mesh is required.

PSKs are user-provided per peer relationship. TLS and mTLS certificates,
private keys, trusted roots, expected SAN-to-node mappings, trust/revocation
policy, and optional snapshot-signing credentials are user-provided.
SQLiteSeal consumes but never creates, distributes, rotates, or revokes them.

Snapshots are canonical logical JSON streams transferred in independently
bounded gzip frames. Their manifest records expanded size, chunk hashes,
complete SHA-256, schema guard, membership manifest hash, and cursor baseline.
Activation occurs through the coordinated writer with networking disabled; a
failed activation rolls back or leaves the previous database generation
active.

Maximum offline duration, event/tombstone retention, conflict-audit retention,
and read-your-write timeouts are required domain-wide operator settings and
are included in the negotiated policy hash. Nodes with different values do not
compact or synchronize.

Membership and retirement use the operator-provided authenticated membership
manifest. Restore safety uses the external identity guard and otherwise forces
a new node identity plus snapshot bootstrap.

Schema upgrades are stop-the-world in protocol version 1: disable networking,
upgrade every node, rebuild descriptors/tables/triggers, verify one schema
hash, then resume. Rolling schema translation and custom merge policies are
not supported.

Set-based merge uses built-in SQLite window functions. Required typed
per-table capture tables are authoritative payload stores, not optional
caches. Type adapters and their startup test vectors are part of the canonical
schema descriptor.

Optional read-your-write tokens use HMAC-SHA-256 with a separate user-provided
application token key. When no token key is supplied, the feature is disabled.

27. Final Recommended Design

The recommended design consists of:

A permanent UUID for every node.

UUID primary keys for replicated rows.

A strictly increasing origin counter per node.

UTC change time saved for every local event.

A persisted Hybrid Logical Clock for deterministic ordering.

Immutable row-sized replication events captured by generated triggers.

A required typed replication-change table for every replicated application
table.

Per-field winning-version metadata.

Row tombstones for deletes.

Per-origin contiguous cursors and explicit gap repair.

Duplicate detection using origin node and origin counter.

Payload hashes to detect conflicting duplicate identities.

Persistent bidirectional TCP using length-prefixed gzip-compressed canonical JSON frames over mandatory production TLS.

PSK challenge-response authentication inside TLS or mTLS certificate
authentication using only user-provided credentials.

Atomic local capture and atomic remote application.

Snapshot bootstrap and safe log compaction.

Clock, schema, security, conflict, and replication-health monitoring.

Schema-derived prepared merge plans and deterministic type adapters.

Bounded set-based batch merge with explicit field-presence and SQL-NULL
semantics.

Periodic SQL gap auditing and resumable bounded retransmission.

Startup round-trip validation and pending-event materialization recovery.

Optional read-your-write session tokens and OpenMetrics-compatible telemetry.

This design allows each node to remain writable while disconnected and guarantees deterministic convergence once all valid events have been exchanged.

28. Required Verification Matrix

Before production use, automated tests must cover:

Schema introspection and generated SQL for simple, composite, quoted, and
reserved-word identifiers.

Round trips for NULL, omitted fields, minimum and maximum integers, values
beyond JSON's interoperable integer range, decimals, Unicode text, BLOBs,
UUIDs, dates, timestamps, booleans, floats, and structured JSON.

Every permutation of arrival order for competing field updates, row deletes,
and explicit re-creations, including exact-HLC ties from different origins.

Duplicate delivery with the same hash and conflicting reuse of an event UUID
or `(origin UUID, origin counter)` with a different hash.

Crashes before event insertion, after insertion but before materialization,
after materialization but before acknowledgment, and during batch or snapshot
activation.

Restart after wall-clock rollback, remote future-clock attacks, logical HLC
overflow policy, and restoration from an old database image.

SQLITE_BUSY injection with concurrent local writes, remote batches,
maintenance, backup, and compaction activity.

SQL `LEAD` gap detection across multiple origins, compacted baselines, bounded
continuations, unavailable history, and snapshot-required responses.

Transport duplication, reordering, truncation, invalid gzip, decompression
bombs, oversized frames, authentication failure, identity spoofing, disconnect
during a frame, and dial/accept reconnection behaviour.

Read-your-write success, expiration, tampering, timeout, and satisfaction only
after durable materialization.

Convergence by replaying the same randomized event set in different orders on
at least three nodes and comparing application rows, field winners,
tombstones, cursors, and hashes.

Performance tests must report results separately from correctness tests. A
performance threshold failure must never hide a failed atomicity, integrity,
security, or convergence assertion.

29. Implementation Provenance

The algorithms in this document are specified independently of a particular
package. If an implementation copies or adapts source code from
`carboneio/replic-sqlite`, including its native SQLite aggregate, it must
preserve the applicable Apache-2.0 license, modification notices, copyright
notices, and any required NOTICE material. Reimplementing an algorithmic idea
does not remove the need to review third-party patents, licenses, native-code
loading policy, and supply-chain requirements before distribution. Part of the
algorythm from carbonerio/replic-sqlite were use to create this replication.
