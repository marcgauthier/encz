# SQLiteSeal two-node replication verifier

This app creates two encrypted SQLiteSeal databases, generates an ephemeral
localhost PKI and PSK, configures a signed two-node full mesh, and verifies
bidirectional replication, administrative peer authentication, credential
reload, status and API error contracts, offline catch-up, per-field conflict
resolution, duplicate-safe resynchronization, tombstones, consistent snapshot
creation, automatic snapshot bootstrap after retained-history loss, and
restart recovery.

Run:

```bash
go run .
```

Each run stores its encrypted databases under `runs/` and exits non-zero on the
first mismatch. Credentials are ephemeral and are not written to disk.
