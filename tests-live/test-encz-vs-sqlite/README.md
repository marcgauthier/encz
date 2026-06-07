# ENCZ vs. SQLite Differential Test Runner

This directory contains `test-encz-vs-sqlite`, a high-concurrency differential testing application that verifies the stability, correctness, and performance of `encz` (SQLite encrypted page VFS) relative to plain SQLite.

## Objective
The core objective is to ensure that under extreme database stress, the behavior of `encz` matches SQLite identically. Any divergence in transaction behavior, return values, row data, schema structure, or database integrity is immediately detected, logged with 200-event diagnostics history, and halts execution.

---

## Stability & Correctness Verification Features

The runner uses several techniques to prove the stability of the `encz` engine:

### 1. High-Concurrency Stress Testing
- **Multi-Worker Execution:** Runs multiple concurrent worker goroutines (configurable via `worker_count`, default: 8) constantly performing database operations.
- **Workload Mix:** Simulates realistic transaction workloads using a configurable mix of CRUD queries (e.g., 60% SELECT, 20% UPDATE, 10% INSERT, 10% DELETE).

### 2. Immediate Inline Validation
- **Read Verification:** Every SELECT query retrieves rows by ID from both SQLite and `encz` and performs a deep structural comparison.
- **Write Verification (Instant Detection):** Immediately following a successful `INSERT` or `UPDATE` transaction on both engines, the runner queries the modified row back by primary key (`id`) and verifies that their data payloads match perfectly. This ensures that:
  - Divergences are detected at the exact action number that caused them.
  - Verification is highly optimized ($O(1)$ complexity) and does not require scanning entire tables.

### 3. Structural Integrity Checks
- **Fast Periodic Verification:** The runner pauses workers at regular intervals (`compare_interval`) to execute:
  ```sql
  PRAGMA integrity_check;
  ```
  on both databases. This commands the database engines to verify structural B-Tree formatting, index links, and page structures, proving that the VFS page transformation did not corrupt the database file.

### 4. Automatic DEK Rotation Resilience
- **Multi-DEK Validation:** With DEK rotation enabled (e.g., `dek_rotation: 1h`), the runner forces the manifest sidecar (`.encz`) to dynamically allocate and rotate Data Encryption Keys. Over long runs, the database file will end up with pages encrypted under different historical DEK keys, proving the VFS can dynamically resolve, read, and write pages using the correct DEK Key IDs.

### 5. Connection Reopen Resilience
- **Restart Simulation:** Periodically closes and reconnects to both databases (`reopen_interval`), verifying that:
  - Cryptographic keys are successfully purged from memory.
  - Manifest parsing and master key envelope decryption (via KEK) work correctly upon reopening.
  - Session state is successfully recovered.

### 6. Dynamic Schema Mutation
- **DDL Mutation:** Periodically modifies database structure by adding/dropping tables, columns, or indexes.
- **Event-Driven Schema Check:** Immediately after a schema mutation completes, the runner runs schema validation to ensure both databases have identical structures.

### 7. Auto-Pruning and VACUUM
- **Disk Management:** If the database exceeds `max_db_size`, the runner automatically deletes 50% of the older rows and triggers a `VACUUM` transaction on both databases. This validates page re-allocation and structural compaction.

### 8. Invalid Write / Constraint Testing
- **Error Matching:** The runner intentionally injects invalid values (nulls in non-nullable columns, wrong data types) on a small percentage of writes. It validates that both SQLite and `encz` return the **exact same error** (e.g., `UNIQUE constraint failed`, `NOT NULL constraint failed`).

### 9. Large Transaction Commit Validation
- **Massive Single Transaction Boundary:** At `large_tx_interval`, the runner pauses workers and inserts 15,000 rows, each carrying a 3.5 KB payload, in one explicit transaction on both databases.
- **Why this matters:** The normal live workload performs random operations individually or in small batches. This phase specifically stresses page cache flushing, temporary files, and encryption-buffer behavior under a large commit boundary.
- **Post-Commit Validation:** After both commits, the runner verifies row counts match and runs `PRAGMA integrity_check` before dropping the temporary validation table and resuming workers.

---

## Future Improvements

To further improve the test coverage, the following enhancements are planned:

1. **Mock I/O Fault Injection:**
   - Inject randomized file-sync and read/write faults (using a mock file-system layer) to verify how the VFS decryption handles torn pages or disk read/write failures.
2. **Power Failure Simulation:**
   - Emulate abrupt power failures by corrupting random database pages mid-write and checking that standard SQLite WAL journal recovery handles decryption of recovered frames correctly.
3. **Resilience & Corruption Harness:**
   - Add abrupt process crash (`SIGKILL`), out-of-disk-space, and byte-level on-disk corruption scenarios to verify the GCM authentication tag flags decryption failures outside the steady-state live runner process.
