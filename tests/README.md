# Encz SQLite Integration & Stress Test Suite Plan

This directory is dedicated to the integration, stress, and boundary testing of the [`encz`](file:///home/marc/ENCZ) package. The package wraps standard SQLite (`github.com/mattn/go-sqlite3`) and injects a custom Virtual File System (VFS) to provide transparent encryption and compression.

The goal of this test suite is to validate that SQLite performs correctly across all features under the VFS encryption/compression layers. Below is an exhaustive list of tests categorized by target behavior, designed to be implemented as a Go test suite.

---

## Table of Contents
1. [Core SQLite & Go Type Compatibility](#1-core-sqlite--go-type-compatibility)
2. [Schema Complexity & Query Engine Validation](#2-schema-complexity--query-engine-validation)
3. [Encryption & Security Verification](#3-encryption--security-verification)
4. [Compression Configurations & Efficiency](#4-compression-configurations--efficiency)
5. [Memory & Storage Variations](#5-memory--storage-variations)
6. [Journaling, Concurrency & Locking](#6-journaling-concurrency--locking)
7. [Stress, Volume & Longevity Testing](#7-stress-volume--longevity-testing)
8. [Fault Tolerance & Failure Simulation](#8-fault-tolerance--failure-simulation)
9. [Test Execution & Harness Guidelines](#9-test-execution--harness-guidelines)

---

## 1. Core SQLite & Go Type Compatibility

These tests ensure that standard data types, CRUD operations, and constraints work normally when intercepted by the `encz` VFS.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-CORE-001** | `TestTypeRoundtrip` | CRUD on all standard SQLite types: `INTEGER`, `REAL`, `TEXT`, `BLOB`, `NULL`, and custom time layouts. | Full roundtrip parity with no data corruption or type coercion failures. |
| **TC-CORE-002** | `TestPrimaryUniqueConstraints` | Enforce and violate `PRIMARY KEY` and `UNIQUE` constraints. | SQLite raises expected constraint violation errors (`SQLITE_CONSTRAINT`). |
| **TC-CORE-003** | `TestForeignKeyConstraints` | Test immediate, deferred, and cascading foreign key constraints (`ON DELETE CASCADE`, `ON UPDATE CASCADE`). | Cascades execute properly, and invalid references block writes. |
| **TC-CORE-004** | `TestCheckAndNotNullConstraints` | Enforce fields with `NOT NULL` and custom `CHECK` constraints (e.g., `CHECK(age >= 0)`). | Constraint validation remains active and behaves as expected. |
| **TC-CORE-005** | `TestNullHandling` | Insert and query rows with nullable columns, executing `IS NULL` and `COALESCE` logic. | Nullability states are correctly preserved and queryable. |

---

## 2. Schema Complexity & Query Engine Validation

These tests verify that complex SQL constructs, subqueries, and large joins execute correctly. Since complex queries use temporary tables and page caching, this validates the VFS intercepting paging operations.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-COMP-001** | `TestComplexJoins` | Perform queries involving `INNER JOIN`, `LEFT OUTER JOIN`, `RIGHT OUTER JOIN`, `FULL OUTER JOIN`, and `CROSS JOIN` across 5+ tables with indexed/non-indexed fields. | Correct dataset joins, sorting, and output. |
| **TC-COMP-002** | `TestCommonTableExpressions` | Run deep CTEs and recursive CTEs (e.g., generating hierarchical tree graphs, Fibonacci sequence calculation). | Correct CTE query results under page-restricted memory. |
| **TC-COMP-003** | `TestSubqueriesAndExists` | Execute correlated subqueries, nested query layers, and filters using `EXISTS` and `NOT EXISTS`. | SQLite engine yields identical results to unencrypted SQLite. |
| **TC-COMP-004** | `TestWindowFunctions` | Query data using partition and windowing clauses (e.g., `ROW_NUMBER() OVER (...)`, `LAG`, `LEAD`, `SUM(...) OVER`). | Window functions compute correct results. |
| **TC-COMP-005** | `TestTriggersAndViews` | Define views and database triggers (`BEFORE INSERT`, `AFTER UPDATE`, `INSTEAD OF` on views). | Triggers fire correctly and execute updates across tables. |
| **TC-COMP-006** | `TestFullTextSearchFTS5` | Create and search virtual tables using SQLite's `FTS5` extension. | Full-text indexing and querying works seamlessly. |

---

## 3. Encryption & Security Verification

These tests validate cryptographic boundaries, key verification, block alignment, and leak prevention.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-SEC-001** | `TestInvalidKeyRejection` | Create database with `Key="Secret123"`. Close connection. Attempt to open with `Key="WrongKey"`. | Reopened connection fails to read schema/data or ping the DB, returning a corruption/decryption error. |
| **TC-SEC-002** | `TestUnencryptedToEncrypted` | Try to open a plain SQLite database as an encrypted database, and vice versa. | Operations fail gracefully with appropriate error codes. |
| **TC-SEC-003** | `TestHeaderSecrecy` | Inspect the first 100 bytes of the encrypted database file on disk. | The standard SQLite magic string `"SQLite format 3\000"` must **not** be present. The file must look like random bytes. |
| **TC-SEC-004** | `TestExtremeKeys` | Open databases using edge-case keys: 1-byte key, 1024-byte key, non-printable binary keys, and UTF-8 multibyte characters. | Successful connection, read/write, and integrity check. |
| **TC-SEC-005** | `TestKeyRotation` | Re-key or migrate an encrypted database. Since SQLite's VFS doesn't support built-in re-keying, verify if running `VACUUM INTO` into a new DSN with a different key works. | Successfully generates a new database file encrypted with the new key. |

---

## 4. Compression Configurations & Efficiency

These tests ensure that the compression codecs (`zstd`, `deflate`) compress pages properly without data loss or corruption, and verify extreme compression configuration options.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-ZIP-001** | `TestCompressionCodecs` | Compare the same dataset written with `Compression="none"`, `Compression="zstd"`, and `Compression="deflate"`. | All databases successfully read/write. Compressed DB files should be smaller than `none` for text datasets. |
| **TC-ZIP-002** | `TestCompressionLevels` | Validate different compression levels (e.g., levels `1`, `3`, `9` for deflate, and `-3` to `22` for zstd). Test out-of-bound levels (e.g., `-999`, `999`). | Valid levels execute successfully; invalid levels fall back to defaults or reject with errors. |
| **TC-ZIP-003** | `TestIncompressibleData` | Write a database filled entirely with random cryptographically secure bytes (uncompressible). | The database handles incompressible pages without excessive growth or compression buffer overflows. |
| **TC-ZIP-004** | `TestZeroBlockCompression` | Write tables with massive columns containing repeated zeros or empty text. | The database file sizes reflect high compression ratios. |

---

## 5. Memory & Storage Variations

These tests evaluate database performance and behavior under physical and logical memory constraints.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-MEM-001** | `TestInMemoryOnly` | Open databases with `:memory:` or `file::memory:` using `encz` VFS encryption and compression. | Fully functioning in-memory database. Encryption/compression overhead behaves normally. |
| **TC-MEM-002** | `TestInMemorySharedCache` | Open multiple connections to a shared-cache in-memory database using URI `file:memdb?mode=memory&cache=shared`. | Multiple connections can read/write to the same encrypted memory structure. |
| **TC-MEM-003** | `TestSmallPageCache` | Set `PRAGMA cache_size = 2` (very small cache, ~2KB). Execute operations that modify thousands of rows. | SQLite is forced to frequently read/write pages to the encrypted/compressed disk. System handles constant paging without deadlock or corrupt state. |
| **TC-MEM-004** | `TestVariablePageSizes` | Create databases using different page sizes: `512`, `1024`, `4096` (default), `8192`, `16384`, `32768`, and `65536` bytes. | Databases read/write correctly. Verifies that page encryption and compression align properly with variable block sizes. |
| **TC-MEM-005** | `TestTempStoreLocation` | Toggle `PRAGMA temp_store = FILE` vs `PRAGMA temp_store = MEMORY` during massive sort/join queries. | Temporary database structures remain secure and do not cause CGO panic or memory leakage. |

---

## 6. Journaling, Concurrency & Locking

These tests verify transaction isolation, locking pragmas, and concurrency stability in multi-threaded environments.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-CON-001** | `TestJournalModes` | Test database creation and modification using different journal modes: `DELETE`, `TRUNCATE`, `PERSIST`, `MEMORY`, `WAL`, and `OFF`. | Database correctly processes transactions in all journal modes. |
| **TC-CON-002** | `TestWALCheckpointing` | Write data in WAL mode, then trigger checkpointing (`PRAGMA wal_checkpoint(TRUNCATE)` or `RESTART`). Reopen and verify data. | WAL and main DB file sync correctly. Reopening verifies state. |
| **TC-CON-003** | `TestLockingModes` | Exercise transaction locking structures: `BEGIN DEFERRED`, `BEGIN IMMEDIATE`, and `BEGIN EXCLUSIVE`. | Locks restrict access as per standard SQLite locking guidelines. |
| **TC-CON-004** | `TestBusyTimeout` | Spawn concurrent reader/writer goroutines. Configure `_busy_timeout` using `BusyTimeoutMillis`. | Blocked operations wait up to the timeout threshold before returning a busy error (`SQLITE_BUSY`). |
| **TC-CON-005** | `TestReaderThreadContention` | 50 concurrent reader goroutines continuously query an encrypted database while 5 writer goroutines write updates. | No deadlocks, race conditions, or corrupted reads occur. |

---

## 7. Stress, Volume & Longevity Testing

These tests push `encz` to its limits to identify memory leaks, CGO boundary performance issues, and scale-related issues.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-STR-001** | `TestMassiveBlobPayloads` | Insert, select, and delete massive single blobs: 10MB, 50MB, 100MB, and 250MB. | No Out-Of-Memory (OOM) errors. VFS streams or chunks page encryption/compression correctly. |
| **TC-STR-002** | `TestHighVolumeInserts` | Insert 1,000,000 rows within a single transaction, and 100,000 individual transactions (single inserts). | Data is stored correctly; database maintains stable execution speed and structure. |
| **TC-STR-003** | `TestConcurrencyStressPool` | Open a pool of 200 concurrent goroutines querying and writing to the database over 5 minutes. | Safe execution with standard Go SQL driver connection pooling. |
| **TC-STR-004** | `TestMemoryLeakLongevity` | Execute 10,000,000 operations (read, write, open, close) in a loop and monitor Go heap + resident set size (RSS) memory. | Memory profile remains flat, proving no CGO memory leak. |

---

## 8. Fault Tolerance & Failure Simulation

These tests simulate realistic file system failures, permission errors, process crashes, and database corruption.

| Test ID | Test Name | Objective / Scenario | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-FLT-001** | `TestSimulateNoDiskSpace` | **Method 1 (Loopback Mount):** Create a tiny loopback filesystem (`tmpfs` or size-limited `loop` device, e.g., 2MB) and write to the database until the filesystem is full.<br>**Method 2 (Mock OS Writer):** Intercept disk writes to return `ENOSPC` (No space left on device) or write failures. | Writes fail with an appropriate error (e.g., `SQLITE_FULL`). The database does not become corrupted; transactions rollback gracefully. |
| **TC-FLT-002** | `TestCrashRecovery` | Execute a helper binary that performs rapid database inserts inside a transaction. Kill the helper binary middle-transaction (using `SIGKILL`). Re-open database with the original key. | SQLite hot-journal/WAL recovery succeeds; database integrity check passes. |
| **TC-FLT-003** | `TestReadOnlyFileSystem` | Copy an encrypted database to a read-only directory or file location. Attempt to open in read-only mode, and attempt to write. | Reads succeed; writes fail with standard write protection/permission errors (`SQLITE_READONLY`). |
| **TC-FLT-004** | `TestCorruptionTampering` | Tamper with random byte locations (e.g., byte offset 500, 1000) of an encrypted/compressed database file on disk. Attempt to open and read. | The VFS detects integrity failure during decryption or decompression, returning a clear error and refusing to load corrupted pages. |

---

## 9. Test Execution & Harness Guidelines

To execute these tests programmatically:

1. **Isolation**: Every test case must use a unique database file path (e.g., generated using `t.TempDir()`) to ensure absolute test isolation.
2. **CGO Requirement**: Build or test command must run with `CGO_ENABLED=1`.
3. **Loopback/Quota Simulation for disk space**: 
   - Since mounting filesystems requires `root` privileges, the disk space simulation (`TC-FLT-001`) can be designed as a separate shell script or a Go test using `os.WriteFile` or OS-level file quota boundaries (like user quotas or `systemd-run` resource limits).
4. **Integrity Validation**: Run `PRAGMA integrity_check;` on the reopened database after every destructive test (crash recovery, stress, WAL checkpoints) to ensure zero page corruption.
5. **No Placeholders**: Do not stub test functions. They must verify actual database states by querying the SQLite table catalog and validating returned row counts.
