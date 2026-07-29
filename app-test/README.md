# SQLiteSeal continuous oracle test

This standalone Go application continuously stress-tests SQLiteSeal until it
receives Ctrl-C. It keeps the expected state in process memory and compares
SQLite query results against that independent oracle.

The workload uses 20 related tables with 13 columns each. It performs inserts,
updates, point reads, filtered and ordered list reads, and parent/child joins.
Every returned field is compared, including NULL values, floating-point values,
timestamps, and binary payloads. Tables use a configurable rolling row window
so a long run remains bounded.

Before the workload starts, the application certifies the complete exported
SQLiteSeal API:

- driver registration and safe/legacy DSN behavior;
- `OpenSQLiteSeal`, `OpenEncz`, and `OpenWithOptions`;
- AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305;
- `SQLDB`, rotation policy/status, read statistics/reset, and idempotent close;
- encrypted backup, backup testing, restore and overwrite protection;
- successful and rejected rekey operations;
- the custom authentication-error log handler and tamper detection.

While running, scheduled exclusive phases perform complete audits, close/reopen
validation, encrypted backup/restore validation, and master-key rotation. Any
unexpected SQL error, integrity failure, or data mismatch stops the application
immediately with a non-zero exit code. The last 200 events and full mismatch
context are retained in the run log.

## Run

```bash
cd app-test
go run .
```

Edit `config.yaml` to change workload size and maintenance intervals. An empty
`duration` runs indefinitely. For CI or a bounded smoke test:

```bash
go run . -duration 30s
```

The console status is rewritten on one line using `\r` and ANSI line clearing.
Errors are printed as permanent lines on stderr. Each invocation creates an
isolated timestamped directory under `runs/`; databases, backups, restored
copies, logs, and failure evidence are preserved there.

## Verify

```bash
go test ./...
go test -race ./...
go vet ./...
```
