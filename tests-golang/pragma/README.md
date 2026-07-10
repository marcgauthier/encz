# PRAGMA & Key Config Integration Tests

This directory contains integration tests verifying encryption key management, key rotation policies, and custom SQLite PRAGMA interactions supported by the `encz` VFS.

## What is tested
- **Key Rotation (ReKey)**: Validates that `db.ReKey` successfully updates the encryption key of an existing database, such that the old key is rejected and the new key is required to decrypt/read data.
- **Rotation Policy Configuration**: Verifies that setting and reading rotation policies via `SetRotationPolicy` and `RotationStatus` persists correctly and rejects invalid policy values (e.g., non-positive rotation days).
- **PRAGMA crypto_key**: Asserts that the database encryption key can be configured via standard raw SQL execution (`PRAGMA crypto_key = '...'`) before any database I/O starts.
- **PRAGMA crypto_status**: Asserts that `PRAGMA crypto_status` returns correct status strings identifying the encryption cipher (AES-256-GCM) and key configuration state.
- **Lazy Key Configuration Rejection**: Asserts that attempting to set `PRAGMA crypto_key` after database reads/writes have occurred results in a validation error.

## Future Improvements
- **Automatic Key Rewrapping**: Test actual key-wrapping behavior when `AutoRewrap` policy is enabled and rotation days are reached.
- **Multiple Attached Databases**: Test using `PRAGMA crypto_key` with multiple attached databases (e.g. `PRAGMA main.crypto_key` vs `PRAGMA aux.crypto_key`).
- **Encrypted Page Size Variations**: Verify using PRAGMAs to alter page size configurations alongside key settings.
