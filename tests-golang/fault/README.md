# Fault SQLite Integration Tests

This directory contains integration, boundary, and crash-resilience tests verifying the robustness of encrypted SQLite databases under various failure and corruption modes.

## What is tested
- **Out of Disk Space Simulation**: Validates rollback safety and error bubbling when SQLite hits the `max_page_count` configuration.
- **Process Crash Recovery**: Spawns concurrent processes that are forcefully terminated (`SIGKILL`) during active write transactions, ensuring the database recoverably rolls back and remains uncorrupted upon subsequent reopen.
- **Data & Header Corruption Detection**: Modifies or corrupts specific bytes of the database file on disk to assert that the VFS/decryption engine detects authenticated-decryption failure (ChaCha20-Poly1305 tag check) and correctly errors out instead of returning corrupted garbage.
- **WAL Page Recovery**: Verifies transaction integrity and log replay under journal recovery/checkpointing when journal pages or logs are corrupted.

## Future Improvements
- **I/O Error Injection**: Implement a mock I/O layer to inject random read/write/sync errors to test resilience.
- **Power Failure Simulation**: Emulate sector-level partial writes (torn pages) to test how SQLite's journal recovery coordinates with the decryption layer.
- **Corruption of Specific WAL Frames**: Test behavior when only a subset of WAL frames are corrupted/tampered with.
