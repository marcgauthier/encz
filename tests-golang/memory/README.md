# Memory Mode Restriction Tests

This directory contains integration tests verifying that raw in-memory SQLite database configurations are properly rejected by the `SQLiteSeal` VFS.

## What is tested
- **In-Memory Database Rejection**: Asserts that trying to open `:memory:` with an encryption key returns `sqliteseal.ErrFileBackedRequired`.
- **Shared Memory Cache Rejection**: Asserts that opening a database with URI parameters containing `mode=memory` and `cache=shared` returns `sqliteseal.ErrFileBackedRequired`.

These constraints exist because in-memory configurations do not trigger file-backed page reads/writes, making the encryption layer irrelevant or unsafe without persistent storage context.

## Future Improvements
- **Empty Path Temporary Databases**: Verify the behavior of opening an empty path `""` database, which SQLite implements using a temporary file-backed storage that is automatically deleted when the database connection is closed.
- **In-Memory VFS Fallback Option**: Test configuration setups if we ever allow optional bypass or unencrypted fallbacks for test/mocking purposes.
