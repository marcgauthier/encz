# Test Plan

This directory contains integration, stress, and boundary tests for `encz`.
The package wraps `github.com/mattn/go-sqlite3` with a custom SQLite VFS that provides transparent page-level encryption.

The suite focuses on correctness under encrypted main-database and WAL page I/O, including:

- core SQLite type and CRUD behavior
- pragma and key configuration behavior
- journal mode and concurrency behavior
- fault handling and corruption detection
- security and key-mismatch behavior
- stress and large-transaction behavior
- in-memory and variable-page-size behavior
