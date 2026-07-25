# Cryptographic & Security Integration Tests

This directory contains integration tests verifying data confidentiality, cryptographic key rejection boundaries, and metadata safety of the `SQLiteSeal` VFS.

## What is tested
- **Invalid Key Rejection**: Asserts that attempting to open or read an encrypted database using an incorrect key fails.
- **Cross-Open Prevention**: Asserts that plain databases cannot be read when using an encryption key, and encrypted databases cannot be read/opened without a key.
- **Header Secrecy**: Verifies that while page payloads are fully encrypted, the standard SQLite format marker ("SQLite format 3\000") is preserved on disk, and the reserved-bytes header field at byte offset 20 is configured correctly (36 bytes reserved per page).
- **Extreme & Edge-Case Keys**: Verifies encryption and decryption work flawlessly with edge-case keys including single-character keys, 1024-byte long keys, binary keys (containing null bytes and non-printable characters), and multibyte Unicode keys.

## Future Improvements
- **Ciphertext Entropy Verification**: Add tests that read the database file bytes and run statistical entropy tests (e.g. chi-squared) to ensure no discernible patterns or structure leak from encrypted pages.
- **Memory Security & Zeroing**: Test that the decryption keys are properly zeroed/cleared from RAM when database connections are closed.
- **Resistance to Plaintext Attacks**: Verify that known database layouts (e.g., standard page headers) do not expose vulnerabilities to ciphertext manipulation.
