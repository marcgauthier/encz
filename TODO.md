  1. Critical: the WAL partial-write path can encrypt uninitialized memory back
     into a frame, which is a real corruption risk under partial WAL writes. In
     encz.c:678, enczWalWriteRegion decrypts the existing page only when nFrame
     < P; if that read returns SQLITE_IOERR_SHORT_READ, it clears the error and
     continues, but aPage was never initialized before the later memcpy and re-
     encrypt/write at encz.c:687. That is not production-safe for a storage
     layer.

  2. Critical: page authentication is not bound to page identity or location.
     The AES-GCM calls in encz.c:468 and encz.c:546 authenticate only the page
     payload bytes; there is no AAD for pgno, file offset, DB UUID, or similar,
     and the nonce/tag are stored with the page at encz.c:559. That means
     ciphertext pages can be replayed or swapped without the MAC necessarily
     detecting it. For an encrypted database format, that is a serious
     integrity/design gap.

 3. High: the current release is not migration-safe for existing users. The
     README explicitly says old databases are not automatically migrated at
     README.md:133, and the security suite still skips the key-rotation path
     based on VACUUM INTO at tests/security_test.go:203. That may be acceptable
     for a greenfield/internal package, but not for a production-ready general
     release unless the rollout constraints are very narrow and documented.

  4. Medium: verification is still incomplete for concurrency/crash behavior
     under stronger tooling. go build ./... and go test ./... both passed, but
     go test -race ./... did not complete cleanly in this review window; it
     stalled after the root package finished, leaving the integration test
     subprocesses alive. Even if that turns out to be a test-harness issue, it
     means the concurrency story is not yet convincingly closed.
