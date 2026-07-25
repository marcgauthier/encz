# Security PRAGMA Integration Tests

This directory verifies that direct-key PRAGMAs are rejected. Production key
configuration is available only through `OpenEncz` and `OpenWithOptions`, which
load an authenticated manifest and pass an unguessable in-process registry
capability to the VFS.

The test also covers rotation-policy validation at the public API boundary.
