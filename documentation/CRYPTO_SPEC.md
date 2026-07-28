# SQLiteSeal Cryptographic Specification & Threat Model

This document defines the cryptographic design, key derivation algorithms, envelope encryption schema, memory protection model, cipher specifications, and threat model for `SQLiteSeal` (`github.com/marcgauthier/SQLiteSeal`).

---

## 1. Cryptographic Architecture & Key Hierarchy

`SQLiteSeal` employs a two-tier envelope encryption model to decouple user authentication passphrases from internal page Data Encryption Keys (DEKs).

```
                      +-----------------------------+
                      |      User Master Key        |
                      |  (Passphrase / Raw Secret)  |
                      +-----------------------------+
                                     |
                                     v
                        Argon2id Key Derivation
                     (t=3, m=64MB, p=4, 16B Salt)
                                     |
                                     v
                      +-----------------------------+
                      | Key Encryption Key (KEK)    |
                      |          (32 Bytes)         |
                      +-----------------------------+
                                     |
                         AEAD Encrypt / Decrypt
                                     |
                                     v
                  +-------------------------------------+
                  |   Sidecar Manifest (.encz JSON)     |
                  |  - Database UUID (16B)              |
                  |  - Cipher Selection                 |
                  |  - Active DEK Key ID                |
                  |  - Array of DEKs (DEK_1, DEK_2...)  |
                  +-------------------------------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
     Page 1 AEAD Encryption                      Page N AEAD Encryption
  (Payload + AAD + Nonce_1)                   (Payload + AAD + Nonce_N)
```

---

## 2. Key Derivation & Parameters

User master keys are transformed into a 256-bit Key Encryption Key (KEK) using **Argon2id** (RFC 9106), providing resistance against GPU, ASIC, and side-channel attacks.

### Argon2id KDF Configuration

| Parameter | Value | Constant Name | Description |
| :--- | :--- | :--- | :--- |
| **Time Cost ($t$)** | `3` | `defaultArgonTime` | Number of iterations over memory. |
| **Memory Cost ($m$)** | `64 MB` (`65,536 KiB`) | `defaultArgonMemory` | Amount of RAM consumed during KDF execution. |
| **Parallelism ($p$)** | `4` | `defaultArgonThreads` | Number of parallel operating system threads. |
| **Salt Length** | `16 bytes` | `manifestSaltSize` | Fresh OS CSPRNG salt generated per manifest creation. |
| **Derived KEK Size** | `32 bytes` | `manifestKEKSize` | 256-bit key used to protect the `.encz` manifest envelope. |

---

## 3. Envelope Encryption & Manifest Schema

The `.encz` sidecar file stores envelope-encrypted metadata. The raw file header begins with a 6-byte magic string `ENCZK3` followed by a 1-byte version identifier (`0x03`).

### Manifest Struct Format (JSON Payload)

```json
{
  "uuid": "a1b2c3d4e5f67890123456789abcdef0",
  "cipher": "aes-256-gcm",
  "created_at": "2026-07-28T15:00:00Z",
  "active_dek_id": 1,
  "deks": [
    {
      "id": 1,
      "key_hex": "<32-byte-hex-encoded-dek>",
      "created_at": "2026-07-28T15:00:00Z"
    }
  ],
  "rotation_policy": {
    "kek_rotation_days": 7,
    "dek_rotation_hours": 24
  }
}
```

### Multi-DEK Key Retention
When key rotation occurs, a new DEK (e.g. `DEK_2`) is created and assigned as the `active_dek_id`. Existing database pages retain their original `Key ID` (e.g. `1`) in their 48-byte trailers. Because older DEKs are preserved in the manifest `deks` array forever, legacy pages can be decrypted seamlessly on read without requiring expensive, full-database re-encryption.

---

## 4. Supported Cipher Suites

`SQLiteSeal` supports three authenticated encryption algorithms (AEAD), operating strictly with 256-bit keys and 128-bit authentication tags.

### 1. AES-256-GCM (Default)
- **Standard**: NIST SP 800-38D
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Implementation**: Go standard library `crypto/aes` & `crypto/cipher`

### 2. ChaCha20-Poly1305
- **Standard**: RFC 8439
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Implementation**: `golang.org/x/crypto/chacha20poly1305`

### 3. XChaCha20-Poly1305
- **Standard**: Draft-irtf-cfrg-xchacha
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 192 bits (24 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Implementation**: `golang.org/x/crypto/chacha20poly1305.NewX`

---

## 5. Nonce Generation & Uniqueness Strategy

Nonces are generated per page write using the operating system's Cryptographically Secure Pseudorandom Number Generator (CSPRNG via `crypto/rand`).

### Probabilistic Nonce Collision Bounds
- **XChaCha20-Poly1305 (192-bit nonce)**: Nonce reuse probability is zero ($2^{-192}$ space). Extremely resilient against nonce collisions across infinite writes.
- **AES-256-GCM & ChaCha20-Poly1305 (96-bit nonce)**: By the Birthday Paradox, evaluated at $P(\text{collision}) \le 2^{-32}$, a single DEK should not exceed **$2^{32}$ page write operations**. To maintain safe cryptographic bounds, `SQLiteSeal` enforces automatic DEK key rotation policies.

---

## 6. Protected Memory Model (`memguard`)

To prevent secret keys from leaking to swap space, core dumps, or process memory scrapers:

1. **Pinned Allocation**: All Master Keys, KEKs, and DEKs are stored in `memguard.LockedBuffer` memory structures.
2. **Page Pinning (`mlock`)**: Calls OS-level memory locking APIs (`mlock` on POSIX, `VirtualLock` on Windows) to prevent RAM swapping to disk.
3. **RAM Wiping**: When keys are destroyed or connections are closed via `Close()`, `memguard` explicitly overwrites memory bytes with zero bytes (`0x00`) before returning memory to the allocator.

---

## 7. Threat Model & Security Boundaries

### Threat Assumptions

#### 1. Adversary Capabilities
- **Storage Access**: The attacker has full read and write access to the disk storage containing the database (`.db`), write-ahead log (`.db-wal`), manifest (`.encz`), and lock files.
- **Offline Analysis**: The attacker can inspect disk snapshots taken at any point in time.
- **Process Memory Scraper**: The attacker may attempt to inspect unallocated process memory if memory is not zeroed.

### Security Guarantees (What IS Protected)

- **Confidentiality of Database Content**: All table rows, column values, indexes, B-tree metadata, and WAL log records are encrypted.
- **Authenticity & Tamper Detection**: Any unauthorized modification to page ciphertext, 48-byte trailers, or manifest JSON triggers an immediate AEAD authentication error.
- **Page Re-ordering & Substitution Protection**: AAD binding (binding DB UUID, Page Number, File Offset, and WAL context) prevents an attacker from moving encrypted pages to different offsets, swapping pages between databases, or replaying WAL pages.
- **Key Swapping Prevention**: Storing the 4-byte `Key ID` inside the AEAD tag calculation prevents an attacker from switching key identifiers.

### Security Boundaries & Non-Goals (What IS NOT Hidden)

- **Database File Size**: The total number of pages and overall database file size remains visible to an observer with filesystem access.
- **Page Size**: The configured page size (e.g. 4096 bytes) is observable from file length multiples.
- **Access Patterns**: High-frequency write locations (e.g. WAL growth rate) can be observed by monitoring disk I/O.
