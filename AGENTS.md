# AGENTS.md -- zig-crypto

## Capabilities

- AES-128/256-CBC encryption and decryption (PKCS#7 and raw modes)
- ECDH P-256 key agreement
- Ed25519 digital signatures (generate, sign, verify)
- HMAC-SHA-256 message authentication
- PBKDF2-SHA1 key derivation
- Cryptographically secure random number generation (OS CSPRNG)
- SHA-256 hashing

## C FFI Exports (zig_crypto.h)

| Function | Return | Description |
|----------|--------|-------------|
| `zig_crypto_sha256` | `void` | Compute SHA-256 hash. out must be at least 32 bytes. |
| `zig_crypto_sha256_hex` | `size_t` | Compute SHA-256 and write lowercase hex string. out must be at least 64 bytes. Returns number of hex chars written (always 64). |
| `zig_crypto_hmac_sha256` | `void` | Compute HMAC-SHA-256. out must be at least 32 bytes. |
| `zig_crypto_aes128_cbc_encrypt` | `int` | AES-128-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1. |
| `zig_crypto_aes128_cbc_decrypt` | `int` | AES-128-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1. |
| `zig_crypto_aes256_cbc_encrypt` | `int` | AES-256-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1. |
| `zig_crypto_aes256_cbc_decrypt` | `int` | AES-256-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1. |
| `zig_crypto_aes256_cbc_encrypt_raw` | `int` | AES-256-CBC encrypt without padding (raw blocks). plaintext_len must be a multiple of 16. For CTAP2 PIN protocol. |
| `zig_crypto_aes256_cbc_decrypt_raw` | `int` | AES-256-CBC decrypt without unpadding (raw blocks). ciphertext_len must be a multiple of 16. For CTAP2 PIN protocol. |
| `zig_crypto_pbkdf2_sha1` | `void` | PBKDF2 with HMAC-SHA1. Derives out_len bytes of key material. |
| `zig_crypto_p256_generate` | `int` | Generate ephemeral P-256 key pair. Writes 32 bytes each to out_scalar, out_pub_x, out_pub_y. Returns 0 on success, -1 on failure. |
| `zig_crypto_p256_ecdh` | `int` | ECDH shared secret: SHA-256(x-coordinate of scalar * peer_point). Writes 32 bytes to out_shared_secret. Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_generate` | `void` | Generate random Ed25519 key pair. Writes seed(32), public(32), signing_key(64). |
| `zig_crypto_ed25519_from_seed` | `int` | Derive Ed25519 key pair from 32-byte seed (deterministic). Writes public(32), signing_key(64). Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_sign` | `int` | Sign a message with Ed25519. Writes 64-byte signature. Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_verify` | `bool` | Verify an Ed25519 signature. Returns true if valid. |
| `zig_crypto_random` | `bool` | Fill buffer with cryptographically secure random bytes. Returns true on success, false on failure. |

## Error Conventions

**Size constants:**

- `ZIG_CRYPTO_SHA256_DIGEST_LEN` = 32
- `ZIG_CRYPTO_SHA256_BLOCK_LEN` = 64
- `ZIG_CRYPTO_HMAC_SHA256_LEN` = 32
- `ZIG_CRYPTO_AES_BLOCK_LEN` = 16
- `ZIG_CRYPTO_P256_SCALAR_LEN` = 32
- `ZIG_CRYPTO_P256_COORD_LEN` = 32
- `ZIG_CRYPTO_ED25519_SEED_LEN` = 32
- `ZIG_CRYPTO_ED25519_PUBLIC_LEN` = 32
- `ZIG_CRYPTO_ED25519_SIGNING_LEN` = 64
- `ZIG_CRYPTO_ED25519_SIGNATURE_LEN` = 64

- Return `0` on success
- Return `-1` on failure
- Functions returning data length return byte count on success, negative on error

## Platform Requirements

- Cross-platform (Zig standard library only)
- No external dependencies

## Build

```bash
zig build                              # static library -> zig-out/lib/
zig build -Doptimize=ReleaseFast       # optimized build
zig build test                         # unit tests
```

## Linking

The library builds as a static archive. Include the header
from `include/` and link `zig-out/lib/libzig-crypto.a`.

