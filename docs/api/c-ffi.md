# C FFI API Reference: zig-crypto

## `zig_crypto.h`

| Function | Description |
|----------|-------------|
| `zig_crypto_sha256` | Compute SHA-256 hash. out must be at least 32 bytes. |
| `zig_crypto_sha256_hex` | Compute SHA-256 and write lowercase hex string. out must be at least 64 bytes. Returns number of hex chars written (always 64). |
| `zig_crypto_hmac_sha256` | Compute HMAC-SHA-256. out must be at least 32 bytes. |
| `zig_crypto_aes128_cbc_encrypt` | AES-128-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1. |
| `zig_crypto_aes128_cbc_decrypt` | AES-128-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1. |
| `zig_crypto_aes256_cbc_encrypt` | AES-256-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1. |
| `zig_crypto_aes256_cbc_decrypt` | AES-256-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1. |
| `zig_crypto_aes256_cbc_encrypt_raw` | AES-256-CBC encrypt without padding (raw blocks). plaintext_len must be a multiple of 16. For CTAP2 PIN protocol. |
| `zig_crypto_aes256_cbc_decrypt_raw` | AES-256-CBC decrypt without unpadding (raw blocks). ciphertext_len must be a multiple of 16. For CTAP2 PIN protocol. |
| `zig_crypto_pbkdf2_sha1` | PBKDF2 with HMAC-SHA1. Derives out_len bytes of key material. |
| `zig_crypto_p256_generate` | Generate ephemeral P-256 key pair. Writes 32 bytes each to out_scalar, out_pub_x, out_pub_y. Returns 0 on success, -1 on failure. |
| `zig_crypto_p256_ecdh` | ECDH shared secret: SHA-256(x-coordinate of scalar * peer_point). Writes 32 bytes to out_shared_secret. Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_generate` | Generate random Ed25519 key pair. Writes seed(32), public(32), signing_key(64). |
| `zig_crypto_ed25519_from_seed` | Derive Ed25519 key pair from 32-byte seed (deterministic). Writes public(32), signing_key(64). Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_sign` | Sign a message with Ed25519. Writes 64-byte signature. Returns 0 on success, -1 on failure. |
| `zig_crypto_ed25519_verify` | Verify an Ed25519 signature. Returns true if valid. |
| `zig_crypto_random` | Fill buffer with cryptographically secure random bytes. Returns true on success, false on failure. |

---

### `zig_crypto_sha256`

Compute SHA-256 hash. out must be at least 32 bytes.

```c
void zig_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *out);
```

### `zig_crypto_sha256_hex`

Compute SHA-256 and write lowercase hex string. out must be at least 64 bytes. Returns number of hex chars written (always 64).

```c
size_t zig_crypto_sha256_hex(const uint8_t *data, size_t data_len, uint8_t *out);
```

### `zig_crypto_hmac_sha256`

Compute HMAC-SHA-256. out must be at least 32 bytes.

```c
void zig_crypto_hmac_sha256( const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out );
```

### `zig_crypto_aes128_cbc_encrypt`

AES-128-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1.

```c
int zig_crypto_aes128_cbc_encrypt( const uint8_t key[16], const uint8_t iv[16], const uint8_t *plaintext, size_t plaintext_len, uint8_t *out );
```

### `zig_crypto_aes128_cbc_decrypt`

AES-128-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1.

```c
int zig_crypto_aes128_cbc_decrypt( const uint8_t key[16], const uint8_t iv[16], const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out );
```

### `zig_crypto_aes256_cbc_encrypt`

AES-256-CBC encrypt (PKCS#7 padding). Returns ciphertext length or -1.

```c
int zig_crypto_aes256_cbc_encrypt( const uint8_t key[32], const uint8_t iv[16], const uint8_t *plaintext, size_t plaintext_len, uint8_t *out );
```

### `zig_crypto_aes256_cbc_decrypt`

AES-256-CBC decrypt (PKCS#7 unpadding). Returns plaintext length or -1.

```c
int zig_crypto_aes256_cbc_decrypt( const uint8_t key[32], const uint8_t iv[16], const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out );
```

### `zig_crypto_aes256_cbc_encrypt_raw`

AES-256-CBC encrypt without padding (raw blocks). plaintext_len must be a multiple of 16. For CTAP2 PIN protocol.

```c
int zig_crypto_aes256_cbc_encrypt_raw( const uint8_t key[32], const uint8_t iv[16], const uint8_t *plaintext, size_t plaintext_len, uint8_t *out );
```

### `zig_crypto_aes256_cbc_decrypt_raw`

AES-256-CBC decrypt without unpadding (raw blocks). ciphertext_len must be a multiple of 16. For CTAP2 PIN protocol.

```c
int zig_crypto_aes256_cbc_decrypt_raw( const uint8_t key[32], const uint8_t iv[16], const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out );
```

### `zig_crypto_pbkdf2_sha1`

PBKDF2 with HMAC-SHA1. Derives out_len bytes of key material.

```c
void zig_crypto_pbkdf2_sha1( const uint8_t *passphrase, size_t passphrase_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len );
```

### `zig_crypto_p256_generate`

Generate ephemeral P-256 key pair. Writes 32 bytes each to out_scalar, out_pub_x, out_pub_y. Returns 0 on success, -1 on failure.

```c
int zig_crypto_p256_generate( uint8_t *out_scalar, uint8_t *out_pub_x, uint8_t *out_pub_y );
```

### `zig_crypto_p256_ecdh`

ECDH shared secret: SHA-256(x-coordinate of scalar * peer_point). Writes 32 bytes to out_shared_secret. Returns 0 on success, -1 on failure.

```c
int zig_crypto_p256_ecdh( const uint8_t scalar[32], const uint8_t peer_x[32], const uint8_t peer_y[32], uint8_t *out_shared_secret );
```

### `zig_crypto_ed25519_generate`

Generate random Ed25519 key pair. Writes seed(32), public(32), signing_key(64).

```c
void zig_crypto_ed25519_generate( uint8_t *out_seed, uint8_t *out_public, uint8_t *out_signing );
```

### `zig_crypto_ed25519_from_seed`

Derive Ed25519 key pair from 32-byte seed (deterministic). Writes public(32), signing_key(64). Returns 0 on success, -1 on failure.

```c
int zig_crypto_ed25519_from_seed( const uint8_t seed[32], uint8_t *out_public, uint8_t *out_signing );
```

### `zig_crypto_ed25519_sign`

Sign a message with Ed25519. Writes 64-byte signature. Returns 0 on success, -1 on failure.

```c
int zig_crypto_ed25519_sign( const uint8_t *message, size_t message_len, const uint8_t signing_key[64], uint8_t *out_signature );
```

### `zig_crypto_ed25519_verify`

Verify an Ed25519 signature. Returns true if valid.

```c
bool zig_crypto_ed25519_verify( const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32] );
```

### `zig_crypto_random`

Fill buffer with cryptographically secure random bytes. Returns true on success, false on failure.

```c
bool zig_crypto_random(uint8_t *buf, size_t len);
```

