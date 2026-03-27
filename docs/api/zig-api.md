# Zig API Reference: zig-crypto

## `aes.zig`
*AES-128/256-CBC*

### Functions

#### `cbc128Encrypt`
AES-128-CBC encrypt with PKCS#7 padding. Returns number of ciphertext bytes written, or error.

```zig
pub fn cbc128Encrypt( key: *const [16]u8, iv: *const [16]u8, plaintext: []const u8, out: []u8, ) !usize
```

#### `cbc128Decrypt`
AES-128-CBC decrypt with PKCS#7 unpadding. Returns number of plaintext bytes written, or error.

```zig
pub fn cbc128Decrypt( key: *const [16]u8, iv: *const [16]u8, ciphertext: []const u8, out: []u8, ) !usize
```

#### `cbc256Encrypt`
AES-256-CBC encrypt with PKCS#7 padding. Returns number of ciphertext bytes written, or error.

```zig
pub fn cbc256Encrypt( key: *const [32]u8, iv: *const [16]u8, plaintext: []const u8, out: []u8, ) !usize
```

#### `cbc256Decrypt`
AES-256-CBC decrypt with PKCS#7 unpadding. Returns number of plaintext bytes written, or error.

```zig
pub fn cbc256Decrypt( key: *const [32]u8, iv: *const [16]u8, ciphertext: []const u8, out: []u8, ) !usize
```

#### `cbc256EncryptRaw`
AES-256-CBC encrypt without padding (raw blocks). Input must be a multiple of 16 bytes. Used by CTAP2 PIN protocol (zero IV, pre-padded data).

```zig
pub fn cbc256EncryptRaw( key: *const [32]u8, iv: *const [16]u8, plaintext: []const u8, out: []u8, ) !usize
```

#### `cbc256DecryptRaw`
AES-256-CBC decrypt without unpadding (raw blocks). Input must be a multiple of 16 bytes. Used by CTAP2 PIN protocol (zero IV, no padding).

```zig
pub fn cbc256DecryptRaw( key: *const [32]u8, iv: *const [16]u8, ciphertext: []const u8, out: []u8, ) !usize
```

### Constants

- `block_length`
- `cbcEncrypt`
- `cbcDecrypt`

## `ecdh.zig`
*ECDH P-256*

### Types

#### `KeyPair` (struct)
P-256 key pair for ECDH key agreement.

### Functions

#### `generateKeyPair`
Generate an ephemeral P-256 ECDH key pair.

```zig
pub fn generateKeyPair() !KeyPair
```

#### `deriveSharedSecret`
Compute ECDH shared secret: SHA-256(x-coordinate of d * Q). This matches CTAP2 PIN protocol v2 shared secret derivation.  peer_x, peer_y: affine coordinates of the peer's P-256 public key. scalar: our 32-byte scalar.

```zig
pub fn deriveSharedSecret( scalar: *const [key_length]u8, peer_x: *const [key_length]u8, peer_y: *const [key_length]u8, ) ![key_length]u8
```

### Constants

- `key_length`
- `uncompressed_point_length`

## `ed25519.zig`
*Ed25519 signing*

### Types

#### `KeyPair` (struct)
Ed25519 key pair.

### Functions

#### `generateKeyPair`
Generate a new Ed25519 key pair from random seed.

```zig
pub fn generateKeyPair() KeyPair
```

#### `fromSeed`
Derive Ed25519 key pair from a 32-byte seed. Used by Sparkle for deriving public key from stored seed.

```zig
pub fn fromSeed(seed: *const [seed_length]u8) !KeyPair
```

#### `sign`
Sign a message with Ed25519.

```zig
pub fn sign( message: []const u8, signing_key_bytes: *const [signing_key_length]u8, ) ![signature_length]u8
```

#### `verify`
Verify an Ed25519 signature.

```zig
pub fn verify( message: []const u8, signature_bytes: *const [signature_length]u8, public_key_bytes: *const [public_key_length]u8, ) bool
```

### Constants

- `seed_length`
- `public_key_length`
- `signature_length`
- `signing_key_length`

## `hmac.zig`
*HMAC-SHA-256*

### Functions

#### `hmacSha256`
Compute HMAC-SHA-256 of a message with the given key.

```zig
pub fn hmacSha256(key: []const u8, data: []const u8) [mac_length]u8
```

### Constants

- `mac_length`

## `pbkdf2.zig`
*PBKDF2-SHA1*

### Functions

#### `pbkdf2Sha1`
PBKDF2 with HMAC-SHA1 as the PRF. Derives `out.len` bytes of key material.

```zig
pub fn pbkdf2Sha1( passphrase: []const u8, salt: []const u8, iterations: u32, out: []u8, ) void
```

## `random.zig`
*CSPRNG*

### Functions

#### `fill`
Fill a buffer with cryptographically secure random bytes. Uses the OS-provided CSPRNG (getrandom on Linux, getentropy on macOS).

```zig
pub fn fill(buf: []u8) !void
```

## `sha256.zig`
*SHA-256 hash*

### Types

#### `Hasher` (struct)
Incremental SHA-256 hasher for streaming input.

### Functions

#### `hash`
Compute SHA-256 hash of arbitrary input.

```zig
pub fn hash(data: []const u8) [digest_length]u8
```

#### `init`

```zig
pub fn init() Hasher
```

#### `update`

```zig
pub fn update(self: *Hasher, data: []const u8) void
```

#### `final`

```zig
pub fn final(self: *Hasher) [digest_length]u8
```

### Constants

- `digest_length`
- `block_length`

