# Zig API Reference

Auto-generated from Zig source files in [`src/`](https://github.com/Jesssullivan/zig-crypto/tree/main/src).

These are the internal Zig modules. For C/Swift interop, see the [C FFI Reference](c-ffi.md).

### `aes.zig`

AES-128-CBC encrypt with PKCS#7 padding.
Returns number of ciphertext bytes written, or error.
```zig
pub fn cbc128Encrypt(
```

AES-128-CBC decrypt with PKCS#7 unpadding.
Returns number of plaintext bytes written, or error.
```zig
pub fn cbc128Decrypt(
```

AES-256-CBC encrypt with PKCS#7 padding.
Returns number of ciphertext bytes written, or error.
```zig
pub fn cbc256Encrypt(
```

AES-256-CBC decrypt with PKCS#7 unpadding.
Returns number of plaintext bytes written, or error.
```zig
pub fn cbc256Decrypt(
```

AES-256-CBC encrypt without padding (raw blocks).
Input must be a multiple of 16 bytes.
Used by CTAP2 PIN protocol (zero IV, pre-padded data).
```zig
pub fn cbc256EncryptRaw(
```

AES-256-CBC decrypt without unpadding (raw blocks).
Input must be a multiple of 16 bytes.
Used by CTAP2 PIN protocol (zero IV, no padding).
```zig
pub fn cbc256DecryptRaw(
```


### `ecdh.zig`

P-256 key pair for ECDH key agreement.
```zig
pub const KeyPair = struct {
```

Generate an ephemeral P-256 ECDH key pair.
```zig
pub fn generateKeyPair() !KeyPair {
```

Compute ECDH shared secret: SHA-256(x-coordinate of d * Q).
This matches CTAP2 PIN protocol v2 shared secret derivation.

peer_x, peer_y: affine coordinates of the peer's P-256 public key.
scalar: our 32-byte scalar.
```zig
pub fn deriveSharedSecret(
```


### `ed25519.zig`

Ed25519 key pair.
```zig
pub const KeyPair = struct {
```

Generate a new Ed25519 key pair from random seed.
```zig
pub fn generateKeyPair() KeyPair {
```

Derive Ed25519 key pair from a 32-byte seed.
Used by Sparkle for deriving public key from stored seed.
```zig
pub fn fromSeed(seed: *const [seed_length]u8) !KeyPair {
```

Sign a message with Ed25519.
```zig
pub fn sign(
```

Verify an Ed25519 signature.
```zig
pub fn verify(
```


### `hmac.zig`

Compute HMAC-SHA-256 of a message with the given key.
```zig
pub fn hmacSha256(key: []const u8, data: []const u8) [mac_length]u8 {
```


### `pbkdf2.zig`

PBKDF2 with HMAC-SHA1 as the PRF.
Derives `out.len` bytes of key material.
```zig
pub fn pbkdf2Sha1(
```


### `random.zig`

Fill a buffer with cryptographically secure random bytes.
Uses the OS-provided CSPRNG (getrandom on Linux, getentropy on macOS).
```zig
pub fn fill(buf: []u8) !void {
```


### `sha256.zig`

Compute SHA-256 hash of arbitrary input.
```zig
pub fn hash(data: []const u8) [digest_length]u8 {
```

Incremental SHA-256 hasher for streaming input.
```zig
pub const Hasher = struct {
```

```zig
pub fn init() Hasher {
```

```zig
pub fn update(self: *Hasher, data: []const u8) void {
```

```zig
pub fn final(self: *Hasher) [digest_length]u8 {
```

