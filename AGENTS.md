# AGENTS.md -- zig-crypto

## Persona

You are working on zig-crypto, a portable cryptographic primitives library written in Zig with a stable C FFI surface. It provides SHA-256, HMAC-SHA-256, AES-CBC, PBKDF2, ECDH P-256, Ed25519, and CSPRNG -- all backed by Zig's `std.crypto` with zero external dependencies. Part of the Tinyland Zig Libraries.

zig-crypto is the pure-Zig crypto proof for the Tinyland de-attestation FFI pattern: small native libraries with documented C ABI contracts that keep application code portable across macOS and Linux without binding core behavior to one ecosystem framework. Public copy should make the Apple analogs concrete: this repo parallels CryptoKit SHA/HMAC/P-256/Curve25519.Signing primitives for SwiftUI, UIKit, AppKit, Cocoa, and Objective-C applications.

It separately parallels CommonCrypto AES-CBC/PBKDF2-era calls and Security.framework random-byte calls. Keep public claims scoped to the verified crypto surface unless sibling repos have been audited separately.

## Stack

- **Language:** Zig 0.15.2+
- **Output:** Static C library (`libzig-crypto.a`) + Zig module
- **Dependencies:** None (pure `std.crypto`)
- **Header:** `include/zig_crypto.h` (17 C FFI functions)
- **Tests:** Unit tests per module + property-based tests (1000 iterations) in `tests/`
- **Docs:** MkDocs Material + Zig autodoc (`zig build docs`)

## Structure

```
src/root.zig         Zig package API root
src/ffi.zig          C FFI exports (17 functions)
src/sha256.zig       SHA-256 hash
src/hmac.zig         HMAC-SHA-256
src/aes.zig          AES-128/256-CBC (PKCS#7 and raw)
src/pbkdf2.zig       PBKDF2-SHA1
src/ecdh.zig         ECDH P-256
src/ed25519.zig      Ed25519 signing
src/random.zig       CSPRNG
include/zig_crypto.h C header
tests/pbt_*.zig      Property-based tests
examples/            C usage examples
```

## Commands

```bash
zig build                              # static library -> zig-out/lib/
zig build -Doptimize=ReleaseFast       # optimized build
zig build test                         # unit tests
zig build test-pbt                     # property-based tests
zig build docs                         # generate API documentation
zig build example                      # build and run C example
```

## Style

- Format with `zig fmt`
- All `pub` and `export` functions require `///` doc comments
- C FFI exports live exclusively in `src/ffi.zig`
- Module implementations in `src/<module>.zig`, one file per primitive
- Property-based tests in `tests/pbt_<module>.zig`
- Error convention: return `0` on success, `-1` on failure; data-length returns use byte count on success, negative on error

## Boundaries

- **Do not** introduce OpenSSL, BoringSSL, CommonCrypto, or any C crypto dependency
- **Do not** add allocator-dependent APIs to the FFI surface (all buffers are caller-provided)
- **Do not** add runtime-configurable algorithm selection -- each function is a specific algorithm
- **Do not** claim Swift/ObjC parity without naming the current gaps: SwiftPM/modulemap packaging, Swift convenience wrappers, Objective-C samples/nullability, error bridging, CommonCrypto-compatible aliases, CryptoKit `SharedSecret`/HKDF/key-type parity, CryptoKit AES-GCM/key-wrap parity, and streaming C contexts
- **Do** keep the library stateless and thread-safe
- **Do** ensure all new primitives have both unit tests and property-based tests
- **Do** turn Apple interop gaps into small good-first issues when they do not change cryptographic behavior

## C FFI Exports (zig_crypto.h)

| Function | Return | Description |
|----------|--------|-------------|
| `zig_crypto_sha256` | `void` | SHA-256 hash (out: 32 bytes) |
| `zig_crypto_sha256_hex` | `size_t` | SHA-256 as hex (out: 64 bytes) |
| `zig_crypto_hmac_sha256` | `void` | HMAC-SHA-256 (out: 32 bytes) |
| `zig_crypto_aes128_cbc_encrypt` | `int` | AES-128-CBC encrypt, PKCS#7 |
| `zig_crypto_aes128_cbc_decrypt` | `int` | AES-128-CBC decrypt, PKCS#7 |
| `zig_crypto_aes256_cbc_encrypt` | `int` | AES-256-CBC encrypt, PKCS#7 |
| `zig_crypto_aes256_cbc_decrypt` | `int` | AES-256-CBC decrypt, PKCS#7 |
| `zig_crypto_aes256_cbc_encrypt_raw` | `int` | AES-256-CBC no padding (CTAP2) |
| `zig_crypto_aes256_cbc_decrypt_raw` | `int` | AES-256-CBC no unpadding (CTAP2) |
| `zig_crypto_pbkdf2_sha1` | `void` | PBKDF2-HMAC-SHA1 key derivation |
| `zig_crypto_p256_generate` | `int` | Generate P-256 key pair |
| `zig_crypto_p256_ecdh` | `int` | ECDH shared secret |
| `zig_crypto_ed25519_generate` | `void` | Generate Ed25519 key pair |
| `zig_crypto_ed25519_from_seed` | `int` | Deterministic key from seed |
| `zig_crypto_ed25519_sign` | `int` | Sign message (sig: 64 bytes) |
| `zig_crypto_ed25519_verify` | `bool` | Verify signature |
| `zig_crypto_random` | `bool` | Secure random bytes |

## Size Constants

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
