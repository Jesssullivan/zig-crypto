# AGENTS.md

Instructions for AI agents working with this codebase.

## Project

zig-crypto provides portable cryptographic primitives in Zig with a C FFI. Used by zig-ctap2 for FIDO2 PIN protocol v2.

## Build

```bash
zig build -Doptimize=ReleaseFast    # static library
zig build test                       # unit tests
zig build test-pbt                   # property-based tests
```

## Structure

- `include/zig_crypto.h` -- Public C API header
- `src/ffi.zig` -- C FFI export layer
- `src/sha256.zig` -- SHA-256 hash
- `src/hmac.zig` -- HMAC-SHA-256
- `src/aes.zig` -- AES-128/256-CBC (PKCS#7 and raw variants)
- `src/pbkdf2.zig` -- PBKDF2-SHA1 key derivation
- `src/ecdh.zig` -- ECDH P-256 key agreement
- `src/ed25519.zig` -- Ed25519 signatures
- `src/random.zig` -- CSPRNG wrapper

## Conventions

- C exports use `snake_case` with `zig_crypto_` prefix
- Zig internals use `camelCase`
- All crypto is pure Zig (Zig stdlib), no platform deps except CSPRNG
- Return values: 0 = success, -1 = failure (for functions returning c_int)
- Output is written to caller-provided buffers with documented minimum sizes
