# AGENTS.md

Instructions for AI agents working with this codebase.

## Project

zig-crypto provides portable cryptographic primitives in Zig with a stable C FFI. It is the crypto proof for the Tinyland Zig Libraries pattern: small Zig implementations behind documented ABI contracts. In planning language, this supports the de-attestation effort; public claims should stay scoped to the verified crypto surface and should name the concrete Apple analogs: CryptoKit SHA/HMAC/P-256/Curve25519.Signing primitives for SwiftUI, UIKit, AppKit, Cocoa, and Objective-C applications.

CommonCrypto AES-CBC/PBKDF2-era calls and Security.framework random bytes are separate analogs.

## Build

```bash
zig build -Doptimize=ReleaseFast    # static library
zig build test                       # unit tests
zig build test-pbt                   # property-based tests
zig build example                    # build and run C example
```

## Structure

- `include/zig_crypto.h` -- Public C API header
- `src/root.zig` -- Zig package API root
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
