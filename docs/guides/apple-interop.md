# Apple / Swift / Objective-C Interop

zig-crypto does not replace SwiftUI, UIKit, AppKit, or Cocoa application structure. Those layers should stay responsible for presentation, lifecycle, and platform integration. The library replaces the crypto capability calls that a Swift or Objective-C application might otherwise make through Apple-only framework surfaces.

In Tinyland planning, this is the practical de-attestation shape: keep the application developer experience intact, but move native capability contracts behind small C ABI surfaces that can also be built and tested on Linux.

## Truthing Notes

This guide is intentionally conservative:

- CryptoKit is the closest Apple analog for SHA-256, HMAC-SHA-256, P-256 key agreement, and Curve25519/Ed25519-style signing.
- CommonCrypto is the closest Apple analog for AES-CBC and PBKDF2-SHA1 migration. CryptoKit's documented AES surface is GCM and key wrap, not CBC.
- Security.framework is the closest Apple analog for secure random bytes.
- cmux-style downstream usage proves Swift can import the C ABI through module maps and call `zig_crypto_*` functions from Swift, but this repo does not yet ship that Swift packaging itself.

## Available Today

| Apple ecosystem surface | zig-crypto surface | Status |
|-------------------------|--------------------|--------|
| CryptoKit `SHA256`, CommonCrypto `CC_SHA256` | `zig_crypto_sha256`, `zig_crypto_sha256_hex` | Available through C ABI |
| CryptoKit `HMAC<SHA256>`, CommonCrypto `CCHmac` | `zig_crypto_hmac_sha256` | Available through C ABI |
| CommonCrypto `CCCrypt` / `CCCryptor` AES-CBC with PKCS#7 | `zig_crypto_aes128_cbc_encrypt/decrypt`, `zig_crypto_aes256_cbc_encrypt/decrypt` | Available through C ABI |
| CommonCrypto raw AES-CBC block workflows | `zig_crypto_aes256_cbc_encrypt_raw`, `zig_crypto_aes256_cbc_decrypt_raw` | Available for CTAP2-style pre-padded data |
| CommonCrypto `CCKeyDerivationPBKDF` PBKDF2-SHA1 workflows | `zig_crypto_pbkdf2_sha1` | Available through C ABI |
| CryptoKit `P256.KeyAgreement` ECDH primitive | `zig_crypto_p256_generate`, `zig_crypto_p256_ecdh` | Available for the documented CTAP2-style `SHA-256(x-coordinate)` shared secret; not CryptoKit `SharedSecret` / HKDF API parity |
| CryptoKit `Curve25519.Signing` Ed25519-style signing | `zig_crypto_ed25519_generate`, `zig_crypto_ed25519_from_seed`, `zig_crypto_ed25519_sign`, `zig_crypto_ed25519_verify` | Available through C ABI raw key bytes; not CryptoKit key type parity |
| Security.framework `SecRandomCopyBytes` | `zig_crypto_random` | Available through C ABI |

## Not Yet Swift / ObjC Parity

These are gaps in Apple developer experience, not gaps in the verified crypto primitives:

- No SwiftPM target, modulemap, or packaged Swift import path.
- No Swift convenience layer using `Data`, `Array<UInt8>`, or CryptoKit-shaped value types.
- No Objective-C wrapper classes, nullability annotations, or `NSError`-style error bridge.
- No CommonCrypto-compatible symbol names or drop-in CommonCrypto header.
- No C ABI streaming contexts for SHA-256 or HMAC; the C ABI is currently one-shot.
- No CryptoKit `AES.GCM`, `AES.KeyWrap`, `SharedSecret`, HKDF, Secure Enclave, or Swift key-type parity.
- No Security.framework `SecKey`, Keychain Services, UserNotifications, AuthenticationServices, ASAuthorization, or CTAP2 transport surface in this repo.

## Good First Issues

These are intentionally scoped so a contributor can improve the Swift/ObjC story without changing cryptographic behavior:

- Add a SwiftPM/modulemap wrapper that imports `zig_crypto.h` and runs a Swift smoke test for `zig_crypto_sha256`.
- Add an Objective-C command-line sample that links `libzig-crypto.a`, calls SHA-256 and Ed25519 verify, and documents the bridging-header setup.
- Add an Apple crypto migration guide with side-by-side examples for CryptoKit SHA/HMAC.
- Include separate CommonCrypto AES-CBC, CommonCrypto PBKDF2-SHA1, and random-byte examples.
- Add nullability annotations to `include/zig_crypto.h` where they improve Swift/ObjC diagnostics without changing the C ABI.

Larger follow-up work should stay separate from good-first issues: Swift `Data` wrappers, CommonCrypto-compatible aliases, `NSError` bridging, binary/XCFramework packaging, and streaming C contexts all need explicit API design.

## Reference Points

- Apple CryptoKit overview: <https://developer.apple.com/documentation/cryptokit/>
- CryptoKit SHA-256: <https://developer.apple.com/documentation/cryptokit/sha256>
- CryptoKit AES modes: <https://developer.apple.com/documentation/cryptokit/aes>
- CryptoKit P-256 key agreement: <https://developer.apple.com/documentation/cryptokit/p256/keyagreement>
- CryptoKit Curve25519 signing: <https://developer.apple.com/documentation/cryptokit/curve25519>
- Security.framework random bytes: <https://developer.apple.com/documentation/security/secrandomcopybytes(_:_:_:)>
- CommonCrypto manual page: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/Common%20Crypto.3cc.html>
- Swift imported C functions: <https://developer.apple.com/documentation/swift/using-imported-c-functions-in-swift>
- Improving Objective-C declarations for Swift: <https://developer.apple.com/documentation/swift/improving-objective-c-api-declarations-for-swift>
