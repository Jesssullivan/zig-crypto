//! Zig package API for zig-crypto.
//!
//! The C ABI surface lives in `ffi.zig`. Zig consumers should import this
//! root module and use the primitive modules directly.

/// AES-128/256-CBC helpers.
pub const aes = @import("aes.zig");

/// ECDH P-256 key agreement.
pub const ecdh = @import("ecdh.zig");

/// Ed25519 key generation, signing, and verification.
pub const ed25519 = @import("ed25519.zig");

/// HMAC-SHA-256 message authentication.
pub const hmac = @import("hmac.zig");

/// PBKDF2-HMAC-SHA1 key derivation.
pub const pbkdf2 = @import("pbkdf2.zig");

/// OS-backed cryptographically secure random bytes.
pub const random = @import("random.zig");

/// SHA-256 hashing.
pub const sha256 = @import("sha256.zig");
