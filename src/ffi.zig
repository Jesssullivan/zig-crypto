const std = @import("std");
const sha256 = @import("sha256.zig");
const hmac = @import("hmac.zig");
const aes = @import("aes.zig");
const pbkdf2 = @import("pbkdf2.zig");
const random = @import("random.zig");
const ecdh = @import("ecdh.zig");
const ed25519 = @import("ed25519.zig");

// ── SHA-256 ─────────────────────────────────────────────────────────────

export fn zig_crypto_sha256(
    data: [*]const u8,
    data_len: usize,
    out: [*]u8,
) void {
    const result = sha256.hash(data[0..data_len]);
    @memcpy(out[0..sha256.digest_length], &result);
}

/// SHA-256 with hex string output. Returns number of hex chars written (64).
export fn zig_crypto_sha256_hex(
    data: [*]const u8,
    data_len: usize,
    out: [*]u8,
) usize {
    const digest = sha256.hash(data[0..data_len]);
    const hex_chars = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        out[i * 2] = hex_chars[byte >> 4];
        out[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return 64;
}

// ── HMAC-SHA-256 ────────────────────────────────────────────────────────

export fn zig_crypto_hmac_sha256(
    key: [*]const u8,
    key_len: usize,
    data: [*]const u8,
    data_len: usize,
    out: [*]u8,
) void {
    const result = hmac.hmacSha256(key[0..key_len], data[0..data_len]);
    @memcpy(out[0..hmac.mac_length], &result);
}

// ── AES-128-CBC ─────────────────────────────────────────────────────────

export fn zig_crypto_aes128_cbc_encrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    out: [*]u8,
) c_int {
    const ct_len = aes.cbc128Encrypt(key, iv, plaintext[0..plaintext_len], out[0 .. plaintext_len + aes.block_length]) catch return -1;
    return @intCast(ct_len);
}

export fn zig_crypto_aes128_cbc_decrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    out: [*]u8,
) c_int {
    const pt_len = aes.cbc128Decrypt(key, iv, ciphertext[0..ciphertext_len], out[0..ciphertext_len]) catch return -1;
    return @intCast(pt_len);
}

// ── AES-256-CBC ─────────────────────────────────────────────────────────

export fn zig_crypto_aes256_cbc_encrypt(
    key: *const [32]u8,
    iv: *const [16]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    out: [*]u8,
) c_int {
    const ct_len = aes.cbc256Encrypt(key, iv, plaintext[0..plaintext_len], out[0 .. plaintext_len + aes.block_length]) catch return -1;
    return @intCast(ct_len);
}

export fn zig_crypto_aes256_cbc_decrypt(
    key: *const [32]u8,
    iv: *const [16]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    out: [*]u8,
) c_int {
    const pt_len = aes.cbc256Decrypt(key, iv, ciphertext[0..ciphertext_len], out[0..ciphertext_len]) catch return -1;
    return @intCast(pt_len);
}

/// AES-256-CBC raw (no padding). For CTAP2 PIN protocol.
export fn zig_crypto_aes256_cbc_encrypt_raw(
    key: *const [32]u8,
    iv: *const [16]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    out: [*]u8,
) c_int {
    const ct_len = aes.cbc256EncryptRaw(key, iv, plaintext[0..plaintext_len], out[0..plaintext_len]) catch return -1;
    return @intCast(ct_len);
}

export fn zig_crypto_aes256_cbc_decrypt_raw(
    key: *const [32]u8,
    iv: *const [16]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    out: [*]u8,
) c_int {
    const pt_len = aes.cbc256DecryptRaw(key, iv, ciphertext[0..ciphertext_len], out[0..ciphertext_len]) catch return -1;
    return @intCast(pt_len);
}

// ── PBKDF2-SHA1 ─────────────────────────────────────────────────────────

export fn zig_crypto_pbkdf2_sha1(
    passphrase: [*]const u8,
    passphrase_len: usize,
    salt: [*]const u8,
    salt_len: usize,
    iterations: u32,
    out: [*]u8,
    out_len: usize,
) void {
    pbkdf2.pbkdf2Sha1(
        passphrase[0..passphrase_len],
        salt[0..salt_len],
        iterations,
        out[0..out_len],
    );
}

// ── ECDH P-256 ──────────────────────────────────────────────────────────

/// Generate P-256 key pair. Writes 32 bytes each to private, pub_x, pub_y.
/// Returns 0 on success, -1 on failure.
export fn zig_crypto_p256_generate(
    out_scalar: [*]u8,
    out_pub_x: [*]u8,
    out_pub_y: [*]u8,
) c_int {
    const kp = ecdh.generateKeyPair() catch return -1;
    @memcpy(out_scalar[0..32], &kp.scalar);
    @memcpy(out_pub_x[0..32], &kp.public_x);
    @memcpy(out_pub_y[0..32], &kp.public_y);
    return 0;
}

/// ECDH shared secret: SHA-256(x-coordinate of d * Q).
/// Returns 0 on success, -1 on failure.
export fn zig_crypto_p256_ecdh(
    scalar: *const [32]u8,
    peer_x: *const [32]u8,
    peer_y: *const [32]u8,
    out_shared_secret: [*]u8,
) c_int {
    const secret = ecdh.deriveSharedSecret(scalar, peer_x, peer_y) catch return -1;
    @memcpy(out_shared_secret[0..32], &secret);
    return 0;
}

// ── Ed25519 ─────────────────────────────────────────────────────────────

/// Generate Ed25519 key pair. Writes seed(32), public(32), secret(64).
export fn zig_crypto_ed25519_generate(
    out_seed: [*]u8,
    out_public: [*]u8,
    out_secret: [*]u8,
) void {
    const kp = ed25519.generateKeyPair();
    @memcpy(out_seed[0..32], &kp.seed);
    @memcpy(out_public[0..32], &kp.public_key);
    @memcpy(out_secret[0..64], &kp.signing_key);
}

/// Derive Ed25519 key pair from 32-byte seed. Returns 0 on success, -1 on failure.
export fn zig_crypto_ed25519_from_seed(
    seed: *const [32]u8,
    out_public: [*]u8,
    out_secret: [*]u8,
) c_int {
    const kp = ed25519.fromSeed(seed) catch return -1;
    @memcpy(out_public[0..32], &kp.public_key);
    @memcpy(out_secret[0..64], &kp.signing_key);
    return 0;
}

/// Sign a message. Writes 64-byte signature. Returns 0 on success, -1 on failure.
export fn zig_crypto_ed25519_sign(
    message: [*]const u8,
    message_len: usize,
    signing_key: *const [64]u8,
    out_signature: [*]u8,
) c_int {
    const sig = ed25519.sign(message[0..message_len], signing_key) catch return -1;
    @memcpy(out_signature[0..64], &sig);
    return 0;
}

/// Verify an Ed25519 signature. Returns true if valid.
export fn zig_crypto_ed25519_verify(
    message: [*]const u8,
    message_len: usize,
    signature: *const [64]u8,
    public_key: *const [32]u8,
) bool {
    return ed25519.verify(message[0..message_len], signature, public_key);
}

// ── CSPRNG ──────────────────────────────────────────────────────────────

export fn zig_crypto_random(buf: [*]u8, len: usize) bool {
    random.fill(buf[0..len]) catch return false;
    return true;
}
