const std = @import("std");
const sha256 = @import("sha256.zig");
const hmac = @import("hmac.zig");
const aes = @import("aes.zig");
const pbkdf2 = @import("pbkdf2.zig");
const random = @import("random.zig");

// ── SHA-256 ─────────────────────────────────────────────────────────────

export fn zig_crypto_sha256(
    data: [*]const u8,
    data_len: usize,
    out: [*]u8,
) void {
    const result = sha256.hash(data[0..data_len]);
    @memcpy(out[0..sha256.digest_length], &result);
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
    const ct_len = aes.cbcEncrypt(key, iv, plaintext[0..plaintext_len], out[0 .. plaintext_len + aes.block_length]) catch return -1;
    return @intCast(ct_len);
}

export fn zig_crypto_aes128_cbc_decrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    out: [*]u8,
) c_int {
    const pt_len = aes.cbcDecrypt(key, iv, ciphertext[0..ciphertext_len], out[0..ciphertext_len]) catch return -1;
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

// ── CSPRNG ──────────────────────────────────────────────────────────────

export fn zig_crypto_random(buf: [*]u8, len: usize) bool {
    random.fill(buf[0..len]) catch return false;
    return true;
}
