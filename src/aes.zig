const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

pub const block_length = 16;

// ── AES-128-CBC ─────────────────────────────────────────────────────────

/// AES-128-CBC encrypt with PKCS#7 padding.
/// Returns number of ciphertext bytes written, or error.
pub fn cbc128Encrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    return cbcEncryptGeneric(Aes128, key, iv, plaintext, out);
}

/// AES-128-CBC decrypt with PKCS#7 unpadding.
/// Returns number of plaintext bytes written, or error.
pub fn cbc128Decrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    return cbcDecryptGeneric(Aes128, key, iv, ciphertext, out);
}

// ── AES-256-CBC ─────────────────────────────────────────────────────────

/// AES-256-CBC encrypt with PKCS#7 padding.
/// Returns number of ciphertext bytes written, or error.
pub fn cbc256Encrypt(
    key: *const [32]u8,
    iv: *const [16]u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    return cbcEncryptGeneric(Aes256, key, iv, plaintext, out);
}

/// AES-256-CBC decrypt with PKCS#7 unpadding.
/// Returns number of plaintext bytes written, or error.
pub fn cbc256Decrypt(
    key: *const [32]u8,
    iv: *const [16]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    return cbcDecryptGeneric(Aes256, key, iv, ciphertext, out);
}

/// AES-256-CBC encrypt without padding (raw blocks).
/// Input must be a multiple of 16 bytes.
/// Used by CTAP2 PIN protocol (zero IV, pre-padded data).
pub fn cbc256EncryptRaw(
    key: *const [32]u8,
    iv: *const [16]u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    if (plaintext.len == 0 or plaintext.len % block_length != 0) return error.InvalidPlaintext;
    if (out.len < plaintext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.AesEncryptCtx(Aes256).init(key.*);
    var prev_block: [block_length]u8 = iv.*;
    var offset: usize = 0;
    while (offset < plaintext.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |i| {
            block[i] = plaintext[offset + i] ^ prev_block[i];
        }
        ctx.encrypt(&block, &block);
        @memcpy(out[offset..][0..block_length], &block);
        prev_block = block;
    }
    return plaintext.len;
}

/// AES-256-CBC decrypt without unpadding (raw blocks).
/// Input must be a multiple of 16 bytes.
/// Used by CTAP2 PIN protocol (zero IV, no padding).
pub fn cbc256DecryptRaw(
    key: *const [32]u8,
    iv: *const [16]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (ciphertext.len == 0 or ciphertext.len % block_length != 0) return error.InvalidCiphertext;
    if (out.len < ciphertext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.AesDecryptCtx(Aes256).init(key.*);
    var prev_block: [block_length]u8 = iv.*;
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        const ct_block = ciphertext[offset..][0..block_length];
        ctx.decrypt(&block, ct_block);
        for (0..block_length) |i| {
            out[offset + i] = block[i] ^ prev_block[i];
        }
        prev_block = ct_block.*;
    }
    return ciphertext.len;
}

// ── Generic CBC implementation ──────────────────────────────────────────

fn cbcEncryptGeneric(
    comptime AesType: type,
    key: *const [AesType.key_bits / 8]u8,
    iv: *const [16]u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    const padded_len = ((plaintext.len / block_length) + 1) * block_length;
    if (out.len < padded_len) return error.BufferTooSmall;

    var padded: [4096 + block_length]u8 = undefined;
    if (padded_len > padded.len) return error.InputTooLarge;
    @memcpy(padded[0..plaintext.len], plaintext);
    const pad_byte: u8 = @intCast(padded_len - plaintext.len);
    @memset(padded[plaintext.len..padded_len], pad_byte);

    const ctx = std.crypto.core.aes.AesEncryptCtx(AesType).init(key.*);

    var prev_block: [block_length]u8 = iv.*;
    var offset: usize = 0;
    while (offset < padded_len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |i| {
            block[i] = padded[offset + i] ^ prev_block[i];
        }
        ctx.encrypt(&block, &block);
        @memcpy(out[offset..][0..block_length], &block);
        prev_block = block;
    }

    return padded_len;
}

fn cbcDecryptGeneric(
    comptime AesType: type,
    key: *const [AesType.key_bits / 8]u8,
    iv: *const [16]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (ciphertext.len == 0 or ciphertext.len % block_length != 0) return error.InvalidCiphertext;
    if (out.len < ciphertext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.AesDecryptCtx(AesType).init(key.*);

    var prev_block: [block_length]u8 = iv.*;
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        const ct_block = ciphertext[offset..][0..block_length];
        ctx.decrypt(&block, ct_block);
        for (0..block_length) |i| {
            out[offset + i] = block[i] ^ prev_block[i];
        }
        prev_block = ct_block.*;
    }

    // PKCS#7 unpad
    const pad_byte = out[ciphertext.len - 1];
    if (pad_byte == 0 or pad_byte > block_length) return error.InvalidPadding;
    const pad_start = ciphertext.len - pad_byte;
    for (out[pad_start..ciphertext.len]) |b| {
        if (b != pad_byte) return error.InvalidPadding;
    }

    return pad_start;
}

// Backwards-compatible aliases
pub const cbcEncrypt = cbc128Encrypt;
pub const cbcDecrypt = cbc128Decrypt;

// ── Tests ───────────────────────────────────────────────────────────────

test "AES-128-CBC round-trip" {
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plaintext = "Hello, AES-128-CBC!";

    var ciphertext: [48]u8 = undefined;
    const ct_len = try cbc128Encrypt(&key, &iv, plaintext, &ciphertext);

    var decrypted: [48]u8 = undefined;
    const pt_len = try cbc128Decrypt(&key, &iv, ciphertext[0..ct_len], &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "AES-128-CBC block-aligned input" {
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 16;
    const plaintext = "0123456789abcdef";

    var ciphertext: [48]u8 = undefined;
    const ct_len = try cbc128Encrypt(&key, &iv, plaintext, &ciphertext);
    try std.testing.expectEqual(@as(usize, 32), ct_len);

    var decrypted: [48]u8 = undefined;
    const pt_len = try cbc128Decrypt(&key, &iv, ciphertext[0..ct_len], &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "AES-256-CBC round-trip" {
    const key = [_]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plaintext = "Hello, AES-256-CBC!";

    var ciphertext: [48]u8 = undefined;
    const ct_len = try cbc256Encrypt(&key, &iv, plaintext, &ciphertext);

    var decrypted: [48]u8 = undefined;
    const pt_len = try cbc256Decrypt(&key, &iv, ciphertext[0..ct_len], &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "AES-256-CBC raw mode (zero IV, CTAP2 style)" {
    const key = [_]u8{0xAA} ** 32;
    const iv = [_]u8{0} ** 16; // zero IV per CTAP2 spec
    const plaintext = [_]u8{0x42} ** 32; // 2 blocks, pre-padded

    var ciphertext: [32]u8 = undefined;
    const ct_len = try cbc256EncryptRaw(&key, &iv, &plaintext, &ciphertext);
    try std.testing.expectEqual(@as(usize, 32), ct_len);

    var decrypted: [32]u8 = undefined;
    const pt_len = try cbc256DecryptRaw(&key, &iv, &ciphertext, &decrypted);
    try std.testing.expectEqual(@as(usize, 32), pt_len);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "AES-256-CBC raw rejects non-aligned input" {
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 16;
    const bad_input = [_]u8{0} ** 15; // not a multiple of 16

    var out: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidPlaintext, cbc256EncryptRaw(&key, &iv, &bad_input, &out));
}
