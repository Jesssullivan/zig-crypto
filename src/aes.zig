const std = @import("std");

pub const block_length = 16;

/// AES-128-CBC encrypt with PKCS#7 padding.
/// Returns number of ciphertext bytes written, or error.
pub fn cbcEncrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    plaintext: []const u8,
    out: []u8,
) !usize {
    const padded_len = ((plaintext.len / block_length) + 1) * block_length;
    if (out.len < padded_len) return error.BufferTooSmall;

    // PKCS#7 pad into a working buffer
    var padded: [4096 + block_length]u8 = undefined;
    if (padded_len > padded.len) return error.InputTooLarge;
    @memcpy(padded[0..plaintext.len], plaintext);
    const pad_byte: u8 = @intCast(padded_len - plaintext.len);
    @memset(padded[plaintext.len..padded_len], pad_byte);

    const ctx = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128).init(key.*);

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

/// AES-128-CBC decrypt with PKCS#7 unpadding.
/// Returns number of plaintext bytes written, or error.
pub fn cbcDecrypt(
    key: *const [16]u8,
    iv: *const [16]u8,
    ciphertext: []const u8,
    out: []u8,
) !usize {
    if (ciphertext.len == 0 or ciphertext.len % block_length != 0) return error.InvalidCiphertext;
    if (out.len < ciphertext.len) return error.BufferTooSmall;

    const ctx = std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes128).init(key.*);

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

// ── Tests ───────────────────────────────────────────────────────────────

test "AES-128-CBC round-trip" {
    const key = [_]u8{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const iv = [_]u8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const plaintext = "Hello, AES-128-CBC!";

    var ciphertext: [48]u8 = undefined;
    const ct_len = try cbcEncrypt(&key, &iv, plaintext, &ciphertext);

    var decrypted: [48]u8 = undefined;
    const pt_len = try cbcDecrypt(&key, &iv, ciphertext[0..ct_len], &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "AES-128-CBC block-aligned input" {
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 16;
    // Exactly 16 bytes — PKCS#7 adds a full padding block
    const plaintext = "0123456789abcdef";

    var ciphertext: [48]u8 = undefined;
    const ct_len = try cbcEncrypt(&key, &iv, plaintext, &ciphertext);
    try std.testing.expectEqual(@as(usize, 32), ct_len); // 16 + 16 padding

    var decrypted: [48]u8 = undefined;
    const pt_len = try cbcDecrypt(&key, &iv, ciphertext[0..ct_len], &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}
