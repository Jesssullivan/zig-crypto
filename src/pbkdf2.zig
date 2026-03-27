const std = @import("std");
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

/// PBKDF2 with HMAC-SHA1 as the PRF.
/// Derives `out.len` bytes of key material.
pub fn pbkdf2Sha1(
    passphrase: []const u8,
    salt: []const u8,
    iterations: u32,
    out: []u8,
) void {
    const h_len = HmacSha1.mac_length; // 20
    var block_num: u32 = 1;
    var offset: usize = 0;

    while (offset < out.len) : (block_num += 1) {
        var u_prev: [h_len]u8 = undefined;

        // U_1 = PRF(passphrase, salt || INT_32_BE(block_num))
        var mac = HmacSha1.init(passphrase);
        mac.update(salt);
        const be_block = std.mem.nativeToBig(u32, block_num);
        mac.update(std.mem.asBytes(&be_block));
        mac.final(&u_prev);

        var t: [h_len]u8 = u_prev;

        // U_2 .. U_c
        for (1..iterations) |_| {
            var u_next: [h_len]u8 = undefined;
            HmacSha1.create(&u_next, &u_prev, passphrase);
            for (0..h_len) |i| {
                t[i] ^= u_next[i];
            }
            u_prev = u_next;
        }

        // Copy derived bytes
        const remaining = out.len - offset;
        const copy_len = @min(h_len, remaining);
        @memcpy(out[offset..][0..copy_len], t[0..copy_len]);
        offset += copy_len;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

test "PBKDF2-SHA1 RFC 6070 test case 1" {
    // RFC 6070: passphrase="password", salt="salt", c=1, dkLen=20
    var out: [20]u8 = undefined;
    pbkdf2Sha1("password", "salt", 1, &out);
    const expected = [_]u8{
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
        0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
        0x2f, 0xe0, 0x37, 0xa6,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "PBKDF2-SHA1 RFC 6070 test case 2" {
    // RFC 6070: passphrase="password", salt="salt", c=2, dkLen=20
    var out: [20]u8 = undefined;
    pbkdf2Sha1("password", "salt", 2, &out);
    const expected = [_]u8{
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
        0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
        0xd8, 0xde, 0x89, 0x57,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "PBKDF2-SHA1 RFC 6070 test case 3" {
    // RFC 6070: passphrase="password", salt="salt", c=4096, dkLen=20
    var out: [20]u8 = undefined;
    pbkdf2Sha1("password", "salt", 4096, &out);
    const expected = [_]u8{
        0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
        0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
        0x65, 0xa4, 0x29, 0xc1,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}
