const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const mac_length = HmacSha256.mac_length; // 32

/// Compute HMAC-SHA-256 of a message with the given key.
pub fn hmacSha256(key: []const u8, data: []const u8) [mac_length]u8 {
    var out: [mac_length]u8 = undefined;
    HmacSha256.create(&out, data, key);
    return out;
}

// ── Tests ───────────────────────────────────────────────────────────────

test "HMAC-SHA-256 RFC 4231 test case 1" {
    // Key = 0x0b repeated 20 times, Data = "Hi There"
    const key = [_]u8{0x0b} ** 20;
    const data = "Hi There";
    const expected = [_]u8{
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    const result = hmacSha256(&key, data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "HMAC-SHA-256 RFC 4231 test case 2" {
    // Key = "Jefe", Data = "what do ya want for nothing?"
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    const expected = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    const result = hmacSha256(key, data);
    try std.testing.expectEqualSlices(u8, &expected, &result);
}
