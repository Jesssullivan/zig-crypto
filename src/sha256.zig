const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const digest_length = Sha256.digest_length; // 32
pub const block_length = Sha256.block_length; // 64

/// Compute SHA-256 hash of arbitrary input.
pub fn hash(data: []const u8) [digest_length]u8 {
    var out: [digest_length]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// Incremental SHA-256 hasher for streaming input.
pub const Hasher = struct {
    inner: Sha256,

    pub fn init() Hasher {
        return .{ .inner = Sha256.init(.{}) };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        self.inner.update(data);
    }

    pub fn final(self: *Hasher) [digest_length]u8 {
        return self.inner.finalResult();
    }
};

// ── Tests ───────────────────────────────────────────────────────────────

test "SHA-256 empty string" {
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    const result = hash("");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "SHA-256 'abc'" {
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    const result = hash("abc");
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "SHA-256 incremental matches single-shot" {
    const data = "The quick brown fox jumps over the lazy dog";
    const single = hash(data);

    var h = Hasher.init();
    h.update(data[0..10]);
    h.update(data[10..]);
    const incremental = h.final();

    try std.testing.expectEqualSlices(u8, &single, &incremental);
}
