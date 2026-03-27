const std = @import("std");

/// Fill a buffer with cryptographically secure random bytes.
/// Uses the OS-provided CSPRNG (getrandom on Linux, getentropy on macOS).
pub fn fill(buf: []u8) !void {
    std.crypto.random.bytes(buf);
}

// ── Tests ───────────────────────────────────────────────────────────────

test "CSPRNG fills buffer with non-zero bytes" {
    var buf = [_]u8{0} ** 32;
    try fill(&buf);

    // Extremely unlikely that 32 random bytes are all zero
    var all_zero = true;
    for (buf) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "CSPRNG produces different outputs" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    try fill(&buf1);
    try fill(&buf2);

    // Two random 32-byte values should differ
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}
