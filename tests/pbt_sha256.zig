const std = @import("std");
const sha256 = @import("sha256");

test "PBT: SHA-256 always produces 32 bytes" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const random = prng.random();

    for (0..1000) |_| {
        const len = random.intRangeAtMost(usize, 0, 512);
        var buf: [512]u8 = undefined;
        random.bytes(buf[0..len]);
        const digest = sha256.hash(buf[0..len]);
        try std.testing.expectEqual(@as(usize, 32), digest.len);
    }
}

test "PBT: SHA-256 is deterministic" {
    var prng = std.Random.DefaultPrng.init(0xCAFEBABE);
    const random = prng.random();

    for (0..1000) |_| {
        const len = random.intRangeAtMost(usize, 0, 256);
        var buf: [256]u8 = undefined;
        random.bytes(buf[0..len]);

        const d1 = sha256.hash(buf[0..len]);
        const d2 = sha256.hash(buf[0..len]);
        try std.testing.expectEqualSlices(u8, &d1, &d2);
    }
}

test "PBT: SHA-256 incremental matches single-shot" {
    var prng = std.Random.DefaultPrng.init(0xF00DBABE);
    const random = prng.random();

    for (0..500) |_| {
        const len = random.intRangeAtMost(usize, 1, 512);
        var buf: [512]u8 = undefined;
        random.bytes(buf[0..len]);

        const single = sha256.hash(buf[0..len]);

        // Split at random point
        const split = random.intRangeAtMost(usize, 0, len);
        var h = sha256.Hasher.init();
        h.update(buf[0..split]);
        h.update(buf[split..len]);
        const incremental = h.final();

        try std.testing.expectEqualSlices(u8, &single, &incremental);
    }
}
