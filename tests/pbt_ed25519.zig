const std = @import("std");
const ed25519 = @import("ed25519");

test "PBT: Ed25519 sign/verify round-trip with random messages" {
    var prng = std.Random.DefaultPrng.init(0xED25_5191);
    const random = prng.random();

    for (0..500) |_| {
        // Generate key pair from random seed
        var seed: [ed25519.seed_length]u8 = undefined;
        random.bytes(&seed);
        const kp = try ed25519.fromSeed(&seed);

        // Random message of variable length 0..512
        const msg_len = random.intRangeAtMost(usize, 0, 512);
        var msg_buf: [512]u8 = undefined;
        random.bytes(msg_buf[0..msg_len]);

        const sig = try ed25519.sign(msg_buf[0..msg_len], &kp.signing_key);
        try std.testing.expect(ed25519.verify(msg_buf[0..msg_len], &sig, &kp.public_key));
    }
}

test "PBT: Ed25519 verification rejects corrupted messages" {
    var prng = std.Random.DefaultPrng.init(0xED25_BAD0);
    const random = prng.random();

    for (0..500) |_| {
        // Generate key pair from random seed
        var seed: [ed25519.seed_length]u8 = undefined;
        random.bytes(&seed);
        const kp = try ed25519.fromSeed(&seed);

        // Random message of length 1..512 (need at least 1 byte to corrupt)
        const msg_len = random.intRangeAtMost(usize, 1, 512);
        var msg_buf: [512]u8 = undefined;
        random.bytes(msg_buf[0..msg_len]);

        const sig = try ed25519.sign(msg_buf[0..msg_len], &kp.signing_key);

        // Corrupt one random byte in the message
        var corrupted: [512]u8 = undefined;
        @memcpy(corrupted[0..msg_len], msg_buf[0..msg_len]);
        const flip_idx = random.intRangeLessThan(usize, 0, msg_len);
        corrupted[flip_idx] ^= (random.intRangeAtMost(u8, 1, 255)); // non-zero XOR

        try std.testing.expect(!ed25519.verify(corrupted[0..msg_len], &sig, &kp.public_key));
    }
}

test "PBT: Ed25519 fromSeed is deterministic" {
    var prng = std.Random.DefaultPrng.init(0xED25_5EED);
    const random = prng.random();

    for (0..200) |_| {
        var seed: [ed25519.seed_length]u8 = undefined;
        random.bytes(&seed);

        const kp1 = try ed25519.fromSeed(&seed);
        const kp2 = try ed25519.fromSeed(&seed);

        try std.testing.expectEqualSlices(u8, &kp1.public_key, &kp2.public_key);
        try std.testing.expectEqualSlices(u8, &kp1.signing_key, &kp2.signing_key);
        try std.testing.expectEqualSlices(u8, &kp1.seed, &kp2.seed);
    }
}
