const std = @import("std");
const ecdh = @import("ecdh");

/// Generate an ECDH key pair from PRNG bytes (for deterministic PBT).
/// Mirrors the logic in ecdh.generateKeyPair() but uses a seeded PRNG
/// instead of std.crypto.random.
fn keyPairFromPrng(random: std.Random) !ecdh.KeyPair {
    const P256 = std.crypto.ecc.P256;
    for (0..64) |_| {
        var scalar: [ecdh.key_length]u8 = undefined;
        random.bytes(&scalar);
        const q = P256.basePoint.mul(scalar, .big) catch continue;
        const affine = q.affineCoordinates();
        return .{
            .scalar = scalar,
            .public_x = affine.x.toBytes(.big),
            .public_y = affine.y.toBytes(.big),
        };
    }
    return error.KeyGenFailed;
}

test "PBT: ECDH P-256 shared secret is symmetric" {
    var prng = std.Random.DefaultPrng.init(0xEC0D_5A01);
    const random = prng.random();

    for (0..200) |_| {
        const alice = try keyPairFromPrng(random);
        const bob = try keyPairFromPrng(random);

        const secret_ab = try ecdh.deriveSharedSecret(&alice.scalar, &bob.public_x, &bob.public_y);
        const secret_ba = try ecdh.deriveSharedSecret(&bob.scalar, &alice.public_x, &alice.public_y);

        try std.testing.expectEqualSlices(u8, &secret_ab, &secret_ba);
    }
}

test "PBT: ECDH P-256 different key pairs produce different shared secrets" {
    var prng = std.Random.DefaultPrng.init(0xEC0D_D1FF);
    const random = prng.random();

    var distinct_count: usize = 0;

    for (0..200) |_| {
        const alice = try keyPairFromPrng(random);
        const bob = try keyPairFromPrng(random);
        const charlie = try keyPairFromPrng(random);

        const ab = try ecdh.deriveSharedSecret(&alice.scalar, &bob.public_x, &bob.public_y);
        const ac = try ecdh.deriveSharedSecret(&alice.scalar, &charlie.public_x, &charlie.public_y);

        if (!std.mem.eql(u8, &ab, &ac)) {
            distinct_count += 1;
        }
    }

    // Collision probability for SHA-256(ECDH) is negligible; all 200 should differ.
    try std.testing.expect(distinct_count == 200);
}
