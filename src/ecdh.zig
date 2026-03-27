const std = @import("std");
const P256 = std.crypto.ecc.P256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const key_length = 32;
pub const uncompressed_point_length = 65; // 0x04 + x(32) + y(32)

/// P-256 key pair for ECDH key agreement.
pub const KeyPair = struct {
    scalar: [key_length]u8,
    public_x: [key_length]u8,
    public_y: [key_length]u8,
};

/// Generate an ephemeral P-256 ECDH key pair.
pub fn generateKeyPair() !KeyPair {
    var scalar: [key_length]u8 = undefined;

    // Retry until we get a valid scalar (non-zero, < order)
    for (0..64) |_| {
        std.crypto.random.bytes(&scalar);
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

/// Compute ECDH shared secret: SHA-256(x-coordinate of d * Q).
/// This matches CTAP2 PIN protocol v2 shared secret derivation.
///
/// peer_x, peer_y: affine coordinates of the peer's P-256 public key.
/// scalar: our 32-byte scalar.
pub fn deriveSharedSecret(
    scalar: *const [key_length]u8,
    peer_x: *const [key_length]u8,
    peer_y: *const [key_length]u8,
) ![key_length]u8 {
    // Reconstruct peer point from affine coordinate bytes
    const Fe = P256.Fe;
    const x = Fe.fromBytes(peer_x.*, .big) catch return error.InvalidPeerKey;
    const y = Fe.fromBytes(peer_y.*, .big) catch return error.InvalidPeerKey;
    const peer_point = P256.fromAffineCoordinates(.{ .x = x, .y = y }) catch return error.InvalidPeerKey;

    // Scalar multiplication
    const shared_point = peer_point.mul(scalar.*, .big) catch return error.ECDHFailed;
    const affine = shared_point.affineCoordinates();
    const x_bytes = affine.x.toBytes(.big);

    // SHA-256(x) per CTAP2 spec
    var out: [key_length]u8 = undefined;
    Sha256.hash(&x_bytes, &out, .{});
    return out;
}

// ── Tests ───────────────────────────────────────────────────────────────

test "ECDH P-256 key generation produces valid key pair" {
    const kp = try generateKeyPair();
    // Private key should be non-zero
    var all_zero = true;
    for (kp.scalar) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
    // Public key coordinates should be non-zero
    var x_zero = true;
    for (kp.public_x) |b| {
        if (b != 0) x_zero = false;
    }
    try std.testing.expect(!x_zero);
}

test "ECDH P-256 roundtrip shared secret" {
    const alice = try generateKeyPair();
    const bob = try generateKeyPair();

    const secret_a = try deriveSharedSecret(&alice.scalar, &bob.public_x, &bob.public_y);
    const secret_b = try deriveSharedSecret(&bob.scalar, &alice.public_x, &alice.public_y);

    try std.testing.expectEqualSlices(u8, &secret_a, &secret_b);
}

test "ECDH P-256 different key pairs produce different secrets" {
    const alice = try generateKeyPair();
    const bob = try generateKeyPair();
    const charlie = try generateKeyPair();

    const ab = try deriveSharedSecret(&alice.scalar, &bob.public_x, &bob.public_y);
    const ac = try deriveSharedSecret(&alice.scalar, &charlie.public_x, &charlie.public_y);

    try std.testing.expect(!std.mem.eql(u8, &ab, &ac));
}
