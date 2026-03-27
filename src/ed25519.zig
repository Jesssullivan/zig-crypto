const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const seed_length = Ed25519.KeyPair.seed_length; // 32
pub const public_key_length = Ed25519.PublicKey.encoded_length; // 32
pub const signature_length = Ed25519.Signature.encoded_length; // 64
pub const signing_key_length = Ed25519.SecretKey.encoded_length; // 64

/// Ed25519 key pair.
pub const KeyPair = struct {
    seed: [seed_length]u8,
    public_key: [public_key_length]u8,
    signing_key: [signing_key_length]u8,
};

/// Generate a new Ed25519 key pair from random seed.
pub fn generateKeyPair() KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return .{
        .seed = kp.secret_key.seed(),
        .public_key = kp.public_key.toBytes(),
        .signing_key = kp.secret_key.toBytes(),
    };
}

/// Derive Ed25519 key pair from a 32-byte seed.
/// Used by Sparkle for deriving public key from stored seed.
pub fn fromSeed(seed: *const [seed_length]u8) !KeyPair {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed.*);
    return .{
        .seed = seed.*,
        .public_key = kp.public_key.toBytes(),
        .signing_key = kp.secret_key.toBytes(),
    };
}

/// Sign a message with Ed25519.
pub fn sign(
    message: []const u8,
    signing_key_bytes: *const [signing_key_length]u8,
) ![signature_length]u8 {
    const sk = try Ed25519.SecretKey.fromBytes(signing_key_bytes.*);
    const kp = try Ed25519.KeyPair.fromSecretKey(sk);
    const sig = try kp.sign(message, null);
    return sig.toBytes();
}

/// Verify an Ed25519 signature.
pub fn verify(
    message: []const u8,
    signature_bytes: *const [signature_length]u8,
    public_key_bytes: *const [public_key_length]u8,
) bool {
    const sig = Ed25519.Signature.fromBytes(signature_bytes.*);
    const pk = Ed25519.PublicKey.fromBytes(public_key_bytes.*) catch return false;
    sig.verify(message, pk) catch return false;
    return true;
}

// ── Tests ───────────────────────────────────────────────────────────────

test "Ed25519 key pair generation" {
    const kp = generateKeyPair();
    var all_zero = true;
    for (kp.public_key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "Ed25519 sign and verify" {
    const kp = generateKeyPair();
    const message = "Hello, Ed25519!";

    const sig = try sign(message, &kp.signing_key);
    try std.testing.expect(verify(message, &sig, &kp.public_key));
}

test "Ed25519 verify rejects wrong message" {
    const kp = generateKeyPair();
    const sig = try sign("correct message", &kp.signing_key);
    try std.testing.expect(!verify("wrong message", &sig, &kp.public_key));
}

test "Ed25519 verify rejects wrong key" {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const sig = try sign("test", &kp1.signing_key);
    try std.testing.expect(!verify("test", &sig, &kp2.public_key));
}

test "Ed25519 from seed is deterministic" {
    const seed = [_]u8{0x42} ** 32;
    const kp1 = try fromSeed(&seed);
    const kp2 = try fromSeed(&seed);
    try std.testing.expectEqualSlices(u8, &kp1.public_key, &kp2.public_key);
    try std.testing.expectEqualSlices(u8, &kp1.signing_key, &kp2.signing_key);
}

test "Ed25519 from seed sign/verify round-trip" {
    const seed = [_]u8{0xAB} ** 32;
    const kp = try fromSeed(&seed);
    const message = "Sparkle update verification";
    const sig = try sign(message, &kp.signing_key);
    try std.testing.expect(verify(message, &sig, &kp.public_key));
}
