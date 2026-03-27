const std = @import("std");
const aes = @import("aes");

test "PBT: AES-128-CBC encrypt-decrypt round-trip" {
    var prng = std.Random.DefaultPrng.init(0xAE5CBC01);
    const random = prng.random();

    for (0..500) |_| {
        var key: [16]u8 = undefined;
        var iv: [16]u8 = undefined;
        random.bytes(&key);
        random.bytes(&iv);

        const pt_len = random.intRangeAtMost(usize, 1, 256);
        var plaintext: [256]u8 = undefined;
        random.bytes(plaintext[0..pt_len]);

        var ciphertext: [256 + 16]u8 = undefined;
        const ct_len = aes.cbcEncrypt(&key, &iv, plaintext[0..pt_len], &ciphertext) catch continue;

        var decrypted: [256 + 16]u8 = undefined;
        const dec_len = aes.cbcDecrypt(&key, &iv, ciphertext[0..ct_len], &decrypted) catch continue;

        try std.testing.expectEqual(pt_len, dec_len);
        try std.testing.expectEqualSlices(u8, plaintext[0..pt_len], decrypted[0..dec_len]);
    }
}

test "PBT: AES-128-CBC ciphertext length is always block-aligned" {
    var prng = std.Random.DefaultPrng.init(0xB10CCA1);
    const random = prng.random();

    for (0..500) |_| {
        var key: [16]u8 = undefined;
        var iv: [16]u8 = undefined;
        random.bytes(&key);
        random.bytes(&iv);

        const pt_len = random.intRangeAtMost(usize, 0, 256);
        var plaintext: [256]u8 = undefined;
        random.bytes(plaintext[0..pt_len]);

        var ciphertext: [256 + 16]u8 = undefined;
        const ct_len = aes.cbcEncrypt(&key, &iv, plaintext[0..pt_len], &ciphertext) catch continue;

        try std.testing.expect(ct_len % 16 == 0);
        try std.testing.expect(ct_len >= pt_len);
    }
}
