/*
 * zig-crypto example: SHA-256 hashing and Ed25519 signing.
 *
 * Build:
 *   zig build example
 */

#include "zig_crypto.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int main(void) {
    const char *msg = "hello from zig-crypto";
    const uint8_t *msg_bytes = (const uint8_t *)msg;
    size_t msg_len = strlen(msg);

    /* SHA-256 */
    uint8_t digest[ZIG_CRYPTO_SHA256_DIGEST_LEN];
    zig_crypto_sha256(msg_bytes, msg_len, digest);
    printf("SHA-256:  ");
    print_hex(digest, sizeof(digest));
    printf("\n");

    /* SHA-256 hex shortcut */
    uint8_t hex[64];
    zig_crypto_sha256_hex(msg_bytes, msg_len, hex);
    printf("Hex:      %.*s\n", 64, hex);

    /* Ed25519 key generation */
    uint8_t seed[ZIG_CRYPTO_ED25519_SEED_LEN];
    uint8_t pub_key[ZIG_CRYPTO_ED25519_PUBLIC_LEN];
    uint8_t signing_key[ZIG_CRYPTO_ED25519_SIGNING_LEN];
    zig_crypto_ed25519_generate(seed, pub_key, signing_key);
    printf("Ed25519 public key: ");
    print_hex(pub_key, sizeof(pub_key));
    printf("\n");

    /* Sign */
    uint8_t sig[ZIG_CRYPTO_ED25519_SIGNATURE_LEN];
    if (zig_crypto_ed25519_sign(msg_bytes, msg_len, signing_key, sig) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }

    /* Verify */
    bool valid = zig_crypto_ed25519_verify(msg_bytes, msg_len, sig, pub_key);
    printf("Signature valid: %s\n", valid ? "yes" : "no");

    /* Tamper and verify again */
    sig[0] ^= 0xff;
    bool tampered = zig_crypto_ed25519_verify(msg_bytes, msg_len, sig, pub_key);
    printf("Tampered valid:  %s\n", tampered ? "yes (BUG!)" : "no (correct)");

    return 0;
}
