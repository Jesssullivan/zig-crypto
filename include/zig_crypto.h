#ifndef ZIG_CRYPTO_H
#define ZIG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── SHA-256 ─────────────────────────────────────────────────────────── */

/** SHA-256 digest size in bytes. */
#define ZIG_CRYPTO_SHA256_DIGEST_LEN 32

/** SHA-256 block size in bytes. */
#define ZIG_CRYPTO_SHA256_BLOCK_LEN 64

/**
 * Compute SHA-256 hash of input data.
 *
 * @param data      Input bytes.
 * @param data_len  Length of input.
 * @param out       Output buffer (must be at least 32 bytes).
 */
void zig_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *out);

/* ── HMAC-SHA-256 ────────────────────────────────────────────────────── */

/** HMAC-SHA-256 output size in bytes. */
#define ZIG_CRYPTO_HMAC_SHA256_LEN 32

/**
 * Compute HMAC-SHA-256.
 *
 * @param key       HMAC key.
 * @param key_len   Length of key.
 * @param data      Input message.
 * @param data_len  Length of message.
 * @param out       Output buffer (must be at least 32 bytes).
 */
void zig_crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t *out
);

/* ── AES-128-CBC ─────────────────────────────────────────────────────── */

/** AES block size in bytes. */
#define ZIG_CRYPTO_AES_BLOCK_LEN 16

/**
 * AES-128-CBC encrypt (PKCS#7 padding).
 *
 * @param key           16-byte AES key.
 * @param iv            16-byte initialization vector.
 * @param plaintext     Input plaintext.
 * @param plaintext_len Length of plaintext.
 * @param out           Output buffer (must be at least plaintext_len + 16).
 * @return              Number of bytes written, or -1 on error.
 */
int zig_crypto_aes128_cbc_encrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *out
);

/**
 * AES-128-CBC decrypt (PKCS#7 unpadding).
 *
 * @param key            16-byte AES key.
 * @param iv             16-byte initialization vector.
 * @param ciphertext     Input ciphertext (must be multiple of 16).
 * @param ciphertext_len Length of ciphertext.
 * @param out            Output buffer (must be at least ciphertext_len).
 * @return               Number of plaintext bytes, or -1 on error.
 */
int zig_crypto_aes128_cbc_decrypt(
    const uint8_t key[16],
    const uint8_t iv[16],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *out
);

/* ── PBKDF2-SHA1 ─────────────────────────────────────────────────────── */

/**
 * PBKDF2 with HMAC-SHA1 key derivation.
 *
 * @param passphrase      Passphrase bytes.
 * @param passphrase_len  Length of passphrase.
 * @param salt          Salt bytes.
 * @param salt_len      Length of salt.
 * @param iterations    Iteration count.
 * @param out           Output buffer for derived key.
 * @param out_len       Desired key length.
 */
void zig_crypto_pbkdf2_sha1(
    const uint8_t *passphrase, size_t passphrase_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *out, size_t out_len
);

/* ── CSPRNG ──────────────────────────────────────────────────────────── */

/**
 * Fill buffer with cryptographically secure random bytes.
 * Uses OS entropy (getrandom on Linux, getentropy on macOS).
 *
 * @param buf  Output buffer.
 * @param len  Number of random bytes to generate.
 * @return     true on success, false on failure.
 */
bool zig_crypto_random(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_CRYPTO_H */
