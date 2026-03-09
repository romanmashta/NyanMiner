/*
 * PlatformIO native test for nerdSHA256plus implementation.
 *
 * Validates nerd_mids() and nerd_sha256d() against known Bitcoin block
 * headers and a reference SHA256 implementation.
 *
 * Run: pio test -e native
 */

#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "ShaTests/nerdSHA256plus.h"
#include "mining_core.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int hex2byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t len = strlen(hex);
    size_t bytes = len / 2;
    if (bytes > max_len) bytes = max_len;
    for (size_t i = 0; i < bytes; i++)
        out[i] = (uint8_t)((hex2byte(hex[2*i]) << 4) | hex2byte(hex[2*i+1]));
    return bytes;
}

static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        snprintf(out + 2*i, 3, "%02x", data[i]);
    out[2*len] = '\0';
}

/* reverse_bytes() is provided by mining_core.h */

/* ------------------------------------------------------------------ */
/* Reference SHA256 for cross-checking (not part of code under test)   */
/* ------------------------------------------------------------------ */

static const uint32_t ref_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t ref_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void ref_sha256(const uint8_t *msg, size_t len, uint8_t *digest) {
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    size_t bit_len = len * 8;
    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint8_t *padded = (uint8_t *)calloc(padded_len, 1);
    memcpy(padded, msg, len);
    padded[len] = 0x80;
    for (int i = 0; i < 8; i++)
        padded[padded_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));

    for (size_t offset = 0; offset < padded_len; offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)padded[offset+4*i] << 24) |
                   ((uint32_t)padded[offset+4*i+1] << 16) |
                   ((uint32_t)padded[offset+4*i+2] << 8) |
                   (uint32_t)padded[offset+4*i+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ref_rotr(w[i-15], 7) ^ ref_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = ref_rotr(w[i-2], 17) ^ ref_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h0, b=h1, c=h2, d=h3, e=h4, f=h5, g=h6, h=h7;
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ref_rotr(e, 6) ^ ref_rotr(e, 11) ^ ref_rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + ref_K[i] + w[i];
            uint32_t S0 = ref_rotr(a, 2) ^ ref_rotr(a, 13) ^ ref_rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;
    }
    free(padded);

    uint32_t H[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (int i = 0; i < 8; i++) {
        digest[4*i]   = (uint8_t)(H[i] >> 24);
        digest[4*i+1] = (uint8_t)(H[i] >> 16);
        digest[4*i+2] = (uint8_t)(H[i] >> 8);
        digest[4*i+3] = (uint8_t)(H[i]);
    }
}

static void ref_sha256d(const uint8_t *msg, size_t len, uint8_t *digest) {
    uint8_t first[32];
    ref_sha256(msg, len, first);
    ref_sha256(first, 32, digest);
}

/* ------------------------------------------------------------------ */
/* Known Bitcoin block test vectors                                    */
/* ------------------------------------------------------------------ */

struct block_vector {
    const char *name;
    const char *header_hex;
    const char *hash_display_hex;  /* Bitcoin display order (byte-reversed) */
};

static const block_vector blocks[] = {
    {
        "Block #0 (Genesis)",
        "0100000000000000000000000000000000000000000000000000000000000000"
        "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
        "4b1e5e4a29ab5f49ffff001d1dac2b7c",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    },
    {
        "Block #1",
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900"
        "00000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e8"
        "57233e0e61bc6649ffff001d01e36299",
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    },
    {
        "Block #125552",
        "0100000081cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a3080000"
        "00000000e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0"
        "f1fc122bc7f5d74df2b9441a42a14695",
        "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d"
    },
    {
        "Block #100000",
        "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200"
        "000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac"
        "4247e9f337221b4d4c86041b0f2b5710",
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
    },
};
static const int NUM_BLOCKS = sizeof(blocks) / sizeof(blocks[0]);

/* Helper: run the full nerd pipeline (midstate + sha256d) on an 80-byte header */
static bool nerd_full_hash(const uint8_t *header, uint8_t *hash) {
    nerdSHA256_context midstate;
    nerd_mids(midstate.digest, header);
    memset(hash, 0xFF, 32);
    return nerd_sha256d(&midstate, header + 64, hash);
}

/* Helper: run the baked pipeline on an 80-byte header */
static bool nerd_full_hash_baked(const uint8_t *header, uint8_t *hash) {
    uint32_t digest[8];
    nerd_mids(digest, header);
    uint32_t bake[15];
    nerd_sha256_bake(digest, header + 64, bake);
    memset(hash, 0xFF, 32);
    return nerd_sha256d_baked(digest, header + 64, bake, hash);
}

/* ================================================================== */
/* ByteReverseWords tests                                              */
/* ================================================================== */

void test_byte_reverse_single_word(void) {
    uint32_t in = 0x01020304;
    uint32_t out;
    ByteReverseWords(&out, &in, 4);
    TEST_ASSERT_EQUAL_HEX32(0x04030201, out);
}

void test_byte_reverse_multiple_words(void) {
    uint32_t in[4]  = {0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC};
    uint32_t exp[4] = {0xDDCCBBAA, 0x44332211, 0x88776655, 0xCCBBAA99};
    uint32_t out[4];
    ByteReverseWords(out, in, 16);
    TEST_ASSERT_EQUAL_MEMORY(exp, out, 16);
}

void test_byte_reverse_identity(void) {
    uint32_t orig[4] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xFEDCBA98};
    uint32_t tmp[4], result[4];
    ByteReverseWords(tmp, orig, 16);
    ByteReverseWords(result, tmp, 16);
    TEST_ASSERT_EQUAL_MEMORY(orig, result, 16);
}

void test_byte_reverse_zeros(void) {
    uint32_t in[4] = {0, 0, 0, 0};
    uint32_t out[4];
    ByteReverseWords(out, in, 16);
    TEST_ASSERT_EQUAL_MEMORY(in, out, 16);
}

void test_byte_reverse_all_ff(void) {
    uint32_t in[4] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    uint32_t out[4];
    ByteReverseWords(out, in, 16);
    TEST_ASSERT_EQUAL_MEMORY(in, out, 16);
}

/* ================================================================== */
/* Reference SHA256 sanity checks                                      */
/* ================================================================== */

void test_ref_sha256_empty(void) {
    uint8_t digest[32];
    ref_sha256((const uint8_t *)"", 0, digest);
    uint8_t expected[32];
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 expected, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected, digest, 32);
}

void test_ref_sha256_abc(void) {
    uint8_t digest[32];
    ref_sha256((const uint8_t *)"abc", 3, digest);
    uint8_t expected[32];
    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 expected, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected, digest, 32);
}

void test_ref_sha256d_empty(void) {
    uint8_t digest[32];
    ref_sha256d((const uint8_t *)"", 0, digest);
    uint8_t expected[32];
    hex_to_bytes("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                 expected, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected, digest, 32);
}

/* ================================================================== */
/* Midstate tests                                                      */
/* ================================================================== */

void test_midstate_deterministic(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint32_t d1[8], d2[8];
    nerd_mids(d1, header);
    nerd_mids(d2, header);
    TEST_ASSERT_EQUAL_MEMORY(d1, d2, 32);
}

void test_midstate_nonzero(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint32_t digest[8];
    nerd_mids(digest, header);

    uint32_t zero_check = 0;
    for (int i = 0; i < 8; i++) zero_check |= digest[i];
    TEST_ASSERT_NOT_EQUAL(0, zero_check);
}

void test_midstate_differs_for_different_input(void) {
    uint8_t h1[80], h2[80];
    hex_to_bytes(blocks[0].header_hex, h1, 80);
    memcpy(h2, h1, 80);
    h2[10] ^= 0xFF;  /* flip byte in first 64 bytes */

    uint32_t d1[8], d2[8];
    nerd_mids(d1, h1);
    nerd_mids(d2, h2);
    TEST_ASSERT_FALSE(memcmp(d1, d2, 32) == 0);
}

void test_midstate_unchanged_by_tail(void) {
    uint8_t h1[80], h2[80];
    hex_to_bytes(blocks[0].header_hex, h1, 80);
    memcpy(h2, h1, 80);
    h2[76] ^= 0xFF;  /* flip nonce byte (past byte 64) */

    uint32_t d1[8], d2[8];
    nerd_mids(d1, h1);
    nerd_mids(d2, h2);
    TEST_ASSERT_EQUAL_MEMORY(d1, d2, 32);
}

/* ================================================================== */
/* Full SHA256d: known Bitcoin blocks                                  */
/* ================================================================== */

void test_sha256d_genesis_block(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t expected[32];
    hex_to_bytes(blocks[0].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);  /* display → raw SHA256d output */

    uint8_t hash[32];
    bool is_share = nerd_full_hash(header, hash);
    TEST_ASSERT_TRUE(is_share);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

void test_sha256d_block_1(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[1].header_hex, header, 80);

    uint8_t expected[32];
    hex_to_bytes(blocks[1].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);

    uint8_t hash[32];
    bool is_share = nerd_full_hash(header, hash);
    TEST_ASSERT_TRUE(is_share);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

void test_sha256d_block_125552(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[2].header_hex, header, 80);

    uint8_t expected[32];
    hex_to_bytes(blocks[2].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);

    uint8_t hash[32];
    bool is_share = nerd_full_hash(header, hash);
    TEST_ASSERT_TRUE(is_share);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

void test_sha256d_block_100000(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[3].header_hex, header, 80);

    uint8_t expected[32];
    hex_to_bytes(blocks[3].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);

    uint8_t hash[32];
    bool is_share = nerd_full_hash(header, hash);
    TEST_ASSERT_TRUE(is_share);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

/* ================================================================== */
/* Cross-check: nerd vs reference for all known blocks                 */
/* ================================================================== */

void test_cross_check_all_blocks(void) {
    for (int t = 0; t < NUM_BLOCKS; t++) {
        uint8_t header[80];
        hex_to_bytes(blocks[t].header_hex, header, 80);

        uint8_t ref_hash[32];
        ref_sha256d(header, 80, ref_hash);

        uint8_t nerd_hash[32];
        bool is_share = nerd_full_hash(header, nerd_hash);

        char msg[128];
        snprintf(msg, sizeof(msg), "Block mismatch: %s", blocks[t].name);
        TEST_ASSERT_TRUE_MESSAGE(is_share, msg);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(ref_hash, nerd_hash, 32, msg);
    }
}

/* ================================================================== */
/* Non-share: function returns false for bad nonces                    */
/* ================================================================== */

void test_non_share_returns_false(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    int non_shares_found = 0;
    int correct_false = 0;

    for (uint32_t nonce = 0; nonce < 2000 && non_shares_found < 50; nonce++) {
        header[76] = (uint8_t)(nonce & 0xFF);
        header[77] = (uint8_t)((nonce >> 8) & 0xFF);
        header[78] = (uint8_t)((nonce >> 16) & 0xFF);
        header[79] = (uint8_t)((nonce >> 24) & 0xFF);

        uint8_t ref_hash[32];
        ref_sha256d(header, 80, ref_hash);

        /* If ref says last two bytes are non-zero, nerd should return false */
        if (ref_hash[30] != 0 || ref_hash[31] != 0) {
            non_shares_found++;

            uint8_t nerd_hash[32];
            bool is_share = nerd_full_hash(header, nerd_hash);
            if (!is_share) correct_false++;
        }
    }

    TEST_ASSERT_GREATER_THAN(0, non_shares_found);
    TEST_ASSERT_EQUAL(non_shares_found, correct_false);
}

/* ================================================================== */
/* Midstate reuse: same midstate, varying nonces                       */
/* ================================================================== */

void test_midstate_reuse(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    nerdSHA256_context midstate;
    nerd_mids(midstate.digest, header);
    uint32_t saved[8];
    memcpy(saved, midstate.digest, 32);

    for (uint32_t nonce = 0; nonce < 200; nonce++) {
        header[76] = (uint8_t)(nonce & 0xFF);
        header[77] = (uint8_t)((nonce >> 8) & 0xFF);

        uint8_t nerd_hash[32];
        nerd_sha256d(&midstate, header + 64, nerd_hash);

        /* Midstate must not be modified */
        TEST_ASSERT_EQUAL_MEMORY(saved, midstate.digest, 32);
    }
}

/* ================================================================== */
/* Edge cases: special header patterns                                 */
/* ================================================================== */

void test_all_zero_header(void) {
    uint8_t header[80];
    memset(header, 0, 80);

    uint8_t ref_hash[32];
    ref_sha256d(header, 80, ref_hash);

    uint8_t nerd_hash[32];
    bool is_share = nerd_full_hash(header, nerd_hash);

    if (is_share) {
        TEST_ASSERT_EQUAL_MEMORY(ref_hash, nerd_hash, 32);
    } else {
        /* If nerd returned false, ref should also have non-zero trailing bytes */
        TEST_ASSERT_TRUE(ref_hash[30] != 0 || ref_hash[31] != 0);
    }
}

void test_all_ff_header(void) {
    uint8_t header[80];
    memset(header, 0xFF, 80);

    uint8_t ref_hash[32];
    ref_sha256d(header, 80, ref_hash);

    uint8_t nerd_hash[32];
    bool is_share = nerd_full_hash(header, nerd_hash);

    if (is_share) {
        TEST_ASSERT_EQUAL_MEMORY(ref_hash, nerd_hash, 32);
    } else {
        TEST_ASSERT_TRUE(ref_hash[30] != 0 || ref_hash[31] != 0);
    }
}

void test_sequential_header(void) {
    uint8_t header[80];
    for (int i = 0; i < 80; i++) header[i] = (uint8_t)i;

    uint8_t ref_hash[32];
    ref_sha256d(header, 80, ref_hash);

    uint8_t nerd_hash[32];
    bool is_share = nerd_full_hash(header, nerd_hash);

    if (is_share) {
        TEST_ASSERT_EQUAL_MEMORY(ref_hash, nerd_hash, 32);
    } else {
        TEST_ASSERT_TRUE(ref_hash[30] != 0 || ref_hash[31] != 0);
    }
}

/* ================================================================== */
/* Stress: 1000 random headers vs reference                            */
/* ================================================================== */

void test_stress_random_headers(void) {
    srand(42);  /* deterministic */
    int mismatches = 0;
    int false_positives = 0;
    int false_negatives = 0;
    int shares_matched = 0;

    for (int i = 0; i < 1000; i++) {
        uint8_t header[80];
        for (int j = 0; j < 80; j++) header[j] = (uint8_t)(rand() & 0xFF);

        uint8_t ref_hash[32];
        ref_sha256d(header, 80, ref_hash);
        bool ref_is_share = (ref_hash[30] == 0 && ref_hash[31] == 0);

        uint8_t nerd_hash[32];
        bool nerd_is_share = nerd_full_hash(header, nerd_hash);

        if (ref_is_share && !nerd_is_share) false_negatives++;
        if (!ref_is_share && nerd_is_share) false_positives++;
        if (ref_is_share && nerd_is_share) {
            if (memcmp(ref_hash, nerd_hash, 32) != 0) mismatches++;
            else shares_matched++;
        }
    }

    TEST_ASSERT_EQUAL_MESSAGE(0, mismatches, "hash mismatches in stress test");
    TEST_ASSERT_EQUAL_MESSAGE(0, false_positives, "false positives in stress test");
    TEST_ASSERT_EQUAL_MESSAGE(0, false_negatives, "false negatives in stress test");
}

/* ================================================================== */
/* Bit-flip sensitivity (avalanche)                                    */
/* ================================================================== */

void test_midstate_avalanche(void) {
    uint8_t header[80];
    memset(header, 0x42, 80);

    uint32_t base_digest[8];
    nerd_mids(base_digest, header);

    /* Flip every bit in the first 64 bytes, midstate must change each time */
    for (int byte_idx = 0; byte_idx < 64; byte_idx++) {
        for (int bit = 0; bit < 8; bit++) {
            uint8_t modified[80];
            memcpy(modified, header, 80);
            modified[byte_idx] ^= (1 << bit);

            uint32_t mod_digest[8];
            nerd_mids(mod_digest, modified);

            char msg[64];
            snprintf(msg, sizeof(msg), "byte %d bit %d didn't change midstate", byte_idx, bit);
            TEST_ASSERT_FALSE_MESSAGE(memcmp(base_digest, mod_digest, 32) == 0, msg);
        }
    }
}

/* ================================================================== */
/* Bake API tests                                                      */
/* ================================================================== */

void test_bake_matches_unbaked_known_blocks(void) {
    for (int t = 0; t < NUM_BLOCKS; t++) {
        uint8_t header[80];
        hex_to_bytes(blocks[t].header_hex, header, 80);

        uint8_t hash_unbaked[32], hash_baked[32];
        bool share_unbaked = nerd_full_hash(header, hash_unbaked);
        bool share_baked = nerd_full_hash_baked(header, hash_baked);

        char msg[128];
        snprintf(msg, sizeof(msg), "bake mismatch: %s", blocks[t].name);
        TEST_ASSERT_EQUAL_MESSAGE(share_unbaked, share_baked, msg);
        if (share_unbaked && share_baked) {
            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(hash_unbaked, hash_baked, 32, msg);
        }
    }
}

void test_bake_stress_random_headers(void) {
    srand(99);
    int mismatches = 0;
    int share_disagreements = 0;

    for (int i = 0; i < 1000; i++) {
        uint8_t header[80];
        for (int j = 0; j < 80; j++) header[j] = (uint8_t)(rand() & 0xFF);

        uint8_t ref_hash[32];
        ref_sha256d(header, 80, ref_hash);
        bool ref_is_share = (ref_hash[30] == 0 && ref_hash[31] == 0);

        uint8_t baked_hash[32];
        bool baked_is_share = nerd_full_hash_baked(header, baked_hash);

        if (ref_is_share != baked_is_share) share_disagreements++;
        if (ref_is_share && baked_is_share) {
            if (memcmp(ref_hash, baked_hash, 32) != 0) mismatches++;
        }
    }

    TEST_ASSERT_EQUAL_MESSAGE(0, mismatches, "bake hash mismatches");
    TEST_ASSERT_EQUAL_MESSAGE(0, share_disagreements, "bake share disagreements");
}

void test_bake_reuse_varying_nonces(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint32_t digest[8];
    nerd_mids(digest, header);

    /* Bake is computed once for header bytes 64-75 (not nonce) */
    uint32_t bake[15];
    nerd_sha256_bake(digest, header + 64, bake);

    /* Vary only the nonce, baked results should match unbaked */
    for (uint32_t nonce = 0; nonce < 200; nonce++) {
        header[76] = (uint8_t)(nonce & 0xFF);
        header[77] = (uint8_t)((nonce >> 8) & 0xFF);
        header[78] = (uint8_t)((nonce >> 16) & 0xFF);
        header[79] = (uint8_t)((nonce >> 24) & 0xFF);

        uint8_t hash_unbaked[32], hash_baked[32];
        bool s1 = nerd_full_hash(header, hash_unbaked);
        bool s2 = nerd_sha256d_baked(digest, header + 64, bake, hash_baked);

        TEST_ASSERT_EQUAL(s1, s2);
        if (s1 && s2) {
            TEST_ASSERT_EQUAL_MEMORY(hash_unbaked, hash_baked, 32);
        }
    }
}

/* ================================================================== */
/* E2E: mining pipeline (check_nonce) tests                            */
/* ================================================================== */

/*
 * Genesis block target from nbits 0x1d00ffff:
 * 00000000FFFF0000000000000000000000000000000000000000000000000000
 * Stored in little-endian byte order for check_valid().
 */
static void make_genesis_target(uint8_t *target32) {
    /* difficulty-1 target in big-endian display order */
    uint8_t be[32];
    hex_to_bytes("00000000ffff0000000000000000000000000000000000000000000000000000",
                 be, 32);
    /* convert to little-endian for check_valid */
    for (int i = 0; i < 32; i++)
        target32[i] = be[31 - i];
}

void test_e2e_genesis_block_valid(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t target[32];
    make_genesis_target(target);

    uint8_t hash[32];
    nonce_result r = check_nonce(header, target, 1.0, hash);

    /* Genesis hash starts with many zero bytes -> 16-bit and 32-bit share */
    TEST_ASSERT_TRUE(r.is_16bit_share);
    TEST_ASSERT_TRUE(r.is_32bit_share);
    TEST_ASSERT_TRUE(r.is_valid_block);
    TEST_ASSERT_GREATER_THAN(0.0, r.difficulty);

    /* Verify hash matches expected */
    uint8_t expected[32];
    hex_to_bytes(blocks[0].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

void test_e2e_block_125552_valid(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[2].header_hex, header, 80);

    uint8_t target[32];
    make_genesis_target(target);  /* diff-1 target is permissive enough */

    uint8_t hash[32];
    nonce_result r = check_nonce(header, target, 1.0, hash);

    TEST_ASSERT_TRUE(r.is_16bit_share);
    TEST_ASSERT_TRUE(r.is_32bit_share);
    TEST_ASSERT_TRUE(r.is_valid_block);

    /* Verify hash */
    uint8_t expected[32];
    hex_to_bytes(blocks[2].hash_display_hex, expected, 32);
    reverse_bytes(expected, 32);
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, 32);
}

void test_e2e_bad_nonce_not_valid(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);
    /* Corrupt the nonce */
    header[76] = 0x00;
    header[77] = 0x00;
    header[78] = 0x00;
    header[79] = 0x00;

    uint8_t target[32];
    make_genesis_target(target);

    uint8_t hash[32];
    nonce_result r = check_nonce(header, target, 1.0, hash);

    /* With a zeroed nonce, the genesis block should NOT be valid */
    /* (the real nonce is 0x1dac2b7c) */
    if (r.is_16bit_share && r.is_32bit_share) {
        /* Extremely unlikely but check anyway */
        TEST_ASSERT_FALSE(r.is_valid_block);
    }
}

void test_e2e_check_nonce_fast_matches_full(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t target[32];
    make_genesis_target(target);

    uint8_t hash_full[32], hash_fast[32];
    nonce_result r_full = check_nonce(header, target, 1.0, hash_full);

    /* Now do it the "fast" way with pre-computed midstate + bake */
    uint32_t digest[8];
    nerd_mids(digest, header);
    uint32_t bake[15];
    nerd_sha256_bake(digest, header + 64, bake);
    nonce_result r_fast = check_nonce_fast(digest, header + 64, bake,
                                           target, 1.0, hash_fast);

    TEST_ASSERT_EQUAL_MEMORY(hash_full, hash_fast, 32);
    TEST_ASSERT_EQUAL(r_full.is_16bit_share, r_fast.is_16bit_share);
    TEST_ASSERT_EQUAL(r_full.is_32bit_share, r_fast.is_32bit_share);
    TEST_ASSERT_EQUAL(r_full.is_valid_block, r_fast.is_valid_block);
    /* Compare difficulty as equal (same input = same result) */
    TEST_ASSERT_TRUE(r_full.difficulty == r_fast.difficulty);
}

void test_e2e_difficulty_calculation(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t target[32];
    make_genesis_target(target);

    uint8_t hash[32];
    nonce_result r = check_nonce(header, target, 1.0, hash);

    /* Genesis block difficulty should be 1.0 (it was mined at difficulty 1) */
    TEST_ASSERT_TRUE(r.difficulty >= 1.0);
}

void test_e2e_pool_difficulty_share_detection(void) {
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t target[32];
    make_genesis_target(target);

    uint8_t hash[32];
    nonce_result r = check_nonce(header, target, 1.0, hash);

    /* With pool difficulty 1.0, genesis block should be a share (diff >= 1) */
    TEST_ASSERT_TRUE(r.difficulty >= 1.0);

    /* With impossibly high pool difficulty, difficulty is still computed
     * but the caller decides whether to submit */
    nonce_result r2 = check_nonce(header, target, 1e15, hash);
    TEST_ASSERT_TRUE(r2.difficulty < 1e15);
}

void test_e2e_check_valid_fixed(void) {
    /* Test that check_valid correctly handles hash < target, hash == target,
     * and hash > target (this tests the bug fixes) */

    uint8_t target[32] = {0};
    target[31] = 0x00;
    target[30] = 0x00;
    target[29] = 0x00;
    target[28] = 0xFF;  /* target = 0xFF000000...00 in LE */

    uint8_t hash_below[32] = {0};
    hash_below[28] = 0xFE;  /* hash < target */
    TEST_ASSERT_TRUE(check_valid(hash_below, target));

    uint8_t hash_equal[32] = {0};
    hash_equal[28] = 0xFF;  /* hash == target */
    TEST_ASSERT_TRUE(check_valid(hash_equal, target));

    uint8_t hash_above[32] = {0};
    hash_above[29] = 0x01;  /* hash > target */
    TEST_ASSERT_FALSE(check_valid(hash_above, target));
}

void test_e2e_diff_from_target(void) {
    /* All-zero hash (except to avoid div-by-zero) should give max difficulty */
    uint8_t hash_low[32];
    memset(hash_low, 0, 32);
    hash_low[0] = 1;  /* smallest non-zero LE value */
    double diff = diff_from_target(hash_low);
    TEST_ASSERT_GREATER_THAN(1e60, diff);

    /* All-0xFF hash should give very low difficulty */
    uint8_t hash_high[32];
    memset(hash_high, 0xFF, 32);
    double diff2 = diff_from_target(hash_high);
    TEST_ASSERT_LESS_THAN(1.0, diff2);
}

/*
 * Reproduce the target calculation from calculateMiningData() in utils.cpp.
 * This uses the PARTIAL swap (only outer 8 bytes) — same as firmware.
 */
static void make_target_like_firmware(const char *nbits_hex, uint8_t *target32) {
    /* Same logic as calculateMiningData() (fixed version):
     *   char target[64+1]; memset(target, '0', 64);
     *   int exponent = strtol(nbits[0:2], 16);
     *   int offset = 64 - 2 * exponent;
     *   memcpy(target + offset, nbits[2:], 6);
     *   to_byte_array -> 32 bytes
     *   full 32-byte reversal
     */
    char target_str[65];
    memset(target_str, '0', 64);
    target_str[64] = 0;

    char exp_str[3] = { nbits_hex[0], nbits_hex[1], 0 };
    int exponent = (int)strtol(exp_str, NULL, 16);
    int offset = 64 - 2 * exponent;
    if (offset < 0) offset = 0;
    memcpy(target_str + offset, nbits_hex + 2, 6);

    /* to_byte_array equivalent */
    hex_to_bytes(target_str, target32, 32);

    /* full 32-byte reversal (matches fixed firmware) */
    for (int j = 0; j < 16; j++) {
        uint8_t tmp = target32[j];
        target32[j] = target32[31 - j];
        target32[31 - j] = tmp;
    }
}

void test_firmware_target_vs_correct_target(void) {
    /* Build target both ways for nbits 1d00ffff (difficulty 1) */
    uint8_t firmware_target[32];
    make_target_like_firmware("1d00ffff", firmware_target);

    uint8_t correct_target[32];
    make_genesis_target(correct_target);  /* full 32-byte reversal */

    /* If the firmware's partial swap is correct, these should match */
    TEST_ASSERT_EQUAL_MEMORY(correct_target, firmware_target, 32);
}

void test_firmware_target_check_valid_genesis(void) {
    /* Hash the genesis block, then check_valid with firmware-style target */
    uint8_t header[80];
    hex_to_bytes(blocks[0].header_hex, header, 80);

    uint8_t hash[32];
    nerd_full_hash(header, hash);

    uint8_t firmware_target[32];
    make_target_like_firmware("1d00ffff", firmware_target);

    /* Genesis block is valid at difficulty 1 — this should be true */
    TEST_ASSERT_TRUE(check_valid(hash, firmware_target));
}

void test_e2e_stress_mining_pipeline(void) {
    /* Run 500 random headers through check_nonce and cross-check with reference */
    srand(123);
    int mismatches = 0;

    uint8_t target[32];
    make_genesis_target(target);

    for (int i = 0; i < 500; i++) {
        uint8_t header[80];
        for (int j = 0; j < 80; j++) header[j] = (uint8_t)(rand() & 0xFF);

        uint8_t ref_hash[32];
        ref_sha256d(header, 80, ref_hash);

        uint8_t nonce_hash[32];
        nonce_result r = check_nonce(header, target, 1e-9, nonce_hash);

        bool ref_is_16bit = (ref_hash[30] == 0 && ref_hash[31] == 0);
        if (ref_is_16bit != r.is_16bit_share) {
            mismatches++;
            continue;
        }
        if (ref_is_16bit && r.is_16bit_share) {
            if (memcmp(ref_hash, nonce_hash, 32) != 0) mismatches++;
        }
    }

    TEST_ASSERT_EQUAL_MESSAGE(0, mismatches, "e2e pipeline mismatches vs reference");
}

/* ================================================================== */
/* Main                                                                */
/* ================================================================== */

int main(int argc, char **argv) {
    UNITY_BEGIN();

    /* ByteReverseWords */
    RUN_TEST(test_byte_reverse_single_word);
    RUN_TEST(test_byte_reverse_multiple_words);
    RUN_TEST(test_byte_reverse_identity);
    RUN_TEST(test_byte_reverse_zeros);
    RUN_TEST(test_byte_reverse_all_ff);

    /* Reference SHA256 sanity */
    RUN_TEST(test_ref_sha256_empty);
    RUN_TEST(test_ref_sha256_abc);
    RUN_TEST(test_ref_sha256d_empty);

    /* Midstate */
    RUN_TEST(test_midstate_deterministic);
    RUN_TEST(test_midstate_nonzero);
    RUN_TEST(test_midstate_differs_for_different_input);
    RUN_TEST(test_midstate_unchanged_by_tail);

    /* Known Bitcoin blocks */
    RUN_TEST(test_sha256d_genesis_block);
    RUN_TEST(test_sha256d_block_1);
    RUN_TEST(test_sha256d_block_125552);
    RUN_TEST(test_sha256d_block_100000);
    RUN_TEST(test_cross_check_all_blocks);

    /* Non-share detection */
    RUN_TEST(test_non_share_returns_false);

    /* Midstate reuse */
    RUN_TEST(test_midstate_reuse);

    /* Edge cases */
    RUN_TEST(test_all_zero_header);
    RUN_TEST(test_all_ff_header);
    RUN_TEST(test_sequential_header);

    /* Stress */
    RUN_TEST(test_stress_random_headers);

    /* Avalanche */
    RUN_TEST(test_midstate_avalanche);

    /* Bake API */
    RUN_TEST(test_bake_matches_unbaked_known_blocks);
    RUN_TEST(test_bake_stress_random_headers);
    RUN_TEST(test_bake_reuse_varying_nonces);

    /* E2E mining pipeline */
    RUN_TEST(test_e2e_genesis_block_valid);
    RUN_TEST(test_e2e_block_125552_valid);
    RUN_TEST(test_e2e_bad_nonce_not_valid);
    RUN_TEST(test_e2e_check_nonce_fast_matches_full);
    RUN_TEST(test_e2e_difficulty_calculation);
    RUN_TEST(test_e2e_pool_difficulty_share_detection);
    RUN_TEST(test_e2e_check_valid_fixed);
    RUN_TEST(test_e2e_diff_from_target);
    RUN_TEST(test_firmware_target_vs_correct_target);
    RUN_TEST(test_firmware_target_check_valid_genesis);
    RUN_TEST(test_e2e_stress_mining_pipeline);

    return UNITY_END();
}
