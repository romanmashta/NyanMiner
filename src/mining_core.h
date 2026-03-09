/************************************************************************************
 *  mining_core.h — Portable mining computation functions (no Arduino/ESP32 deps)
 *
 *  These functions encapsulate the pure-computation parts of the mining pipeline
 *  and can be compiled natively for testing.
 ************************************************************************************/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Result of evaluating a single nonce */
struct nonce_result {
    double difficulty;       /* computed difficulty from hash */
    bool is_16bit_share;     /* hash[31]==0 && hash[30]==0 */
    bool is_32bit_share;     /* + hash[29]==0 && hash[28]==0 */
    bool is_valid_block;     /* hash <= target */
};

/*
 * check_nonce — Full pipeline: midstate + bake + hash + evaluate
 *
 * header80:        80-byte block header (nonce already set at bytes 76-79)
 * target32:        32-byte target in little-endian byte order
 * pool_difficulty:  minimum difficulty threshold for a share
 * hash_out:        32-byte output buffer for the double-SHA256 hash
 *
 * Returns nonce_result with share/validity status and difficulty.
 */
nonce_result check_nonce(const uint8_t* header80, const uint8_t* target32,
                         double pool_difficulty, uint8_t* hash_out);

/*
 * check_nonce_fast — Uses pre-computed midstate and bake for inner-loop usage
 *
 * midstate_digest: 8 x uint32_t midstate from nerd_mids()
 * header_tail16:   pointer to header bytes 64-79 (last 16 bytes)
 * bake:            15 x uint32_t pre-computed from nerd_sha256_bake()
 * target32:        32-byte target in little-endian byte order
 * pool_difficulty:  minimum difficulty threshold for a share
 * hash_out:        32-byte output buffer for the double-SHA256 hash
 */
nonce_result check_nonce_fast(const uint32_t* midstate_digest,
                              const uint8_t* header_tail16,
                              const uint32_t* bake,
                              const uint8_t* target32,
                              double pool_difficulty,
                              uint8_t* hash_out);

/* ---- Portable utility functions ---- */

uint8_t hex(char ch);
int to_byte_array(const char *in, size_t in_size, uint8_t *out);
void swap_endian_words(const char *hex_words, uint8_t *output);
void reverse_bytes(uint8_t *data, size_t len);
double le256todouble(const uint8_t *target);
double diff_from_target(const uint8_t *target);
bool check_valid(const uint8_t *hash, const uint8_t *target);
void suffix_string(double val, char *buf, size_t bufsiz, int sigdigits);
