/************************************************************************************
 *  mining_core.cpp — Portable mining computation (no Arduino/ESP32 dependencies)
 ************************************************************************************/

#ifdef ARDUINO
#include <Arduino.h>
#endif

#include "mining_core.h"
#include "ShaTests/nerdSHA256plus.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* ---- Byte utilities ---- */

uint8_t hex(char ch) {
    uint8_t r = (ch > 57) ? (ch - 55) : (ch - 48);
    return r & 0x0F;
}

int to_byte_array(const char *in, size_t in_size, uint8_t *out) {
    int count = 0;
    if (in_size % 2) {
        while (*in && out) {
            *out = hex(*in++);
            if (!*in)
                return count;
            *out = (*out << 4) | hex(*in++);
            *out++;
            count++;
        }
        return count;
    } else {
        while (*in && out) {
            *out++ = (hex(*in++) << 4) | hex(*in++);
            count++;
        }
        return count;
    }
}

void swap_endian_words(const char *hex_words, uint8_t *output) {
    size_t hex_length = strlen(hex_words);
    if (hex_length % 8 != 0) {
        fprintf(stderr, "Must be 4-byte word aligned\n");
        exit(EXIT_FAILURE);
    }

    size_t binary_length = hex_length / 2;

    for (size_t i = 0; i < binary_length; i += 4) {
        for (int j = 0; j < 4; j++) {
            unsigned int byte_val;
            sscanf(hex_words + (i + j) * 2, "%2x", &byte_val);
            output[i + (3 - j)] = byte_val;
        }
    }
}

void reverse_bytes(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len / 2; ++i) {
        uint8_t temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

/* ---- Difficulty computation ---- */

static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;

/* Converts a little endian 256-bit value to a double */
double le256todouble(const uint8_t *target)
{
    uint64_t data64;
    double dcut64;

    memcpy(&data64, target + 24, sizeof(uint64_t));
    dcut64 = data64 * 6277101735386680763835789423207666416102355444464034512896.0;

    memcpy(&data64, target + 16, sizeof(uint64_t));
    dcut64 += data64 * 340282366920938463463374607431768211456.0;

    memcpy(&data64, target + 8, sizeof(uint64_t));
    dcut64 += data64 * 18446744073709551616.0;

    memcpy(&data64, target, sizeof(uint64_t));
    dcut64 += data64;

    return dcut64;
}

double diff_from_target(const uint8_t *target)
{
    double d64, dcut64;

    d64 = truediffone;
    dcut64 = le256todouble(target);
    if (dcut64 == 0.0)
        dcut64 = 1;
    return d64 / dcut64;
}

/* ---- Target validation ---- */

bool check_valid(const uint8_t *hash, const uint8_t *target)
{
    /* Compare hash <= target (both in little-endian byte order).
     * Walk from the most-significant byte (index 31) downward. */
    for (int i = 31; i >= 0; i--) {
        if (hash[i] < target[i])
            return true;
        if (hash[i] > target[i])
            return false;
    }
    return true;  /* exact equality */
}

/* ---- Display helpers ---- */

void suffix_string(double val, char *buf, size_t bufsiz, int sigdigits)
{
    const double kilo = 1000;
    const double mega = 1000000;
    const double giga = 1000000000;
    const double tera = 1000000000000;
    const double peta = 1000000000000000;
    const double exa  = 1000000000000000000;
    const double min_diff = 0.001;
    char suffix[2] = "";
    bool decimal = true;
    double dval;

    if (val >= exa) {
        val /= peta;
        dval = val / kilo;
        strcpy(suffix, "E");
    } else if (val >= peta) {
        val /= tera;
        dval = val / kilo;
        strcpy(suffix, "P");
    } else if (val >= tera) {
        val /= giga;
        dval = val / kilo;
        strcpy(suffix, "T");
    } else if (val >= giga) {
        val /= mega;
        dval = val / kilo;
        strcpy(suffix, "G");
    } else if (val >= mega) {
        val /= kilo;
        dval = val / kilo;
        strcpy(suffix, "M");
    } else if (val >= kilo) {
        dval = val / kilo;
        strcpy(suffix, "K");
    } else {
        dval = val;
        if (dval < min_diff)
            dval = 0.0;
    }

    if (!sigdigits) {
        if (decimal)
            snprintf(buf, bufsiz, "%.3f%s", dval, suffix);
        else
            snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
    } else {
        int ndigits = sigdigits - 1 - (dval > 0.0 ? (int)floor(log10(dval)) : 0);
        snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
    }
}

/* ---- Core mining check functions ---- */

nonce_result check_nonce(const uint8_t* header80, const uint8_t* target32,
                         double pool_difficulty, uint8_t* hash_out)
{
    /* Compute midstate from first 64 bytes */
    uint32_t digest[8];
    nerd_mids(digest, header80);

    /* Precompute bake from header bytes 64-75 */
    uint32_t bake[15];
    nerd_sha256_bake(digest, header80 + 64, bake);

    return check_nonce_fast(digest, header80 + 64, bake,
                            target32, pool_difficulty, hash_out);
}

nonce_result check_nonce_fast(const uint32_t* midstate_digest,
                              const uint8_t* header_tail16,
                              const uint32_t* bake,
                              const uint8_t* target32,
                              double pool_difficulty,
                              uint8_t* hash_out)
{
    nonce_result result;
    memset(&result, 0, sizeof(result));
    memset(hash_out, 0xFF, 32);

    /* Double-SHA256 with bake optimization */
    bool early_hit = nerd_sha256d_baked(midstate_digest, header_tail16, bake, hash_out);
    (void)early_hit;

    /* 16-bit share: last two bytes of hash are zero */
    result.is_16bit_share = (hash_out[31] == 0 && hash_out[30] == 0);

    if (!result.is_16bit_share) {
        result.difficulty = 0.0;
        result.is_32bit_share = false;
        result.is_valid_block = false;
        return result;
    }

    /* Compute difficulty from hash */
    result.difficulty = diff_from_target(hash_out);

    /* 32-bit share: first 4 bytes in LE (last 4 bytes) are zero */
    result.is_32bit_share = (hash_out[29] == 0 && hash_out[28] == 0);

    /* Check against target (only if 32-bit share in production) */
    #ifdef TEST_POOL
    result.is_valid_block = check_valid(hash_out, target32);
    #else
    if (result.is_32bit_share) {
        result.is_valid_block = check_valid(hash_out, target32);
    } else {
        result.is_valid_block = false;
    }
    #endif

    return result;
}
