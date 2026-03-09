
#include <Arduino.h>
#include "utils.h"
#include "mining.h"
#include "stratum.h"
#include "mbedtls/sha256.h"

#include <string.h>
#include <stdio.h>

/****************** PREMINING CALCULATIONS ********************/

void getNextExtranonce2(int extranonce2_size, char *extranonce2) {
  for (int i = 0; i < extranonce2_size; i++) {
    uint8_t b = esp_random() & 0xFF;
    sprintf(extranonce2 + i * 2, "%02x", b);
  }
  extranonce2[2 * extranonce2_size] = 0;
}

miner_data init_miner_data(void){

  miner_data newMinerData;

  newMinerData.poolDifficulty = DEFAULT_DIFFICULTY;
  newMinerData.inRun = false;
  newMinerData.newJob = false;

  return newMinerData;
}

miner_data calculateMiningData(mining_subscribe& mWorker, mining_job mJob){

  miner_data mMiner = init_miner_data();

  // calculate target - target = (nbits[2:]+'00'*(int(nbits[:2],16) - 3)).zfill(64)

    char target[TARGET_BUFFER_SIZE+1];
    memset(target, '0', TARGET_BUFFER_SIZE);
    int exponent = (int) strtol(mJob.nbits.substring(0, 2).c_str(), 0, 16);
    int offset = TARGET_BUFFER_SIZE - 2 * exponent;
    if (offset < 0) offset = 0;
    memcpy(target + offset, mJob.nbits.substring(2).c_str(), mJob.nbits.length() - 2);
    target[TARGET_BUFFER_SIZE] = 0;
    Serial.print("    target: "); Serial.println(target);

    // bytearray target
    size_t size_target = to_byte_array(target, 32, mMiner.bytearray_target);

    for (size_t j = 0; j < size_target / 2; j++) {
      mMiner.bytearray_target[j] ^= mMiner.bytearray_target[size_target - 1 - j];
      mMiner.bytearray_target[size_target - 1 - j] ^= mMiner.bytearray_target[j];
      mMiner.bytearray_target[j] ^= mMiner.bytearray_target[size_target - 1 - j];
    }

    // get extranonce2 - extranonce2 = hex(random.randint(0,2**32-1))[2:].zfill(2*extranonce2_size)
    //To review
    char extranonce2_char[2 * mWorker.extranonce2_size+1];
	  mWorker.extranonce2.toCharArray(extranonce2_char, 2 * mWorker.extranonce2_size + 1);
    #ifdef TEST_POOL_EXTRANONCE2
    strcpy(extranonce2_char, TEST_POOL_EXTRANONCE2);
    #else
    getNextExtranonce2(mWorker.extranonce2_size, extranonce2_char);
    #endif
    mWorker.extranonce2 = String(extranonce2_char);

    //get coinbase - coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()
    String coinbase = mJob.coinb1 + mWorker.extranonce1 + mWorker.extranonce2 + mJob.coinb2;
    Serial.print("    coinbase: "); Serial.println(coinbase);
    size_t str_len = coinbase.length()/2;
    uint8_t bytearray[str_len];

    size_t res = to_byte_array(coinbase.c_str(), str_len*2, bytearray);

    #ifdef DEBUG_MINING
    Serial.print("    extranonce2: "); Serial.println(mWorker.extranonce2);
    Serial.print("    coinbase: "); Serial.println(coinbase);
    Serial.print("    coinbase bytes - size: "); Serial.println(res);
    for (size_t i = 0; i < res; i++)
        Serial.printf("%02x", bytearray[i]);
    Serial.println("---");
    #endif

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    byte interResult[32]; // 256 bit
    byte shaResult[32]; // 256 bit

    mbedtls_sha256_starts_ret(&ctx,0);
    mbedtls_sha256_update_ret(&ctx, bytearray, str_len);
    mbedtls_sha256_finish_ret(&ctx, interResult);

    mbedtls_sha256_starts_ret(&ctx,0);
    mbedtls_sha256_update_ret(&ctx, interResult, 32);
    mbedtls_sha256_finish_ret(&ctx, shaResult);
    mbedtls_sha256_free(&ctx);

    #ifdef DEBUG_MINING
    Serial.print("    coinbase double sha: ");
    for (size_t i = 0; i < 32; i++)
        Serial.printf("%02x", shaResult[i]);
    Serial.println("");
    #endif


    // copy coinbase hash
    memcpy(mMiner.merkle_result, shaResult, sizeof(shaResult));

    byte merkle_concatenated[32 * 2];
    for (size_t k=0; k < mJob.merkle_branch.size(); k++) {
        const char* merkle_element = (const char*) mJob.merkle_branch[k];
        uint8_t bytearray[32];
        size_t res = to_byte_array(merkle_element, 64, bytearray);

        #ifdef DEBUG_MINING
        Serial.print("    merkle element    "); Serial.print(k); Serial.print(": "); Serial.println(merkle_element);
        #endif
        for (size_t i = 0; i < 32; i++) {
          merkle_concatenated[i] = mMiner.merkle_result[i];
          merkle_concatenated[32 + i] = bytearray[i];
        }

        #ifdef DEBUG_MINING
        Serial.print("    merkle element    "); Serial.print(k); Serial.print(": "); Serial.println(merkle_element);
        Serial.print("    merkle concatenated: ");
        for (size_t i = 0; i < 64; i++)
            Serial.printf("%02x", merkle_concatenated[i]);
        Serial.println("");
        #endif

        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts_ret(&ctx,0);
        mbedtls_sha256_update_ret(&ctx, merkle_concatenated, 64);
        mbedtls_sha256_finish_ret(&ctx, interResult);

        mbedtls_sha256_starts_ret(&ctx,0);
        mbedtls_sha256_update_ret(&ctx, interResult, 32);
        mbedtls_sha256_finish_ret(&ctx, mMiner.merkle_result);
        mbedtls_sha256_free(&ctx);

        #ifdef DEBUG_MINING
        Serial.print("    merkle sha         : ");
        for (size_t i = 0; i < 32; i++)
            Serial.printf("%02x", mMiner.merkle_result[i]);
        Serial.println("");
        #endif
    }
    // merkle root from merkle_result

    Serial.print("    merkle sha         : ");
    char merkle_root[65];
    for (int i = 0; i < 32; i++) {
      Serial.printf("%02x", mMiner.merkle_result[i]);
      snprintf(&merkle_root[i*2], 3, "%02x", mMiner.merkle_result[i]);
    }
    merkle_root[65] = 0;
    Serial.println("");

    // calculate blockheader
    // j.block_header = ''.join([j.version, j.prevhash, merkle_root, j.ntime, j.nbits])
    String blockheader = mJob.version + mJob.prev_block_hash + String(merkle_root) + mJob.ntime + mJob.nbits + "00000000";
    str_len = blockheader.length()/2;

    //uint8_t bytearray_blockheader[str_len];
    res = to_byte_array(blockheader.c_str(), str_len*2, mMiner.bytearray_blockheader);

    #ifdef DEBUG_MINING
    Serial.println("    blockheader: "); Serial.print(blockheader);
    Serial.println("    blockheader bytes "); Serial.print(str_len); Serial.print(" -> ");
    #endif

    // reverse version
    uint8_t buff;
    size_t bword, bsize, boffset;
    boffset = 0;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mMiner.bytearray_blockheader[j];
        mMiner.bytearray_blockheader[j] = mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }

    // reverse prev hash (4-byte word swap)
    boffset = 4;
    bword = 4;
    bsize = 32;
    for (size_t i = 1; i <= bsize / bword; i++) {
        for (size_t j = boffset; j < boffset + bword / 2; j++) {
            buff = mMiner.bytearray_blockheader[j];
            mMiner.bytearray_blockheader[j] = mMiner.bytearray_blockheader[2 * boffset + bword - 1 - j];
            mMiner.bytearray_blockheader[2 * boffset + bword - 1 - j] = buff;
        }
        boffset += bword;
    }

    // reverse ntime
    boffset = 68;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mMiner.bytearray_blockheader[j];
        mMiner.bytearray_blockheader[j] = mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }

    // reverse difficulty
    boffset = 72;
    bsize = 4;
    for (size_t j = boffset; j < boffset + (bsize/2); j++) {
        buff = mMiner.bytearray_blockheader[j];
        mMiner.bytearray_blockheader[j] = mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j];
        mMiner.bytearray_blockheader[2 * boffset + bsize - 1 - j] = buff;
    }


    #ifdef DEBUG_MINING
    Serial.print(" >>> bytearray_blockheader     : ");
    for (size_t i = 0; i < 4; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("version     ");
    for (size_t i = 0; i < 4; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("prev hash   ");
    for (size_t i = 4; i < 4+32; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("merkle root ");
    for (size_t i = 36; i < 36+32; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("ntime       ");
    for (size_t i = 68; i < 68+4; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("nbits       ");
    for (size_t i = 72; i < 72+4; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.print("nonce       ");
    for (size_t i = 76; i < 76+4; i++)
        Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    Serial.println("");
    Serial.println("bytearray_blockheader: ");
    for (size_t i = 0; i < str_len; i++) {
      Serial.printf("%02x", mMiner.bytearray_blockheader[i]);
    }
    Serial.println("");
    #endif
  return mMiner;
}
