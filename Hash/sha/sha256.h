#ifndef _SHA256_H
#define _SHA256_H

#include "common/common.h"

#define WORD_SIZE 4
#define BLOCK_SIZE 64   // 16 * WORD_SIZE
#define SCHEDULE_SIZE 64    // steps
#define DIGEST_SIZE 32  // (256/8)

typedef struct _HashState {
    uint32_t hash[8];
    // BLOCK_SIZE == 16 * WORD_SIZE bytes
    // 64 bytes == 512 bits for SHA-256
    // 128 bytes == 1024 bits for SHA-512
    uint8_t block[BLOCK_SIZE];
    uint8_t nBytesLen;        // byte offset of current block
    // msg length padding
    // 8 bytes == 64 bits for SHA-256
    // 16 bytes == 128 bits for SHA-512
    uint64_t nBitsLen;        
} HashState;

ErrCrypto SHA256_init(HashState* pHashState);
ErrCrypto SHA256_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA256_final(HashState* pHashState, uint8_t* pDigest, int nDigest);
ErrCrypto SHA1256_HMAC(const uint8_t* pKey, int nKey,
    const uint8_t* pData, uint32_t nData,
    uint8_t* md, uint32_t* nMd);
void test_sha256();
void test_sha256_hmac();

#endif