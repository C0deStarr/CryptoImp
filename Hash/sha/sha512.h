#ifndef _SHA512_H
#define _SHA512_H

#include "common/common.h"

#define WORD_SIZE 4
#define BLOCK_SIZE 64   // 16 * WORD_SIZE
#define SCHEDULE_SIZE 80    // steps
#define DIGEST_SIZE (512/8)

typedef struct _HashState {
    uint64_t hash[8];
    // BLOCK_SIZE == 16 * WORD_SIZE bytes
    // 64 bytes == 512 bits for SHA-256
    // 128 bytes == 1024 bits for SHA-512
    uint8_t block[BLOCK_SIZE];
    uint8_t nBytesLen;        // byte offset of current block
    // msg length padding
    // 8 bytes == 64 bits for SHA-256
    // 16 bytes == 128 bits for SHA-512
    uint64_t nBitsLen[2];     
} HashState;

ErrCrypto SHA512_init(HashState* pHashState);
ErrCrypto SHA512_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA512_digest(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha512();

#endif