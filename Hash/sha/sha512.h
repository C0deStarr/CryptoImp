#ifndef _SHA256_H
#define _SHA256_H

#include "common/common.h"

#define WORD_SIZE 4
#define BLOCK_SIZE 64   // 16 * WORD_SIZE
#define SCHEDULE_SIZE 64    // steps
#define DIGEST_SIZE (256/8)

typedef struct _HashState {
    uint32_t hash[8];
    // BLOCK_SIZE == 16 * WORD_SIZE bytes
    // 64 bytes == 512 bits for SHA-256
    // 128 bytes == 1024 bits for SHA-512
    uint8_t block[BLOCK_SIZE];
    uint8_t nBytesLen;        // byte offset of current block
    uint64_t nBitsLen;          // for msg padding
} HashState;

ErrCrypto SHA256_init(HashState* pHashState);
ErrCrypto SHA256_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA256_digest(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha256();

#endif