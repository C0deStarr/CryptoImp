#ifndef _SHA512_H
#define _SHA512_H

#include "common/common.h"

#define SHA512_WORD_SIZE 8
#define SHA512_BLOCK_SIZE 128   // 16 * WORD_SIZE
#define SHA512_SCHEDULE_SIZE 80    // steps
#define SHA512_DIGEST_SIZE (512/8)

typedef struct _SHA512HashState {
    uint64_t hash[8];
    // BLOCK_SIZE == 16 * WORD_SIZE bytes
    // 64 bytes == 512 bits for SHA-256
    // 128 bytes == 1024 bits for SHA-512
    uint8_t block[SHA512_BLOCK_SIZE];
    uint32_t nBytesLen;        // byte offset of current block
    // msg length padding
    // 8 bytes == 64 bits for SHA-256
    // 16 bytes == 128 bits for SHA-512
    uint64_t nArrBitsLen[2];     
} SHA512HashState;

ErrCrypto SHA512_init(SHA512HashState* pSHA512HashState);
ErrCrypto SHA512_update(SHA512HashState* pSHA512HashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA512_final(SHA512HashState* pSHA512HashState, uint8_t* pDigest, int nDigest);
void test_sha512();
void sha512_t_iv_generator();
#endif