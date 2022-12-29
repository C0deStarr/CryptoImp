#ifndef _SHA1_H
#define _SHA1_H


#include <common/common.h>
#define BLOCK_SIZE 64
#define DIGEST_SIZE 20

typedef struct _HashState {
    uint32_t hash[5];
    uint8_t block[BLOCK_SIZE];    // 64 bytes == 512 bits == 16 32-bit words
    uint8_t nBytesLen;        // byte offset of current block
    uint64_t nBitsLen;          // for msg padding
} HashState;

ErrCrypto SHA1_init(HashState* pHashState);
ErrCrypto SHA1_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA1_final(HashState* pHashState, uint8_t* digest, int nDigest/* DIGEST_SIZE */);
void test_sha1();
#endif