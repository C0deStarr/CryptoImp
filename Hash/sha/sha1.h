#ifndef _SHA1_H
#define _SHA1_H


#include <common/common.h>
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

typedef struct _HashState {
    uint32_t hash[5];
    uint8_t block[SHA1_BLOCK_SIZE];    // 64 bytes == 512 bits == 16 32-bit words
    uint8_t nBytesLen;        // byte offset of current block
    uint64_t nBitsLen;          // for msg padding
} HashState;

ErrCrypto SHA1_init(HashState* pHashState);
ErrCrypto SHA1_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA1_final(HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */);
ErrCrypto SHA1_digest(const uint8_t* pData, uint64_t nData
    , uint8_t* pDigest, uint32_t nDigest);
void test_sha1();
#endif