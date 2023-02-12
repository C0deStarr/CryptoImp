#ifndef _SHA224_H
#define _SHA224_H

#include "common/common.h"
#include "./sha256.h"


#define SHA224_DIGEST_SIZE 28 // (224/8)

ErrCrypto SHA224_init(SHA256_HashState* pHashState);
ErrCrypto SHA224_update(SHA256_HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA224_final(SHA256_HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha224();

#endif