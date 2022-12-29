#ifndef _SHA224_H
#define _SHA224_H

#include "common/common.h"
#include "./sha256.h"


#define DIGEST_SIZE (224/8)

ErrCrypto SHA224_init(HashState* pHashState);
ErrCrypto SHA224_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA224_final(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha224();

#endif