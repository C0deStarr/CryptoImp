#ifndef _SHA512_224_H
#define _SHA512_224_H

#include "common/common.h"
#include "./sha512.h"


#define DIGEST_SIZE (512/8)


ErrCrypto SHA512_224_init(HashState* pHashState);
ErrCrypto SHA512_224_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA512_224_digest(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha512_224();

#endif