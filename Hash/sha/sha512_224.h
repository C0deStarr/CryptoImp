#ifndef _SHA512_224_H
#define _SHA512_224_H

#include "common/common.h"
#include "./sha512.h"


#define SHA512_224_DIGEST_SIZE  28// (224/8)


ErrCrypto SHA512_224_init(SHA512HashState* pHashState);
ErrCrypto SHA512_224_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA512_224_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha512_224();

#endif