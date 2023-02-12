#ifndef _SHA512_256_H
#define _SHA512_256_H

#include "common/common.h"
#include "./sha512.h"


#define SHA512_256_DIGEST_SIZE 32 // (256/8)


ErrCrypto SHA512_256_init(SHA512HashState* pHashState);
ErrCrypto SHA512_256_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA512_256_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha512_256();

#endif