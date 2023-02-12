#ifndef _SHA384_H
#define _SHA384_H

#include "common/common.h"
#include "./sha512.h"


#define SHA384_DIGEST_SIZE (384/8)


ErrCrypto SHA384_init(SHA512HashState* pHashState);
ErrCrypto SHA384_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA384_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha384();

#endif