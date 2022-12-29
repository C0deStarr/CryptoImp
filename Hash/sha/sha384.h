#ifndef _SHA384_H
#define _SHA384_H

#include "common/common.h"
#include "./sha512.h"


#define DIGEST_SIZE (384/8)


ErrCrypto SHA384_init(HashState* pHashState);
ErrCrypto SHA384_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SHA384_final(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sha384();

#endif