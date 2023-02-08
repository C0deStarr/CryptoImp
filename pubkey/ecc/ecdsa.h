#ifndef _ECDSA_H
#define _ECDSA_H

#include <common/common.h>

#include "ecc.h"

typedef struct {
	EC ec;
	EC_KEY priKey;
	EC_KEY pubKey;
}ecdsa;

ErrCrypto InitECDSA(ecdsa* pCtx, enum_ec typeEC);

void test_ecdsa();

#endif // !_ECDSA_H
