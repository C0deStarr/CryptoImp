#ifndef _ECDSA_H
#define _ECDSA_H

#include <common/common.h>

#include "ecc.h"

typedef struct {
	EC ec;
	EC_PRIKEY priKey;
	EC_PUBKEY pubKey;
}ecdsa;

ErrCrypto InitECDSA(ecdsa* pCtx, enum_ec typeEC);
ErrCrypto GenerateEcdsaKeys(ecdsa* pCtx);

void test_ecdsa();

#endif // !_ECDSA_H
