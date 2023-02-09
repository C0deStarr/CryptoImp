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

ErrCrypto ecdsa_sign(ecdsa* pCtx
	, const uint8_t *pHash, uint32_t nHash
	, uint8_t *pOut, uint32_t nOut);

void test_ecdsa();

#endif // !_ECDSA_H
