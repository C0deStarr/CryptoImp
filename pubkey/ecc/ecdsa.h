#ifndef _ECDSA_H
#define _ECDSA_H

#include <common/common.h>

#include "ec.h"

typedef struct {
	EC ec;
	EC_PRIKEY priKey;
	EC_PUBKEY pubKey;
}ecdsa;

ErrCrypto InitECDSA(ecdsa* pCtx, enum_ec typeEC);
ErrCrypto GenerateEcdsaKeys(ecdsa* pCtx);

ErrCrypto ecdsa_sign(ecdsa* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, uint8_t* pOutR, uint32_t nOutR
	, uint8_t* pOutS, uint32_t nOutS);

ErrCrypto ecdsa_verify(ecdsa* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, const uint8_t* pInR, uint32_t nR
	, const uint8_t* pInS, uint32_t nS);

void test_ecdsa();

#endif // !_ECDSA_H
