#ifndef _ECC_H
#define _ECC_H

#include <common/common.h>
#include <common/mr_util.h>

#include "ec.h"

typedef struct {
	EC ec;
	EC_PRIKEY priKey;
	EC_PUBKEY pubKey;
}ecc;
void test_ecc_demo();


ErrCrypto InitECC(ecc* pCtx, enum_ec typeEC);
ErrCrypto GenerateEccKeys(ecc* pCtx);

ErrCrypto ec_encrypt(ecc* pCtx
	, uint8_t* pMsg, uint32_t nMsg
	, uint8_t* pOutXc, uint32_t nXc
	, int* pnOutLsbYc
	, uint8_t* pOutXx1, uint32_t nXx1
	, int* pnOutLsbYx1);

void test_ecc();
#endif // !_ECC_H
