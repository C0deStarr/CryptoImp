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


/**
 * @brief 
 * @param pX1 
 *		size == ctx.ec.stcCurve.nSizeOfN + 1
 *			LsbY || x
 * @return 
*/
ErrCrypto ecc_encrypt(ecc* pCtx
	, const uint8_t* pMsg, uint32_t nMsg
	, uint8_t* pOutXc, uint32_t nCx
	//, int* pnOutLsbYc	// C is not needed to reconstruct
	, uint8_t* pOutX1, uint32_t nX1
#ifdef _DEBUG
	, big X2
#endif
	);
ErrCrypto ecc_decrypt(ecc* pCtx
	, const uint8_t* pInXc, uint32_t nXc
	//, int nLsbYc
	, const uint8_t* pInX1, uint32_t nX1
	, uint8_t *pOutDec, uint32_t nOutDec
#ifdef _DEBUG
	, big X2
#endif
);

void test_ecc();
#endif // !_ECC_H
