#ifndef _SM2_H
#define _SM2_H

#include <common/common.h>
#include "ecc.h"

#define SM2_BLOCK_SIZE 32

/**
 * @brief 
 * @param pnNeededOutBuffer 
 *		get least nCipher
 * @return 
*/
ErrCrypto sm2_encrypt(ecc* pCtx
	, const uint8_t* pMsg, uint32_t nMsg
	, uint8_t* pOutCipher, _Inout_ uint32_t *pnCipher
);

ErrCrypto sm2_decrypt(ecc* pCtx
	, const uint8_t* pCipher, uint32_t nCipher
	, uint8_t* pOutMsg, _Inout_ uint32_t *pnOutMsg
);

void test_sm2();


ErrCrypto sm2_sign(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, uint8_t* pOutR, uint32_t nOutR
	, uint8_t* pOutS, uint32_t nOutS
#ifdef _DEBUG
	, big dbgR
	, big dbgS
	, big dbgX1
#endif 
);

ErrCrypto sm2_verify(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, const uint8_t* pInR, uint32_t nR
	, const uint8_t* pInS, uint32_t nS
#ifdef _DEBUG
	, big dbgR
	, big dbgS
	, big dbgX1
#endif 
);

void test_sm2_sign();

#endif // !_SM2_H
