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

#endif // !_SM2_H
