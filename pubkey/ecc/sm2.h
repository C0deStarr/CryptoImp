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
	, uint8_t* pOutCipher, uint32_t nCipher
	, uint32_t* pnNeededOutBuffer
);

void test_sm2();

#endif // !_SM2_H
