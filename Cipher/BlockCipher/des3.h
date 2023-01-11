#ifndef _DES3_H
#define _DES3_H

#include "des.h"

typedef struct {
	des_key desKeys[3];
}des3_key;

ErrCrypto des3_init(des3_key* pStcKey, const uint8_t* pKey, uint32_t nKey);

ErrCrypto des3(des3_key* pStcKey
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pOut
	, uint32_t nOutBuf
	, DES_OPERATION op);

void test_des3();

#endif