
#ifndef _DES_H
#define _DES_H


#include <common/common.h>
#include "modes.h"


#define NUMBER_OF_ROUNDS    16
#define KEY_SIZE    8


typedef struct {
    uint64_t subkeys[NUMBER_OF_ROUNDS];
}des_key;


ErrCrypto des_init(des_key *pKey, uint32_t nKey);

ErrCrypto des_encrypt(des_key key
	, uint32_t nKey
	, const uint8_t *pData
	, uint32_t nData
	, uint8_t *pCipher
	, uint32_t nOutBuf
	, uint32_t *pnCipher
	, OperationModes mode);

ErrCrypto des_decrypt(des_key key
	, uint32_t nKey
	, uint8_t* pCipher
	, uint32_t nCipher
	, uint8_t *pOutPlain
	, uint32_t nOutBuf
	, uint32_t* pnPlain
	, OperationModes mode);

//ErrCrypto des_finalize();

void test_des();


#endif