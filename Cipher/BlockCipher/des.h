
#ifndef _DES_H
#define _DES_H


#include <common/common.h>
#include "modes.h"


#define NUMBER_OF_ROUNDS    16
#define KEY_SIZE    8
#define BLOCK_SIZE    8

typedef enum {
	ENC = 0,
	DEC = 1
}DES_OPERATION;

typedef struct {
	// big endian
    uint64_t subkeys[NUMBER_OF_ROUNDS];
}block_state;


ErrCrypto des_init(block_state *pState, const uint8_t *pKey, uint32_t nKey);

ErrCrypto des_encrypt(block_state *pState
	, const uint8_t *pData
	, uint32_t nData
	, uint8_t *pCipher
	, uint32_t nOutBuf
	, uint32_t *pnCipher
	, DES_OPERATION op);

ErrCrypto des_decrypt(block_state *pState
	, uint8_t* pCipher
	, uint32_t nCipher
	, uint8_t *pOutPlain
	, uint32_t nOutBuf
	, uint32_t* pnPlain
	, OperationModes mode);

//ErrCrypto des_finalize();

void test_des();


#endif