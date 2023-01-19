#ifndef _SM4_H
#define _SM4_H


#include <common/common.h>

#define SM4_BLOCK_SIZE 16
#define SM4_Nb 4	// == number of state columns == SM4_BLOCK_SIZE / sizeof(dword)
#define SM4_KEY_SIZE 16


typedef struct {
	uint32_t w[60];	// max == Nb * (Nr+1)
	uint32_t dw[60];	// max == Nb * (Nr+1)

}StcSM4;

ErrCrypto sm4_init(StcSM4* pStcSM4, uint8_t *pKey, uint32_t nKey);

ErrCrypto sm4_encrypt(StcSM4* pStcSM4
	, uint8_t *in
	, uint32_t nIn/* = SM4_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = SM4_BLOCK_SIZE*/);

ErrCrypto sm4_decrypt(StcSM4* pStcSM4
	, uint8_t* in
	, uint32_t nIn/* = SM4_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = SM4_BLOCK_SIZE*/);

void test_sm4();


#endif

