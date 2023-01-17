#ifndef _AES_H
#define _AES_H


#include <common/common.h>

#define AES_BLOCK_SIZE 16
#define AES_Nb 4	// == number of state columns == AES_BLOCK_SIZE / sizeof(dword)

typedef enum {
	aes128 = 128,	// Nr = 10; Nk = 4 dword
	aes192 = 192,	// Nr = 12; Nk = 6 dword
	aes256 = 256	// Nr = 14; Nk = 8 dword
}aes_key_size;

typedef struct {
	uint32_t w[60];	// max == Nb * (Nr+1)
	aes_key_size nKeyBitsSize;
	//uint32_t Nb;
	uint32_t Nr;
	uint32_t Nk;
}StcAES;

ErrCrypto aes_init(StcAES* pStcAES, aes_key_size nAesKeySize, uint8_t *pKey, uint32_t nKey);

ErrCrypto aes_encrypt(StcAES* pStcAES
	, uint8_t *in
	, uint32_t nIn/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = AES_BLOCK_SIZE*/);

void test_aes();

#endif

