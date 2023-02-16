#ifndef _ZUC_H
#define _ZUC_H

#include <common/common.h>


# define ZUC_KEY_SIZE	16
# define ZUC_IV_SIZE	16

typedef struct {
	uint32_t LFSR[16];
	uint32_t R1;
	uint32_t R2;
} ZUC;

ErrCrypto zuc_init(ZUC* pState
	, const uint8_t *pKey, uint32_t nKey/* = ZUC_KEY_SIZE*/
	, const uint8_t *pIV, uint32_t nIV/* =ZUC_IV_SIZE*/
);

ErrCrypto zuc_generate_keystream(ZUC* pState
	, uint32_t nWords
	, uint32_t* keystream);

ErrCrypto zuc_encrypt(ZUC* pState
	, const uint8_t* pIn
	, uint32_t nIn
	, uint8_t* pOut);


void test_zuc();

#endif // !_ZUC_H
