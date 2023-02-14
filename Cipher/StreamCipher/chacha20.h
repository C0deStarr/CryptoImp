#ifndef _CHACHA20_H
#define _CHACHA20_H

#include <common/common.h>

#define CHACHA20_HASH_WORD_NUM 16
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_KEYSTREAM_LEN 64

typedef struct {
	uint32_t hash[CHACHA20_HASH_WORD_NUM];
    uint8_t keystream[CHACHA20_KEYSTREAM_LEN];
    uint32_t nNonce;
    uint32_t nKeyStreamUsedOffset;
}chacha20;


ErrCrypto chacha20_init(chacha20* pState,
    const uint8_t* pKey,
    uint32_t nKey,
    const uint8_t* pNonce,
    uint32_t nNonce);

ErrCrypto chacha20_block_func(chacha20* pState);

ErrCrypto chacha20_encrypt(chacha20* state,
    const uint8_t *pIn, uint32_t nIn
    , uint8_t *pOut, uint32_t nOut);

void test_chacha20();

#endif // !_CHACHA20_H

