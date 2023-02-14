#ifndef _CHACHA20_H
#define _CHACHA20_H

#include <common/common.h>

#define CHACHA20_HASH_WORD_NUM 16
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_KEYSTREAM_LEN 64

typedef struct {
	uint32_t hash[CHACHA20_HASH_WORD_NUM];
    uint8_t keystream[CHACHA20_KEYSTREAM_LEN];
}chacha20;


ErrCrypto chacha20_init(chacha20* pState,
    const uint8_t* pKey,
    uint32_t nKey,
    const uint8_t* pNonce,
    uint32_t nNonce);

void test_chacha20();

#endif // !_CHACHA20_H

