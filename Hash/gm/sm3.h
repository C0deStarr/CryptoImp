#ifndef _SM3_H
#define _SM3_H

#include <common/common.h>

#define BLOCK_SIZE 64   // 16 * WORD_SIZE
#define DIGEST_SIZE (256/8)
typedef struct {
	uint32_t hash[8];
	uint8_t block[BLOCK_SIZE];
	uint8_t nByIndex; // index of block
}HashState;

ErrCrypto SM3_init(HashState* pHashState);
ErrCrypto SM3_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SM3_final(HashState* pHashState, uint8_t* pDigest, int nDigest);
void test_sm3();

#endif