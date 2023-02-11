#ifndef _SM3_H
#define _SM3_H

#include <common/common.h>

#define WORD_SIZE 4
#define SM3_BLOCK_SIZE 64   // 16 * WORD_SIZE
#define SM3_DIGEST_SIZE 32 // 256/8
typedef struct {
	uint32_t hash[8];
	uint8_t block[SM3_BLOCK_SIZE];
	uint8_t nBytesLen; // index of block
	uint64_t nBitsLen;
}SM3_HashState;

ErrCrypto SM3_init(SM3_HashState* pHashState);
ErrCrypto SM3_update(SM3_HashState* pHashState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto SM3_final(SM3_HashState* pHashState, uint8_t* pDigest, int nDigest);
ErrCrypto SM3_digest(
	const uint8_t* pData, uint64_t nData
	, uint8_t* pDigest, uint32_t nDigest);
void test_sm3();

#endif