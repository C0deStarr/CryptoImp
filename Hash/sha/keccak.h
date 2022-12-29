
#ifndef _KECCAK_H
#define _KECCAK_H

#include <common/common.h>

#define KECCAK_b1600bits_200bytes	200
#define MAX_MD_SIZE	64	// sha3-512
typedef struct
{
	// w == b / 25 == length of lane == 8 bytes == sizeof(uint64_t)
	uint64_t ullArrStateLanes[5][5];

	// as long as the array state
	uint8_t buf[KECCAK_b1600bits_200bytes];
}KeccakState;

ErrCrypto keccak_init(KeccakState* pKeccakState);
ErrCrypto keccak_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto keccak_digest(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest);
void test_keccak();
#endif