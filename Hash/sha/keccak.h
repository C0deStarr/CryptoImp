
#ifndef _KECCAK_H
#define _KECCAK_H

#include <common/common.h>

/*
* l = 6, w = 64, b = 1600
*/

#define KECCAK_b_200BYTES	200	// 1600/8
#define MAX_MD_SIZE	64	// sha3-512
#define NUMBER_OF_ROUNDS 24	// for keccak-f, number of round == 12 + 2*l == 24

typedef struct
{
	// w == b / 25 == length of lane == 8 bytes == sizeof(uint64_t)
	uint64_t ullArrStateLanes[5][5];

	// as long as the array state
	uint8_t buf[KECCAK_b_200BYTES];

	// c + r == b
	uint32_t nByCapacity;
	uint32_t nByRate;

	// number of round
	uint32_t nr;
}KeccakState;

/*
*
* args:
*	c: number of bytes of capacity
*/
ErrCrypto keccak_init(KeccakState* pKeccakState, uint32_t c /*, uint32_t nr = 24*/);
ErrCrypto keccak_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto keccak_digest(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest);
void test_keccak();
#endif