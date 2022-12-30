
#ifndef _SHA3_H
#define _SHA3_H

#include <common/common.h>

/*
* l = 6, w = 64, b = 1600
*/

#define KECCAK_b_200BYTES	200	// 1600/8
#define MAX_MD_SIZE	64	// sha3-512
#define NUMBER_OF_ROUNDS 24	// for keccak-f, number of round == 12 + 2*l == 24

typedef enum sha3_algorithm {
	SHA3_224,
	SHA3_256,
	SHA3_384,
	SHA3_512,
	SHAKE128,
	SHAKE256
}SHA3_ALG;

typedef struct
{
	// w == b / 25 == length of lane == 8 bytes == sizeof(uint64_t)
	uint64_t ullArrStateLanes[5][5];

	// as long as the array state
	// used to store r bytes as block
	uint8_t block[KECCAK_b_200BYTES];
	uint32_t nByOffset;

	// c + r == b
	uint32_t nByCapacity;
	uint32_t nByRate;	// rate for sponge construction

	// number of round
	uint32_t nr;

	SHA3_ALG alg;
	uint32_t nByMd;
}KeccakState;

/*
*
* args:
*	c: number of bytes of capacity
*/
ErrCrypto sha3_init(KeccakState* pKeccakState /*, uint32_t nr = 24*/);
ErrCrypto sha3_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen);
ErrCrypto sha3_final(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest);
void test_sha3();
#endif