
#include "./sha3.h"
#include <string.h>

ErrCrypto sha3_init(KeccakState* pKeccakState, SHA3_ALG alg)
{
	ErrCrypto err = ERR_OK;
	if(!pKeccakState)
		return ERR_NULL;



	if ((SHAKE128 == alg) || (SHAKE256 == alg))
		return ERR_PARAM;

	//pKeccakState->nByCapacity = c;
	//pKeccakState->nByRate = KECCAK_b_200BYTES - c;

	pKeccakState->nr = NUMBER_OF_ROUNDS;

	pKeccakState->alg = alg;
	switch (alg)
	{
		case 	SHA3_224:
			{
				pKeccakState->nByMd= 28;
				// 2 * md size
				pKeccakState->nByCapacity = 56;		// 448 bits
				// b - capacity
				pKeccakState->nByRate = 144;	// 1152 bits
			}
			break;
		case 	SHA3_256:
			{
				pKeccakState->nByMd = 32;
				pKeccakState->nByCapacity = 64;	// 512 bits
				pKeccakState->nByRate = 136;	// 1088 bits
			}
			break;
		case 	SHA3_384:
			{
				pKeccakState->nByMd = 48;
				pKeccakState->nByCapacity = 96;	// 768 bits	
				pKeccakState->nByRate = 104;	// 832 bits
			}
			break;
		default: /* default Keccak setting: SHA3_512 */
		case 	SHA3_512:
			{
				pKeccakState->nByMd = 64;
				pKeccakState->nByCapacity = 128;	// 1024 bits
				pKeccakState->nByRate = 72;		// 576 bits
			}
			break;
	}

	memset(pKeccakState->ullArrStateLanes, 0, KECCAK_b_200BYTES);

	return err;
}

static ErrCrypto keccak_p(uint64_t* pArrState, uint32_t nr)
//static ErrCrypto keccak_f(uint64_t* pArrState/*, uint32_t nr==24 == 12+2*l*/)	
{
	ErrCrypto err = ERR_OK;
	uint32_t ir = 0;	// ir = 12+2*l-nr
	if(!pArrState)
		return ERR_NULL;
	if(nr >= NUMBER_OF_ROUNDS)
		return ERR_NR_ROUNDS;
	

	for (ir = NUMBER_OF_ROUNDS - nr/*=0*/; ir < nr; ++ir)
	{

	}

	return err;
}


ErrCrypto sha3_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pBuf)
		return ERR_NULL;
	return err;
}
ErrCrypto sha3_final(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pDigest)
		return ERR_NULL;
	return err;
}

void test_sha3()
{
	KeccakState keccakState = {0};

	uint8_t data[] = "abc";
	uint8_t digest[MAX_MD_SIZE] = {0};
	uint8_t nDigest = 28;
	uint8_t i = 0;
	uint32_t nCapacity224 = 28;
	SHA3_ALG alg = SHA3_224;
	sha3_init(&keccakState, alg);
	sha3_update(&keccakState, data, sizeof(data) - 1);
	sha3_final(&keccakState, digest, nDigest);
	for (i = 0; i < nDigest; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}