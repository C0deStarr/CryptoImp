
#include "./sha3.h"
#include <string.h>
#include <common/endianess.h>
ErrCrypto sha3_init(KeccakState* pKeccakState, SHA3_ALG alg)
{
	ErrCrypto err = ERR_OK;
	if(!pKeccakState)
		return ERR_NULL;



	if ((SHAKE128 == alg) || (SHAKE256 == alg))
		return ERR_PARAM;

	//pKeccakState->nByCapacity = c;
	//pKeccakState->nByRate = KECCAK_b_200BYTES - c;

	pKeccakState->nRounds = NUMBER_OF_ROUNDS;

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
	pKeccakState->nByOffset = 0;
	return err;
}


static ErrCrypto ConvertS2Array(KeccakState* pKeccakState)
{
	uint32_t nLane = 0;

	if (!pKeccakState)
		return ERR_NULL;

	for (nLane = 0;
		(nLane < 25);
		++nLane)
	{
		// little endian
		// y: low-->high
		// operation: xor
		pKeccakState->ullArrStateLanes[nLane] ^= u8to64_little(pKeccakState->block[8*nLane]);
	}
	return ERR_OK;
}

//static ErrCrypto keccak_p(uint8_t* pBlock, uint32_t nr)
//static ErrCrypto keccak_f(uint64_t* pArrState/*, uint32_t nr==24 == 12+2*l*/)	
static ErrCrypto keccak_f(KeccakState* pKeccakState)
{
	ErrCrypto err = ERR_OK;
	uint32_t ir = 0;
	uint32_t i = 0;
	if(!pKeccakState)
		return ERR_NULL;
	if(pKeccakState->nRounds >= NUMBER_OF_ROUNDS)
		return ERR_NR_ROUNDS;
	
	// convert bits to state array
	ConvertS2Array(pKeccakState);

	for (ir = 0;	// ir = 12+2*l-nr
		ir < pKeccakState->nRounds;
		++ir)
	{

	}

	return err;
}

/*
*	data-->block-->keccak()-->state array
*/
static ErrCrypto keccak_absorb(KeccakState* pKeccakState,
	const uint8_t* pData,
	uint32_t nInLen)
{
	ErrCrypto err = ERR_OK;
	uint32_t nByCopy = 0;
	uint32_t nByNeeded = 0;
	if (!pKeccakState || !pData)
		return ERR_NULL;

	while (nInLen)
	{
		nByNeeded = pKeccakState->nByRate - pKeccakState->nByOffset;
		nByCopy = (nByNeeded > nInLen) ? nInLen : nByNeeded;
		// min rate is 72 bytes when capacity is 512*2 bits(sha3-512)
		memcpy(pKeccakState->block[pKeccakState->nByOffset], pData, nByCopy);
		pKeccakState->nByOffset += nByCopy;
		pData += nByCopy;
		nInLen -= nByCopy;

		
		if (pKeccakState->nByOffset == pKeccakState->nByRate)
		{
			keccak_f(pKeccakState->block, pKeccakState->nRounds);
			// wait for next r-byte block
			pKeccakState->nByOffset = 0;
		}
	}

	return err;
}


ErrCrypto sha3_update(KeccakState* pKeccakState, const uint8_t* pData, uint64_t nInLen)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pData)
		return ERR_NULL;

	err = keccak_absorb(pKeccakState, pData, nInLen);

	return err;
}

ErrCrypto sha3_final(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pDigest)
		return ERR_NULL;
	if (nDigest * 2 != pKeccakState->nByMd)
		return ERR_DIGEST_SIZE;

	// padding rule for sponge construction
	// fips 202 B.2
	memset(pKeccakState->block[pKeccakState->nByOffset]
		, 0
		, pKeccakState->nByRate - pKeccakState->nByOffset);
	if ((SHAKE128 != pKeccakState->alg)
		&& (SHAKE256 != pKeccakState->alg))
	{
		// sh3 hash functions
		pKeccakState->block[pKeccakState->nByOffset] = 0x06;
		pKeccakState->block[pKeccakState->nByRate - 1] = 0x80;
	}
	else
	{
		// sha3 xof
		if ((pKeccakState->nByRate - pKeccakState->nByOffset) >= 2)
		{
			pKeccakState->block[pKeccakState->nByOffset] = 0x1F;
			pKeccakState->block[pKeccakState->nByRate - 1] = 0x80;
		}
		else
		{
			pKeccakState->block[pKeccakState->nByOffset] = 0x9F;
		}
	}

	// the final absorb
	if(err = keccak_f(pKeccakState))
	{
		return err;
	}

	// squeeze
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