
#include "./sha3.h"
#include <string.h>
#include <common/endianess.h>
#include <common/util.h>




/*

int LFSR86540(uint8_t* LFSR)
{
	int result = ((*LFSR) & 0x01) != 0;
	if (((*LFSR) & 0x80) != 0)
		// Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
		(*LFSR) = ((*LFSR) << 1) ^ 0x71;	// 0111 0001
	else
		(*LFSR) <<= 1;
	return result;
}

void KeccakInitializeRoundConstants()
{
	uint8_t LFSRstate = 0x01;
	unsigned int ir, j, bitPosition;
	uint8_t nr = 24;
	uint64_t KeccakRoundConstants[64] = {0};
	for (ir = 0; ir < nr; ir++) {
		KeccakRoundConstants[ir] = 0;
		for (j = 0; j < 7; j++) {
			bitPosition = (1 << j) - 1; //2^j-1
			if (LFSR86540(&LFSRstate))
				KeccakRoundConstants[ir] ^= (uint64_t)1 << bitPosition;
		}
	}
	for (ir = 0; ir < 24; ++ir)
	{
		printf("%016llx\n", KeccakRoundConstants[ir]);
	}
}
*/
static const uint64_t g_arrUllRoundConstants[NUMBER_OF_ROUNDS] = {
	0x0000000000000001ULL,    0x0000000000008082ULL,
	0x800000000000808aULL,    0x8000000080008000ULL,
	0x000000000000808bULL,    0x0000000080000001ULL,
	0x8000000080008081ULL,    0x8000000000008009ULL,
	0x000000000000008aULL,    0x0000000000000088ULL,
	0x0000000080008009ULL,    0x000000008000000aULL,
	0x000000008000808bULL,    0x800000000000008bULL,
	0x8000000000008089ULL,    0x8000000000008003ULL,
	0x8000000000008002ULL,    0x8000000000000080ULL,
	0x000000000000800aULL,    0x800000008000000aULL,
	0x8000000080008081ULL,    0x8000000000008080ULL,
	0x0000000080000001ULL,    0x8000000080008008ULL
};

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

	pKeccakState->bIsSqueezing = 0;
	return err;
}


ErrCrypto sha3_xof_init(KeccakState* pKeccakState, SHA3_ALG alg, uint32_t nDigest)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState)
		return ERR_NULL;
	if ((SHAKE128 != alg) && (SHAKE256 != alg))
		return ERR_PARAM;

	sha3_init(pKeccakState, SHA3_512);
	pKeccakState->alg = alg;
	switch (alg)
	{
	// SHAKE128(M,d) = KECCAK[256](M||1111,d), FIPS-202, sec 6.2
	case SHAKE128:  
		pKeccakState->nByRate = 168; // 1344 bits 
		pKeccakState->nByCapacity = 32;  //  256 bits == 128 * 2
		pKeccakState->nByMd = nDigest / 8;
		break;
	default:
	// SHAKE256(M,d) = KECCAK[512](M||1111,d), FIPS-202, sec 6.2
	case SHAKE256:  
		pKeccakState->nByRate = 136; // 1088 bits
		pKeccakState->nByCapacity = 64;  //  512 bits 
		pKeccakState->nByMd = nDigest / 8;
		break;
	}
	return err;
}

// absorb: block --> state array
static ErrCrypto keccak_absorb_convertS2Array(KeccakState* pKeccakState)
{
	uint32_t nLane = 0;

	if (!pKeccakState)
		return ERR_NULL;

	for (nLane = 0;
		8*nLane < pKeccakState->nByRate;
		++nLane)
	{
		// little endian
		// y: low-->high
		// operation: xor
		pKeccakState->ullArrStateLanes[nLane] ^= u8to64_little(&(pKeccakState->block[8*nLane]));
	}
	return ERR_OK;
}
// squeeze: state array --> block
static ErrCrypto keccak_squeeze_convertArray2S(KeccakState* pKeccakState)
{
	uint32_t nLane = 0;

	if (!pKeccakState)
		return ERR_NULL;

	for (nLane = 0;
		8 * nLane < pKeccakState->nByRate;
		++nLane)
	{
		// little endian
		// y: low-->high
		// operation: xor
		u64to8_little(&(pKeccakState->block[8 * nLane]), pKeccakState->ullArrStateLanes[nLane]);
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


	uint64_t (*pArrayState5_5)[5][5] = NULL;
	uint64_t (*pArrayState25)[25] = NULL;
	uint64_t ullCopiedArrayState5_5[5][5] = {0};	// for pi
	uint64_t theta_C[5] = { 0 };
	uint64_t theta_D[5] = { 0 };
	uint8_t x = 0, y = 0;
	uint8_t x1 = 0, y1 = 0;
	

	static const uint32_t rho_offset[5][5] = {
		   0,   1,  190,  28,  91,
		  36, 300,    6,  55, 276,
		   3,  10,  171, 153, 231,
		 105,  45,   15,  21, 136,
		 210,  66,  253, 120,  78
	};

	if(!pKeccakState)
		return ERR_NULL;
	if(pKeccakState->nRounds != NUMBER_OF_ROUNDS)
		return ERR_NR_ROUNDS;
	
	pArrayState25 = pKeccakState->ullArrStateLanes;
	pArrayState5_5 = pKeccakState->ullArrStateLanes;

	for (ir = 0;	// ir = 12+2*l-nr
		ir < pKeccakState->nRounds;
		++ir)
	{
		// theta
		// xor all the sheets --> plane theta_C
		for (i = 0; i < 5; ++i)
		{
			theta_C[i] = (*pArrayState25)[i]
				^ (*pArrayState25)[i + 5]
				^ (*pArrayState25)[i + 10]
				^ (*pArrayState25)[i + 15]
				^ (*pArrayState25)[i + 20];
		}

		for (i = 0; i < 5; ++i)
		{
			// D[x] = C[x-1] ^ ROTL( C[x+1],    1)
			theta_D[i] = theta_C[(i+4)%5] ^ ROTL64(theta_C[(i+1)%5], 1);
		}

		for (y = 0; y < 5; ++y)
		{
			for (x = 0; x < 5; ++x)
			{
				(*pArrayState5_5)[y][x] = (*pArrayState5_5)[y][x] ^ theta_D[x];
			}
		}
		// theta end

		// rho
		x = 1;
		y = 0;
		for (i = 1; i < 25; ++i)
		{
			(*pArrayState25)[x + 5 * y] = ROTL64((*pArrayState25)[x + 5 * y], rho_offset[y][x]%64);	// 64 == 8*sizeof(uint64_t)
			x1 = x;
			x = y;
			y = (2 * x1 + 3 * y) % 5;
		}

		// rho end

		// pi
		memcpy(ullCopiedArrayState5_5, pKeccakState->ullArrStateLanes, KECCAK_b_200BYTES);

		/*
		x = 1;
		y = 0;
		for (i = 0; i < 25; ++i)
		{
			x1 = (x + 3 * y) % 5;
			y1 = x;
			(*pArrayState5_5)[y][x] = (*pArrayState5_5)[y1][x1];
			x = x1;
			y = y1;
		}
		*/
		for (y = 0; y < 5; y++)
		{
			for (x = 0; x < 5; x++)
			{
		  		(*pArrayState5_5)[y][x] = ullCopiedArrayState5_5[x][(x + 3 * y) % 5];
			}
		}
		//pi end


		// chi 
		memcpy(ullCopiedArrayState5_5, pKeccakState->ullArrStateLanes, KECCAK_b_200BYTES);
		for (y = 0; y < 5; ++y)
		{
			for (x = 0; x < 5; ++x)
			{
				(*pArrayState5_5)[y][x] = ullCopiedArrayState5_5[y][x]
					^ ( ( ~(ullCopiedArrayState5_5[y][ ( x + 1 ) % 5 ]))
						& ullCopiedArrayState5_5[y][ ( x + 2 ) % 5 ]  );

			}
		}
		// chi end

		// iota
		(*pArrayState25)[0] ^= g_arrUllRoundConstants[ir];
		// iota end
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

	if(pKeccakState->bIsSqueezing)
		return ERR_UNKNOWN;

	while (nInLen)
	{
		nByNeeded = pKeccakState->nByRate - pKeccakState->nByOffset;
		nByCopy = (nByNeeded > nInLen) ? nInLen : nByNeeded;
		// min rate is 72 bytes when capacity is 512*2 bits(sha3-512)
		memcpy(&(pKeccakState->block[pKeccakState->nByOffset])
			, pData
			, nByCopy);
		pKeccakState->nByOffset += nByCopy;
		pData += nByCopy;
		nInLen -= nByCopy;

		
		if (pKeccakState->nByOffset == pKeccakState->nByRate)
		{
			// convert bits to state array
			keccak_absorb_convertS2Array(pKeccakState);
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

ErrCrypto sha3_xof_update(KeccakState* pKeccakState, const uint8_t* pData, uint64_t nInLen)
{
	return sha3_update(pKeccakState, pData, nInLen);
}


ErrCrypto sha3_final(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	ErrCrypto err = ERR_OK;
	uint32_t nSqueeze = 0;

	if (!pKeccakState || !pDigest)
		return ERR_NULL;
	if (nDigest < pKeccakState->nByMd)
		return ERR_MEMORY;
	if (!(pKeccakState->bIsSqueezing))
	{
		// padding rule for sponge construction
		// fips 202 B.2
		memset(&(pKeccakState->block[pKeccakState->nByOffset])
			, 0
			, pKeccakState->nByRate - pKeccakState->nByOffset);
		if ((SHAKE128 != pKeccakState->alg)
			&& (SHAKE256 != pKeccakState->alg))
		{
			// sh3 hash functions
			pKeccakState->block[pKeccakState->nByOffset] = 0x06;
			pKeccakState->block[pKeccakState->nByRate - 1] |= 0x80;
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
		// convert bits to state array
		keccak_absorb_convertS2Array(pKeccakState);
		if(err = keccak_f(pKeccakState))
		{
			return err;
		}

		// begin squeezing
		pKeccakState->bIsSqueezing = 1;
		keccak_squeeze_convertArray2S(pKeccakState);
		pKeccakState->nByOffset = pKeccakState->nByRate;
	}
	nDigest = pKeccakState->nByMd;
	while (nDigest)
	{
		nSqueeze = (nDigest < pKeccakState->nByOffset) ? nDigest : pKeccakState->nByOffset;
		memcpy(pDigest
			, &(pKeccakState->block[pKeccakState->nByRate - pKeccakState->nByOffset])
			, nSqueeze);

		pKeccakState->nByOffset -= nSqueeze;
		pDigest += nSqueeze;
		nDigest -= nSqueeze;

		if (0 == pKeccakState->nByOffset)
		{
			keccak_f(pKeccakState);
			keccak_squeeze_convertArray2S(pKeccakState);
			pKeccakState->nByOffset = pKeccakState->nByRate;
		}

	}
	return err;
}

ErrCrypto sha3_xof_final(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	return sha3_final(pKeccakState, pDigest, nDigest);
}


void test_sha3()
{
	KeccakState keccakState = {0};

	uint8_t data[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	uint8_t digest[MAX_MD_SIZE] = {0};
	uint8_t nDigest = MAX_MD_SIZE;
	uint8_t i = 0;
	SHA3_ALG alg = SHAKE256;
	sha3_xof_init(&keccakState, alg, 256);
	sha3_xof_update(&keccakState, data, sizeof(data) - 1);
	sha3_xof_final(&keccakState, digest, nDigest);
	for (i = 0; i < keccakState.nByMd; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}