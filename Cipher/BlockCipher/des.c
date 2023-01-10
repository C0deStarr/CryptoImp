#include "des.h"
#include <common/endianess.h>
/*
* Permuted choice
* 64 bits --> 28 bits + 28 bits
*/
static const uint8_t pc1[56] = {
	// C
	57, 49,  41, 33,  25,  17,  9,
	 1, 58,  50, 42,  34,  26, 18,
	10,  2,  59, 51,  43,  35, 27,
	19, 11,   3, 60,  52,  44, 36,
	// D
	63, 55,  47, 39,  31,  23, 15,
	 7, 62,  54, 46,  38,  30, 22,
	14,  6,  61, 53,  45,  37, 29,
	21, 13,   5, 28,  20,  12,  4
};

#define ROTL28(n, x)   (((x)<<(n)) | ((x)>>(28-(n))))

static const unsigned char LeftShifts[NUMBER_OF_ROUNDS] = {
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

/*
* Permuted choice 2
*	56 bits --> 48 bits subkey
*/
static const unsigned char pc2[48] = {
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

static ErrCrypto Permutate(uint8_t *pPermutationChoice, uint32_t nChoice
	, uint8_t *pIn, uint32_t nInBytes
	, uint64_t *pUllOut
	/*, uint8_t *pOut, uint32_t nOutBytes*/)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nBitOffset= 0;
	//uint8_t  byPermutedChoice = 0;
	uint64_t ullIn = 0;
	uint64_t ullTmp = 0;
	uint64_t ullRet = 0;
	uint32_t i = 0;
	if (!pPermutationChoice || !pUllOut/*|| !pOut*/)
	{
		return ERR_NULL;
	}
	// if ((nOutBytes * 8) < nChoice)
	// {
	// 	return ERR_MEMORY;
	// }
	if (nInBytes > 8/*sizeof(ullIn)*/)
	{
		return ERR_MEMORY;
	}
	ullIn = u8to64_big(pIn);
	for (i = 0; i < nChoice; ++i)
	{
		nBitOffset = pPermutationChoice[i] - 1;
		//if ((nBitOffset >> 3) > (nInBytes - 1))
		//{
		//	errRet = ERR_MEMORY;
		//	break;
		//}
		//// big endian
		//byPermutedChoice = 0x80 >> (nBitOffset & 7);	// % 8: bit offset in the byte
		//byPermutedChoice &= pIn[nBitOffset >> 3];	//  /8: the bit in original key byte 
		//byPermutedChoice <<= nBitOffset & 7;	// // 0x80 or 0x00
		//
		//pOut[i / 8] |= byPermutedChoice >> (i % 8);

		ullTmp = ((0x8000000000000000 >> nBitOffset) & (ullIn)) 
			<< nBitOffset;
		(*pUllOut) |= ullTmp >> i;
	}
	return errRet;
}

static ErrCrypto PermutateEx(uint8_t* pPermutationChoice, uint32_t nChoice
	, uint64_t ullIn
	, uint64_t* pUllOut
/*, uint8_t *pOut, uint32_t nOutBytes*/)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nBitOffset = 0;
	//uint8_t  byPermutedChoice = 0;
	uint64_t ullTmp = 0;
	uint64_t ullRet = 0;
	uint32_t i = 0;
	if (!pPermutationChoice || !pUllOut/*|| !pOut*/)
	{
		return ERR_NULL;
	}


	for (i = 0; i < nChoice; ++i)
	{
		nBitOffset = pPermutationChoice[i] - 1;
	
		ullTmp = ((0x8000000000000000 >> nBitOffset) & (ullIn))
			<< nBitOffset;
		(*pUllOut) |= ullTmp >> i;
	}
	return errRet;
}

ErrCrypto des_init(block_state* pStcKey, const uint8_t* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;

	
	uint64_t ullC = 0, ullD = 0;
	uint32_t i = 0, j = 0;
	//uint8_t arrByPC1_56bits[8] = {0};
	uint64_t ullPC1_56bits = 0;

	if(!pKey)
	{
		return ERR_NULL;
	}

	if (KEY_SIZE != nKey)
	{
		return ERR_KEY_SIZE;
	}



	// permutation choice 1
	Permutate(pc1, 56, pKey, nKey, &ullPC1_56bits);


	ullC = ullPC1_56bits & 0xFFFFFFF000000000;
	ullD = ullPC1_56bits & 0x0000000FFFFFFF00;
	for (i = 0; i < 16; ++i)
	{
		ullC = ROTL28(LeftShifts[i], ullC) & 0xFFFFFFF000000000;
		ullD = ROTL28(LeftShifts[i], ullD) & 0x0000000FFFFFFF00;
	
		ullPC1_56bits = ullC | ullD;

		//u64to8_big(arrByPC1_56bits, ullPC1_56bits);
		// permutation choice 2
		PermutateEx(pc2, 48, ullPC1_56bits, &(pStcKey->subkeys[i]));
	
	}

	return errRet;
}


/* Initial Permutation Table 
* 64 bits --> 32 bit L + 32 bit R
*/
static const uint8_t IP[] = {
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
	64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7
};

/* Inverse Initial Permutation Table */
static const uint8_t InverseIP[] = {
	40,  8, 48, 16, 56, 24, 64, 32,
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25
};

ErrCrypto des_encrypt(block_state *pState
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pCipher
	, uint32_t nOutBuf
	, uint32_t* pnCipher
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	uint64_t ullData = 0;
	uint32_t L = 0, R = 0;
	if (!pState || !pData || !pCipher || !pnCipher)
	{
		return ERR_NULL;
	}
	if ((BLOCK_SIZE != nData) || (BLOCK_SIZE > nOutBuf) )
	{
		return ERR_BLOCK_SIZE;
	}

	Permutate(IP, 64, pData, nData, &ullData);
	L = (ullData >> 32) & 0xFFFFFFFF;
	R = ullData & 0xFFFFFFFF;

	return errRet;
}

ErrCrypto des_decrypt(block_state *pState
	, uint8_t* pCipher
	, uint32_t nCipher
	, uint8_t* pOutPlain
	, uint32_t nOutBuf
	, uint32_t* pnPlain
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	if (!pState || !pCipher || !pOutPlain || !pnPlain)
	{
		return ERR_NULL;
	}

	return errRet;
}



void test_des()
{
	block_state state = {0};
	uint8_t data[] = { 0x94, 0x74, 0xB8, 0xE8, 0xC7, 0x3B, 0xCA, 0x7D };
	uint8_t szKey[] = { 0x10, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4A };
	uint8_t cipher[256] = { 0 };
	uint8_t buf[256] = { 0 };

	uint32_t nData = sizeof(data);
	uint32_t nKey = sizeof(szKey);
	uint32_t nBuf = sizeof(cipher);
	uint32_t nCipher = 0;
	uint32_t nDecrypt = 0;
	uint32_t i = 0;
	ErrCrypto err = ERR_OK;
	err = des_init(&state, szKey, nKey);
	err = des_encrypt(
		&state
		, data
		, nData
		, cipher
		, nBuf
		, &nCipher
		, MODE_ECB);

	for (i = 0; i < nCipher; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");


	err = des_decrypt(
		&state
		, cipher
		, nBuf
		, buf
		, nBuf
		, &nDecrypt
		, MODE_ECB);

	for (i = 0; i < nCipher; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");

}