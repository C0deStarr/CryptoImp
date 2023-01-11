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

/**
 * @brief 
 *		uint8_t pIn[] --> pUllOut
*/
static ErrCrypto PermutateArr(uint8_t *pPermutationChoice, uint32_t nChoice
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
	(*pUllOut) = 0;
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

		ullTmp = (0x8000000000000000  & (ullIn << nBitOffset));
		(*pUllOut) |= ullTmp >> i;
	}
	return errRet;
}

/**
 * @brief
 *		uint64_t ullIn --> pUllOut
*/
static ErrCrypto PermutateULL(uint8_t* pPermutationChoice, uint32_t nChoice
	, uint64_t ullIn
	, uint64_t* pUllOut)
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

	(*pUllOut) = 0;
	for (i = 0; i < nChoice; ++i)
	{
		nBitOffset = pPermutationChoice[i] - 1;
	
		ullTmp = (0x8000000000000000 & (ullIn << nBitOffset));
		(*pUllOut) |= ullTmp >> i;
	}
	return errRet;
}

ErrCrypto des_init(des_key* pStcKey, const uint8_t* pKey, uint32_t nKey)
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
	PermutateArr(pc1, 56, pKey, nKey, &ullPC1_56bits);


	ullC = ullPC1_56bits & 0xFFFFFFF000000000;
	ullD = ullPC1_56bits & 0x0000000FFFFFFF00;
	for (i = 0; i < 16; ++i)
	{
		ullC = ROTL28(LeftShifts[i], ullC) & 0xFFFFFFF000000000;
		ullD = ROTL28(LeftShifts[i], ullD) & 0x0000000FFFFFFF00;
	
		ullPC1_56bits = ullC | ullD;

		//u64to8_big(arrByPC1_56bits, ullPC1_56bits);
		// permutation choice 2
		PermutateULL(pc2, 48, ullPC1_56bits, &(pStcKey->subkeys[i]));
	
	}

	return errRet;
}


/* Initial Permutation Table 
* 64 bits --> 32 bit L + 32 bit R
*/
static const uint8_t IP[64] = {
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
static const uint8_t InverseIP[64] = {
	40,  8, 48, 16, 56, 24, 64, 32,
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25
};

/*	Extend table for f(R, k)
*/
static const uint8_t E[48] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};


/* The S-Box tables */
static const uint8_t S[8][64] = { 
{
		/* S1 */
		14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
	},{
		/* S2 */
		15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
	},{
		/* S3 */
		10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
	},{
		/* S4 */
		 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
	},{
		/* S5 */
		 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
	},{
		/* S6 */
		12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
	},{
		/* S7 */
		 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
	},{
		/* S8 */
		13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
	} 
};

/* For S-Box output*/
static const uint8_t P[32] = {
	16,  7, 20, 21,
	29, 12, 28, 17,
	 1, 15, 23, 26,
	 5, 18, 31, 10,
	 2,  8, 24, 14,
	32, 27,  3,  9,
	19, 13, 30,  6,
	22, 11,  4, 25
};

ErrCrypto des(des_key *pStcKey
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pOut
	, uint32_t nOutBuf
	, DES_OPERATION op)
{
	ErrCrypto errRet = ERR_OK;
	uint64_t ullData = 0;
	uint64_t L = 0, R = 0;
	uint64_t ullExtend_48bits = 0;
	uint32_t i = 0, j = 0;

	uint64_t ullS_Output = 0;
	uint64_t ullF = 0;
	uint64_t ullTmp = 0;
	uint8_t by6bits = 0;
	uint8_t nRow = 0;
	uint8_t nCol = 0;

	uint64_t ullRet = 0;


	if (!pStcKey || !pData || !pOut)
	{
		return ERR_NULL;
	}
	if ((BLOCK_SIZE != nData) || (BLOCK_SIZE > nOutBuf) )
	{
		return ERR_BLOCK_SIZE;
	}

	PermutateArr(IP, 64, pData, nData, &ullData);
	L = ullData & 0xFFFFFFFF00000000;
	R = (ullData << 32) & 0xFFFFFFFF00000000;


	for (i = 0; i < NUMBER_OF_ROUNDS; ++i)
	{
		// f(R, k)

		// extend
		ullExtend_48bits = 0;
		PermutateULL(E, 48, R, &ullExtend_48bits);


		// xor sub key
		if (ENC == op)
		{
			ullExtend_48bits ^= pStcKey->subkeys[i];
		}
		else
		{
			ullExtend_48bits ^= pStcKey->subkeys[NUMBER_OF_ROUNDS - 1- i];
		}

		// s-box
		for (j = 0; j < 8; ++j)
		{
			by6bits = ((ullExtend_48bits & (0xFC00000000000000 >> 6*j))
				>> (58 - 6*j));
			// bit 5 | bit 0
			nRow = ((by6bits >> 4 ) & 0x2) | (by6bits & 0x1);
			// bit 4 | bit 3 | bit 2 | bit 1
			nCol = (by6bits & 0x1E) >> 1;
			
			ullS_Output <<= 4;
			ullS_Output |= (uint32_t)(S[j][16*nRow+nCol] & 0xF);
		}

		// Permutation P
		ullS_Output <<= 32;
		PermutateULL(P, 32, ullS_Output, &ullF);

		ullTmp = R;
		R = L ^ ullF;
		L = ullTmp;
	}

	ullTmp = R | (L >> 32);

	// inverse initial permutation
	PermutateULL(InverseIP, 64, ullTmp, &ullRet);
	u64to8_big(pOut, ullRet);
	return errRet;
}




void test_des()
{
	des_key stcKey = {0};
	uint8_t data[] = { 0x94, 0x74, 0xB8, 0xE8, 0xC7, 0x3B, 0xCA, 0x7D };
	uint8_t szKey[] = { 0x10, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4A };
	uint8_t cipher[256] = { 0 };
	uint8_t buf[256] = { 0 };

	uint32_t nData = sizeof(data);
	uint32_t nKey = sizeof(szKey);
	uint32_t nBuf = sizeof(cipher);

	uint32_t i = 0;
	ErrCrypto err = ERR_OK;
	err = des_init(&stcKey, szKey, nKey);
	err = des(
		&stcKey
		, data
		, nData
		, cipher
		, nBuf
		, ENC);

	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");


	err = des(
		&stcKey
		, cipher
		, BLOCK_SIZE
		, buf
		, nBuf
		, DEC);

	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

}