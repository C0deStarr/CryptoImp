#include "pkcs1_pss.h"
#include <common/util.h>
#include <string.h>
#include <stdlib.h>


/*
					  +-----------+
					  |     M     |
					  +-----------+
							|
							V
						   Hash
							|
							V
			 +--------+----------+----------+
		M¡¯ = |Padding1|   mHash  |   salt   |
			 +--------+----------+----------+
							 |
	 +--------+----------+   V
DB = |Padding2|   salt   |  Hash
	 +--------+----------+   |
			|                |
			V                |
			xor <--- MGF <---|
			|                |
			|                |
			V                V
	 +-------------------+----------+--+
EM = |      maskedDB     |    H     |bc|
	 +-------------------+----------+--+
	 |		M'  len = 8 + nHash + nSalt
	 +---------------------------
	 |		  MGF    	 |
	 +-------------------+
*/

ErrCrypto emsa_pss_encode(const uint8_t* pInMsg
	, uint32_t nMsg
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nEM = 0;
	uint32_t nHash = 0;
	PFnHash pfnHash = NULL;
	uint32_t nDB = 0;

	uint8_t* pEM = NULL;

	uint8_t* pDB = NULL;	// data block
	uint32_t nPadding2 = 8;
	uint8_t* pSaltInDB = NULL;

	uint8_t* pHash = NULL;
	uint8_t* pM1 = NULL;
	uint32_t nM1 = 0;
	const uint32_t nPadding1 = 8;
	uint8_t* pMsgHash = NULL;
	uint8_t* pSaltInM1 = NULL;

	uint8_t *pMGF = NULL;
	
	uint8_t  chMask = 0;
	uint32_t nMask = 0;

	if (!pInMsg || !pOut)
	{
		return ERR_NULL;
	}
	nEM = nEmBits / 8;
	if(nEmBits % 8)	++nEM;

	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if (!pfnHash) return ERR_PARAM;

	// step 1 length checking
	if (nMsg > nHash)
	{
		return ERR_MAX_DATA;
	}
	// step 3
	if (nEM < (nHash + nSalt + 2))
	{
		return ERR_MAX_DATA;
	}
	do {
		nDB = nEM - nHash - 1;
		nM1 = 8 + nHash + nSalt;
		pEM = (uint8_t*)calloc(nEM
			+ nM1
			+ nDB	// for MGF
			,1);
		if (!pEM)
		{
			errRet = ERR_MEMORY;
			break;
		}

		// step5 M1
		{
			// step 2 hash
			pM1 = pEM + nEM;
			pMsgHash = pM1 + nPadding1;
			errRet = pfnHash(pInMsg, nMsg, pMsgHash, nHash);
			if (errRet != ERR_OK) break;

			// step 4
			if (nSalt)
			{
				pSaltInM1 = pMsgHash + nHash;
				GetRandomBytes(pSaltInM1, nSalt);
			}
		}

		// step 6
		pHash = pEM + nEM;
		errRet = pfnHash(pM1, nM1, pHash, nHash);
		if (errRet != ERR_OK) break;

		// step 7 padding string in db
		// done by calloc

		// step 8
		//  DB = PS || 0x01 || salt
		pDB = pEM;
		nPadding2 = nEM - nSalt - nHash - 2;
		pDB[nPadding2] = 1;
		pSaltInDB = pDB + nPadding2 + 1;
		memcpy(pSaltInDB, pSaltInM1, nSalt);

		// step 9
		pMGF = pM1 + nM1;
		errRet = MGF1(pHash, nHash, nDB, enum_sha1, pMGF, nDB);
		if (errRet != ERR_OK) break;

		// step 10
		xor_buf(pMGF, pDB, nDB);

		// step 11
		nMask = 8 * nEM - nEmBits;
		while (nMask)
		{
			chMask = (chMask >> 1 ) | 0x80;
		}

		pDB[0] = pDB[0] & (~chMask);

		// step 12
		pHash[nHash] = 0xbc;


		memcpy(pOut, pEM, nEM);
	}while(0);

	if (pEM)
	{
		free(pEM);
		pEM = NULL;
		pEM = NULL;
		pDB = NULL;	// data block
		pSaltInDB = NULL;
		pHash = NULL;
		pM1 = NULL;
		pMsgHash = NULL;
		pSaltInM1 = NULL;
		pMGF = NULL;
	}

	return errRet;
}

ErrCrypto emsa_pss_verify(const uint8_t* pInMsg
	, uint32_t nMsg
	, const uint8_t* pInEM
	, uint32_t nEM
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits)
{
	ErrCrypto errRet = ERR_OK;
	if (!pInMsg || !pInEM)
	{
		return ERR_NULL;
	}
	return errRet;
}



void test_pss()
{

}
