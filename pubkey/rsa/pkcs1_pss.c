/*
Usage condition:
	RSA_Init()
*/

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

uint32_t emsa_pss_encode(const uint8_t* pInMsg
	, uint32_t nMsg
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut)
{
	uint32_t nRet = 0;
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

	if (nOut < nEM)
	{
		return ERR_NOT_ENOUGH_DATA;
	}

	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if (!pfnHash) return ERR_PARAM;

	// step 1 length checking
	if (nMsg > nHash)
	{
		return 0;
	}
	// step 3
	if (nEM < (nHash + nSalt + 2))
	{
		return 0;
	}
	do {
		nDB = nEM - nHash - 1;
		nM1 = 8 + nHash + nSalt;
		pEM = (uint8_t*)calloc(nEM
			+ nM1
			+ nDB + nHash	// for MGF
			,1);
		if (!pEM)
		{
			//nRet = ERR_MEMORY;
			break;
		}

		// step5 M1
		{
			// step 2 hash
			pM1 = pEM + nEM;
			pMsgHash = pM1 + nPadding1;
			if (ERR_OK != pfnHash(pInMsg, nMsg, pMsgHash, nHash)) break;

			// step 4
			if (nSalt)
			{
				pSaltInM1 = pMsgHash + nHash;
				GetRandomBytes(pSaltInM1, nSalt);
			}
		}

		// step 6
		pHash = pEM + nDB;
		if (ERR_OK != pfnHash(pM1, nM1, pHash, nHash)) break;

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
		if(ERR_OK != MGF1(pHash, nHash, nDB, enum_sha1, pMGF, nDB))	break;

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
		nRet = nEM;
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

	return nRet;
}

ErrCrypto emsa_pss_verify(const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, const uint8_t* pInEM
	, uint32_t nEM
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits)
{
	ErrCrypto errRet = ERR_OK;
	if (!pInMsgHash || !pInEM)
	{
		return ERR_NULL;
	}
	return errRet;
}

uint32_t pkcs1_pss_sign(RSA* pPriKey
	, const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut)
{
	uint32_t nRet = ERR_OK;
	uint32_t nEncoding;
	big bigEM = NULL;
	big bigSignature = NULL;
	if (!pPriKey || !pInMsgHash || !pOut)
	{
		return ERR_NULL;
	}
	
	nEncoding = emsa_pss_encode(pInMsgHash, nMsgHash
		, enum_sha1
		, nSalt
		, nEmBits
		, pOut, nOut);
	if (0 == nEncoding) return ERR_UNKNOWN;

	bigEM = mirvar(0);
	bigSignature = mirvar(0);
	bytes_to_big(nEncoding, pOut, bigEM);
	RSA_Encrypt(pPriKey, bigEM, bigSignature);
	nRet = big_to_bytes(nEncoding, bigEM, pOut, TRUE);

	return nRet;
}

ErrCrypto pkcs1_pss_verify(RSA* pPriKey
	, const uint8_t* pInMsg
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
	RSA rsa = { 0 };
	RSA_BITS enumBits = RSA_1024;

	uint8_t msg[] = { "abcdefgh" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t msgHash[MAX_SIZE_OF_DIGEST] = { 0 };
	enum_hash enumHash = enum_sha1;
	uint32_t nHash = 0;
	PFnHash pfnHash = NULL;

	uint8_t signature[384] = { 0 };
	uint32_t nSignature = enumBits / 8;
	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);

	pfnHash(msg, nMsg, msgHash, nHash);

	RSA_Init(&rsa, enumBits);


	pkcs1_pss_sign(&rsa
		, msgHash, nHash
		, enumHash
		, 0
		, enumBits
		, signature, nSignature);

	printf("signature:\n");
	output_buf(signature, nSignature);

}
