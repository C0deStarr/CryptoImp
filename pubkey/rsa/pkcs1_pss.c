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

uint32_t emsa_pss_encode(const uint8_t* pInMsgHash
	, uint32_t nMsgHash
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
	uint32_t nMGF = 0;
	
	uint8_t  chMask = 0;
	uint32_t nMask = 0;

	if (!pInMsgHash || !pOut)
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
	if (nMsgHash > nHash)
	{
		return 0;
	}
	// step 3
	if (nEM < (nHash + nSalt + 2))
	{
		return 0;
	}
	do {
		nDB = nEM - nHash
			- 1;	// 0xbc
		nMGF = nDB + nHash;
		nM1 = nPadding1 + nHash + nSalt;
		pEM = (uint8_t*)calloc(nEM
			+ nM1
			+ nMGF
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
			if (ERR_OK != pfnHash(pInMsgHash, nMsgHash, pMsgHash, nHash)) break;

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
		if(0 == MGF1(pHash, nHash, nDB, enum_sha1, pMGF, nMGF))	break;

		// step 10
		xor_buf(pMGF, pDB, nDB);

		// step 11
		nMask = 8 * nEM - nEmBits;
		while (nMask--)
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
	ErrCrypto errRet = ERR_SIGNATURE_VERIFY;
	uint32_t nHash = 0;
	PFnHash pfnHash = NULL;

	uint8_t* pDBInEM = NULL;
	uint8_t *pHashInEM = NULL;

	uint32_t nDB = 0;

	uint8_t *pBuf = NULL;
	uint8_t* pM1InBuf = NULL;
	uint8_t* pSaltInM1 = NULL;

	uint8_t* pHashInBuf = NULL;
	uint8_t* pMGFInBuf = NULL;
	uint8_t* pSaltInDB = NULL;

	uint32_t nMGF = 0;
	//uint8_t* pDBInBuf = NULL;
	uint32_t nM1 = 0;


	uint32_t nMask = 0;
	uint8_t  chMask = 0;

	const uint32_t nPadding1 = 8;	// should be 8
	uint32_t nPadding2 = 0;
	uint32_t i = 0;

	if (!pInMsgHash || !pInEM)
	{
		return ERR_NULL;
	}

	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if (!pfnHash) return ERR_PARAM;

	// step 1 length checking
	if (nMsgHash > nHash)
	{
		return ERR_DIGEST_SIZE;
	}
	// step 3
	if (nEM < (nHash + nSalt + 2))
	{
		return ERR_BLOCK_SIZE;
	}

	// step 4
	if (pInEM[nEM - 1] != 0xbc)
	{
		return errRet;
	}


	do{
		// step 5
		nDB = nEM - nHash
			- 1;	// 0xbc
		pDBInEM = pInEM;
		pHashInEM = pDBInEM + nDB;

		// step 6
		nMask = 8 * nEM - nEmBits;
		while (nMask--)
		{
			chMask = (chMask >> 1) | 0x80;
		}
		if (chMask & pDBInEM[0]) break;

		/* alloc buf
			+ -------------------------- -
			| M'  len = 8 + nHash + nSalt
			+ -------------------------- -
			| MGF 
			+------------------ - +
		*/
		
		nMGF = nDB + nHash;
		nM1 = nPadding1 + nHash + nSalt;
		pBuf = (uint8_t*)calloc(nM1
			+ nMGF
			, 1);
		if (!pBuf)
		{
			errRet = ERR_MEMORY;
			break;
		}

		// step 2
		pM1InBuf = pBuf;
		pHashInBuf = pM1InBuf + nPadding1;
		if (ERR_OK != pfnHash(
			pInMsgHash, nMsgHash
			, pHashInBuf, nHash)) break;


		// step 7
		pMGFInBuf = pBuf + nM1;
		if (0 == MGF1(pHashInEM, nHash, nDB, enum_sha1, pMGFInBuf, nMGF))	break;

		// step 8
		xor_buf(pDBInEM, pMGFInBuf, nDB);

		// step 9
		nMask = 8 * nEM - nEmBits;
		while (nMask--)
		{
			chMask = (chMask >> 1) | 0x80;
		}
		//pDBInBuf = pMGFInBuf;
		pMGFInBuf[0] = pMGFInBuf[0] & (~chMask);
		

		// step 10 check DB
		//	padding2
		//	0x1
		nPadding2 = nEM - nHash - nSalt - 2;
		for (i = 0; i < nPadding2; ++i)
		{
			if(0 != pMGFInBuf[i]) break;
		}
		if( i != nPadding2 ) break;

		if(1 != pMGFInBuf[nPadding2]) break;

		// step 11 salt in DB
		pSaltInDB = &pMGFInBuf[nPadding2+1];

		// step 12 
		// M¡¯ = (0x)00 00 00 00 00 00 00 00 || mHash || salt
		pSaltInM1 = pM1InBuf + nPadding1 + nHash;
		memcpy(pSaltInM1, pSaltInDB, nSalt);

		// step 13 Hash(M')
		if (ERR_OK != pfnHash(pM1InBuf, nM1, pHashInBuf, nHash)) break;

		// step 14
		if (0 == memcmp(pHashInBuf, pHashInEM, nHash))
		{
			errRet = ERR_OK;
		}

	}while(0);

	if (pBuf)
	{
		free(pBuf);
		pBuf = NULL;
		pHashInBuf = NULL;
		pMGFInBuf = NULL;
	}

	return errRet;
}

uint32_t pkcs1_pss_sign(RSA_KEY* pPriKey
	, const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, enum_hash enumHash
	, uint32_t nSalt
	//, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut
#ifdef _DEBUG
	, big bigOutEM
#endif
	)
{
	uint32_t nRet = ERR_OK;
	uint32_t nEncoding;
	big bigEM = NULL;
	big bigSignature = NULL;
	uint32_t nKeyBits = 0;
	if (!pPriKey || !pInMsgHash || !pOut)
	{
		return ERR_NULL;
	}
	
	// step 1
	nKeyBits = numdig(pPriKey->n);
	nEncoding = emsa_pss_encode(pInMsgHash, nMsgHash
		, enum_sha1
		, nSalt
		, nKeyBits - 1
		, pOut, nOut);
	if (0 == nEncoding) return ERR_UNKNOWN;

	// step 2a
	bigEM = mirvar(0);
	bigSignature = mirvar(0);
	bytes_to_big(nEncoding, pOut, bigEM);
#ifdef _DEBUG
	copy(bigEM, bigOutEM);
#endif
	// step 2b
	RSA_Encrypt(pPriKey, bigEM, bigSignature);

	// step 2c
	nRet = big_to_bytes(nEncoding, bigSignature, pOut, TRUE);

	return nRet;
}

ErrCrypto pkcs1_pss_verify(RSA_KEY* pPubKey
	, const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, const uint8_t* pInSignature
	, uint32_t nSignature
	, enum_hash enumHash
	, uint32_t nSalt
	//, uint32_t nEmBits
#ifdef _DEBUG
	, big bigOriEM
#endif
	)
{
	ErrCrypto errRet = ERR_SIGNATURE_VERIFY;
	uint32_t nKey = 0;
	big bigSignature = NULL;
	big bigEM = NULL;
	uint8_t em[RSA_MAX_BITS] = {0};
	//uint32_t nEM = 0;
	uint32_t nKeyBits = 0;
	if (!pPubKey || !pInMsgHash || !pInSignature)
	{
		return ERR_NULL;
	}
	nKeyBits = numdig(pPubKey->n);
	nKey = nKeyBits / 8;

	// step 1
	if (nKey != nSignature)
	{
		return ERR_SIGNATURE_SIZE;
	}

	// step 2a
	bigSignature = mirvar(0);
	bytes_to_big(nKey, pInSignature, bigSignature);
	// step 2b
	bigEM = mirvar(0);
	RSA_Decrypt(pPubKey, bigSignature, bigEM);
#ifdef _DEBUG
	if (0 == mr_compare(bigOriEM, bigEM))
	{
		printf("verify() decrypt ok\n");
	}
#endif
	//nEM = numdig(bigEM) / 8;

	if (nKey == big_to_bytes(nKey, bigEM, em, TRUE))
	{
		errRet = emsa_pss_verify(pInMsgHash, nMsgHash
			, em, nKey
			, enum_sha1
			, nSalt
			, nKeyBits - 1);
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
	uint32_t nRetSig = 0;
	uint32_t nSalt = 8;
	ErrCrypto errSig = ERR_OK;
	big bigEM = NULL;

	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);

	pfnHash(msg, nMsg, msgHash, nHash);

	RSA_Init(&rsa, enumBits);

	bigEM = mirvar(0);

	nRetSig = pkcs1_pss_sign(&(rsa.priKey)
		, msgHash, nHash
		, enumHash
		, nSalt
		//, enumBits
		, signature, nSignature
		, bigEM);
	if (nRetSig == nSignature)
	{
		printf("sig len ok\n");
		printf("signature:\n");
		output_buf(signature, nRetSig);
	}

	errSig = pkcs1_pss_verify(&(rsa.pubKey)
		, msgHash, nHash
		, signature, nRetSig
		, enum_sha1
		, nSalt
		, bigEM);
	if (ERR_OK == errSig)
	{
		printf("verify ok\n");
	}
}
