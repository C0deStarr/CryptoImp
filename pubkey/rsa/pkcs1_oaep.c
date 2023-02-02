
#include "pkcs1_oaep.h"
#include <common/util.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "rsa.h"
#include <stdio.h>
#include <miracl.h>


/*
						+----------+------+--+-------+
				DB =    | lHash    | PS   |01|   M   |
						+----------+------+--+-------+
									 |
			+----------+             |
			|   seed   |             |
			+----------+             |
				|                    |
				|-------> MGF --->  xor
				|                    |
		+--+    V                    |
		|00|    xor <----- MGF <-----|
		+--+    |                    |
		  |     |                    |
		  V     V                    V dbMask
		+--+----------+----------------------------+
 EM =   |00|maskedSeed|          maskedDB          |
		+--+----------+----------------------------+
*/
ErrCrypto pkcs1_oaep_encrypt(RSA_KEY* pPubKey
	, const uint8_t* pMsg
	, uint32_t nMsg	// mLen
	, enum_hash enumHash
	, uint8_t *pLabel
	, uint32_t nLabel
	, uint8_t* pCipher
	, uint32_t nCipher
#ifdef _DEBUG
	, big trueEM
	, big trueCipher
#endif // _DEBUG
)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nHash = 0;
	uint32_t nKey = 0;
	PFnHash pfnHash = NULL;

	uint8_t* pEM = NULL; // encoded message
	uint8_t *pSeed = NULL;
	uint8_t* pDB = NULL;	// data block
	uint8_t* pPS = NULL;	// padding string
	uint8_t* pMGF = NULL;	// mask generation function output
	uint32_t nDB = 0;
	big bigEM = NULL;
	big bigCipher = NULL;
	int nPS = 0;
	int nMGF = 0;
	if (!pPubKey || !pMsg || !pCipher)
	{
		return ERR_NULL;
	}
	nKey = numdig(pPubKey->n) / 8;
	if (nCipher < nKey)
	{
		return ERR_MEMORY;
	}
	
	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if(!pfnHash) return ERR_PARAM;

	nPS = nKey - nMsg - 2 * nHash - 2;
	// Step 1b 
	if (nPS < 0)
	{
		return ERR_MAX_DATA;
	}
	if (!pLabel)
	{
		pLabel = "";
		nLabel = 1;
	}
	do {
		nDB = nKey - 1 - nHash;
		nMGF = MAX(nDB, nHash) + nHash;
		pEM = (uint8_t *)calloc(nKey
			+ nMGF
			, 1);
		if(!pEM) 
		{
			errRet = ERR_MEMORY;
			break;
		}
		pDB = pEM + 1 + nHash;
		// Step 2a
		errRet = pfnHash(pLabel, nLabel, pDB, nHash);
		if(errRet != ERR_OK) break;
		

		pPS = pDB + nHash;
		// Step 2b
		memset(pPS, 0, nPS);
		// Step 2c DB(data block)
		pPS[nPS] = 1;
		memcpy(pPS + nPS + 1, pMsg, nMsg);

		// Step 2d
		pSeed = pEM + 1;
		GetRandomBytes(pSeed, nHash);

		// Step 2e
		pMGF = pEM + nKey;
		if(0 == MGF1(pSeed, nHash, nDB, enumHash, pMGF, nMGF))
			break;
		
		// Step 2f
		xor_buf(pMGF, pDB, nDB);

		// Step 2g seedMask
		if(0 == MGF1(pDB, nDB, nHash, enumHash, pMGF, nMGF))
			break;
		

		// Step 2h
		xor_buf(pMGF, pSeed, nHash);

		
		// Step 2i
		pEM[0] = '\x00';

		// Step 3a(OS2IP)
		bigEM = mirvar(0);
		bigCipher = mirvar(0);
		bytes_to_big(nKey, pEM, bigEM);
		errRet = RSA_Encrypt(pPubKey, bigEM, bigCipher);
		if(ERR_OK != errRet) break;
#ifdef _DEBUG
		copy(bigEM, trueEM);
		copy(bigCipher, trueCipher);
#endif // _DEBUG
			

		if (nKey != big_to_bytes(nKey, bigCipher, pCipher, TRUE))
		{
			errRet = ERR_ENCRYPT;
		}

	}while(0);


	if (pEM)
	{
		free(pEM);
		pEM = NULL;
		pSeed = NULL;
		pDB = NULL;	// data block
		pPS = NULL;	// padding string
		pMGF = NULL;
	}
	return errRet;
}

ErrCrypto pkcs1_oaep_decrypt(RSA_KEY* pPriKey
	, const uint8_t* pCipher
	, uint32_t nCipher	// mLen
	, enum_hash enumHash
	, uint8_t* pLabel
	, uint32_t nLabel
	, uint8_t* pOut
	, uint32_t nOut
#ifdef _DEBUG
	, big trueEM
	, big trueCipher
#endif // _DEBUG
)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nKey = 0;
	uint32_t nHash = 0;
	PFnHash pfnHash = NULL;
	big bigEM = NULL;
	big bigCipher = NULL;

	uint8_t* pEM = NULL; // encoded message
	uint8_t* pY = NULL;
	uint8_t* pSeed = NULL;

	uint8_t* pDB = NULL;	// data block
	uint8_t* pHash = NULL;
	uint8_t* pPS = NULL;	// padding string
	uint8_t* pOne = NULL;
	uint8_t* pMsg = NULL;
	
	uint8_t* pMGF = NULL;	// mask generation function output
	uint8_t* pCalcHash = NULL;

	uint32_t nMGF = 0;
	uint32_t nDB = 0;
	uint8_t bInvalid = 0;
	uint32_t nTmp = 0;
	
	if (!pPriKey || !pCipher || !pOut)
	{
		return ERR_NULL;
	}

	nKey = numdig(pPriKey->n) / 8;
	nHash = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if (!pfnHash) return ERR_PARAM;

	// Step 1b and 1c
	if((nCipher != nKey)
		|| (nCipher < (2 * nHash + 2)))
	{
		return ERR_KEY_SIZE;
	}

	if (nOut < (2 * nHash + 2))
	{
		return ERR_MEMORY;
	}

	if (!pLabel)
	{
		pLabel = "";
		nLabel = 1;
	}

	do {

		nDB = nKey - 1 - nHash;
		nMGF = MAX(nDB, nHash) + nHash;
		pEM = (uint8_t*)calloc(nKey
			+ nMGF
			+ nHash // for calced hash
			, 1);
		if (!pEM)
		{
			errRet = ERR_MEMORY;
			break;
		}
		pDB = pEM + 1 + nHash;


		// Step 2a(O2SIP)
		bigCipher = mirvar(0);
		bigEM = mirvar(0);
		bytes_to_big(nCipher, pCipher, bigCipher);

		// Step 2b RSADP
		errRet = RSA_Decrypt(pPriKey, bigCipher, bigEM);
		if (ERR_OK != errRet) break;
#ifdef _DEBUG
		if (0 == mr_compare(bigCipher, trueCipher))
		{
			printf("cipher ok\n");
		}
		if (0 == mr_compare(bigEM, trueEM))
		{
			printf("decrypt successfully\n");
		}
#endif // _DEBUG

		// Step 2c I2OSP
		nTmp = big_to_bytes(nKey
			, bigEM
			, pEM
			, TRUE);	// 0 justified
		if (nKey != nTmp)
		{
			errRet = ERR_DECRYPT;
			break;
		}

		// Step 3a lHash
		pCalcHash = pEM + nKey + nMGF;
		errRet = pfnHash(pLabel, nLabel, pCalcHash, nHash);
		if (errRet != ERR_OK) break;

		// Step 3b separate EM
		pY = pEM;
		pSeed = pEM + 1; // Masked Seed 
		pDB = pSeed + nHash; // Masked DB

		// Step 3c seedMask
		pMGF = pEM + nKey;
		if(0 == MGF1(pDB, nDB, nHash, enumHash, pMGF, nMGF))
			break;
		
		// Step 3d seed
		xor_buf(pMGF, pSeed, nHash);
		// Step 3e dbMask
		if(0 == MGF1(pSeed, nHash, nDB, enumHash, pMGF, nMGF))
			break;
		
		// Step 3f DB
		xor_buf(pMGF, pDB, nDB);

		// Step 3g separate DB
		pHash = pDB;
		pPS = pHash + nHash;
		pOne = memchr(pDB, '\x01', nDB);
		if (!pOne)
		{
			errRet = ERR_DECRYPT;
			break;
		}
		bInvalid = *pY; // 0 
		bInvalid |= memcmp(pHash, pCalcHash, nHash);
		bInvalid |= (NULL == pOne);
		for (; pPS != pOne; ++pPS)
		{
			// ps == "00000..."
			// len == nKey - nMsg - 2 * nHash - 2 == nDB - nHash - 1 - nMsg
			bInvalid |= *pPS;	
		}
		if (bInvalid)
		{
			errRet = ERR_DECRYPT;
			break;
		}
		pMsg = pOne + 1;
		memcpy(pOut, pMsg, pMGF - pMsg);

	}while(0);

	if (pEM)
	{
		free(pEM);
		pEM = NULL;
		pY = NULL;
		pSeed = NULL;
		pDB = NULL;	// data block
		pHash = NULL;
		pPS = NULL;	// padding string
		pOne = NULL;
		pMsg = NULL;
		pMGF = NULL;	// mask generation function output
		pCalcHash = NULL;
	}

	return errRet;
}

void test_rsa_oaep()
{
	RSA rsa = {0};
	uint8_t msg[] = { "abcdefgh" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t cipher[256] = { 0};
	RSA_BITS enumBits = RSA_1024;
	uint32_t nCipher = enumBits / 8;
	uint8_t plain[256] = { 0 };

	big trueEM = NULL;
	big trueCipher = NULL;

	RSA_Init(&rsa, RSA_1024);
	trueEM = mirvar(0);
	trueCipher = mirvar(0);
	pkcs1_oaep_encrypt(&(rsa.pubKey)
		, msg , nMsg
		, enum_sha1
		, NULL , 0
		, cipher
		, nCipher
		, trueEM
		, trueCipher);
	printf("cipher:\n");
	output_buf(cipher, nCipher);

	pkcs1_oaep_decrypt(&(rsa.priKey)
		, cipher, nCipher
		, enum_sha1
		, NULL, 0
		, plain
		, sizeof(plain)
		, trueEM
		, trueCipher);
	printf("plaintext:\n");
	output_buf(plain, nMsg);

	RSA_UnInit(&rsa);
}
