
#include "pkcs1_oaep.h"
#include <common/util.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


ErrCrypto pkcs1_oaep_init(OAEP* pCtx, RSA_BITS nBits)
{
	return RSA_Init(pCtx, nBits);
}

ErrCrypto pkcs1_oaep_uninit(OAEP* pCtx)
{
	return RSA_UnInit(pCtx);
}

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
ErrCrypto pkcs1_oaep_encrypt(OAEP* pCtx
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
	if (!pCtx || !pMsg || !pCipher)
	{
		return ERR_NULL;
	}
	nKey = pCtx->rsa.nKeyBits / 8;
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
		errRet = MGF1(pSeed, nHash, nDB, enumHash, pMGF, nDB);
		if(ERR_OK != errRet) break;
		
		// Step 2f
		xor_buf(pMGF, pDB, nDB);

		// Step 2g seedMask
		errRet = MGF1(pDB, nDB, nHash, enumHash, pMGF, nHash);
		if (ERR_OK != errRet) break;
		

		// Step 2h
		xor_buf(pMGF, pSeed, nHash);

		
		// Step 2i
		pEM[0] = '\x00';

		// Step 3a(OS2IP)
		bigEM = mirvar(0);
		bigCipher = mirvar(0);
		bytes_to_big(nKey, pEM, bigEM);
		errRet = RSA_Encrypt(&(pCtx->rsa), bigEM, bigCipher);
		if(ERR_OK != errRet) break;
#ifdef _DEBUG
		copy(bigEM, trueEM);
		copy(bigCipher, trueCipher);
#endif // _DEBUG
			

		if (nKey != big_to_bytes(nKey, bigCipher, pCipher, 0))
		{
			errRet = ERR_ENCRYPT;
		}

	}while(0);


	if (pEM)
	{
		free(pEM);
		pEM = NULL;
	}
	return errRet;
}


void test_rsa_oaep()
{
	OAEP oaep = {0};
	uint8_t msg[] = { "abc" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t cipher[256] = { 0};
	uint32_t nCipher = RSA_1024 / 8;
	pkcs1_oaep_init(&oaep, RSA_1024);
	pkcs1_oaep(&oaep
		, msg , nMsg
		, enum_sha1
		, NULL , 0
		, cipher
		, nCipher);
	printf("cipher:\n");
	output_buf(cipher, nCipher);
	pkcs1_oaep_uninit(&oaep);
}
