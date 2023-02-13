#include "sm2.h"
#include <Hash/hash.h>
#include <common/endianess.h>
#include <common/util.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


// Key Derivation Function
static int KDF(const uint8_t* pData
	, uint32_t nData
	, uint32_t nKeyBytesLen
	, PFnHash pfnHash
	, uint32_t nHash
	, uint8_t* pOut	)
{
	int nRet = 0;
	uint32_t nLoop = 0;
	uint32_t zt = 1;
	uint32_t i = 0;

	uint8_t *pBuf = NULL;
	uint32_t nBuf = nData + 4/*sizeof(zt)*/;
	if (!pData || !pOut)
	{
		return 0;
	}


	// alloc memory
	pBuf = (uint8_t *)calloc(nBuf, 1);
	if(!pBuf) return 0;
	memcpy(pBuf, pData, nData);

	nLoop = (nKeyBytesLen + nHash - 1) / nHash;	// upper(nKeyBytesLen/nHash)
	for (i = 0; i < nLoop; ++i)
	{
		u32to8_big(&(pBuf[nData]), zt);
		if (ERR_OK != pfnHash(pBuf, nBuf
			, pOut + i * nHash, nHash))
		{
			break;
		}
		++zt;
	}
	if (i == nLoop)
	{
		nRet = nKeyBytesLen;
	}
	return nRet;
}



/*
Output:
	C1 || C2 || C3
	C1 = random 
*/
ErrCrypto sm2_encrypt(ecc* pCtx
	, const uint8_t* pMsg, uint32_t nMsgC2
	, uint8_t* pOutCipher, _Inout_ uint32_t* pnCipher
)
{
	ErrCrypto err = ERR_ENCRYPT;

	big bigK = NULL;	// random
	epoint* epointC1 = NULL;
	epoint* epointC2 = NULL;
	epoint *epointQ = NULL;	// public key
	uint8_t *pBuf = NULL;	// as KDF and hash input
	uint32_t nBuf = 0;

	PFnHash pfnHash = NULL;
	uint32_t nHashC3 = 0;

	big bigX = NULL;
	big bigY = NULL;
	int nLsbY = 0;
	enum_hash enumHash = enum_sm3;

	// output
	uint32_t nC1 = 0;

	if (!pCtx || !(pCtx->pubKey.xq)
		|| !pMsg || !pnCipher)
	{
		return ERR_NULL;
	}
	
	nHashC3 = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if(!pfnHash) return ERR_UNKNOWN;

	nC1 = pCtx->ec.stcCurve.nSizeOfN + 1; // compressed point C1: x || lsbY
	if (*pnCipher < (nC1 + nMsgC2 + nHashC3))
	{
		
		*pnCipher = nC1 + nMsgC2 + nHashC3;
		return ERR_MAX_OFFSET;
	}
	if (!pOutCipher)
	{
		return ERR_NULL;
	}

	bigK = mirvar(0);
	bigX = mirvar(0);
	bigY = mirvar(0);
	epointC1 = epoint_init();
	epointQ = epoint_init();
	do {
		// step A1 random K
		irand(time(NULL));
		bigrand(pCtx->ec.stcCurve.n_or_q, bigK);

		// GBT_32918.5-2017
		//instr(bigK, "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21");

		// step A2 : C1
		ecurve_mult(bigK, pCtx->ec.stcCurve.G, epointC1);
		// compress PaddingChar
		nLsbY = epoint_get(epointC1, bigX, bigX);
		CompressPoint(enum_compress
			, pCtx->ec.stcCurve.nSizeOfN
			, nLsbY
			, bigX, NULL
			, pOutCipher
			, 1 + pCtx->ec.stcCurve.nSizeOfN);

		// step A4
		// reconstruct public key
		epoint_set(pCtx->pubKey.xq, pCtx->pubKey.xq
			, pCtx->pubKey.nLSB_y
			, epointQ);
		ecurve_mult(bigK, epointQ, epointQ);
		epoint_get(epointQ, bigX, bigY);

		// step A5 KDF(x2 || y2 , nMsg)
		nBuf = pCtx->ec.stcCurve.nSizeOfN * 2 + nMsgC2
			+ nHashC3;	// prevent stack overflow in KDF
		pBuf = (uint8_t*)calloc(nBuf, 1);
		if(!pBuf) break;
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigX
			, pBuf
			, TRUE);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigY
			, pBuf + pCtx->ec.stcCurve.nSizeOfN
			, TRUE);
		if (0 == KDF(pBuf, pCtx->ec.stcCurve.nSizeOfN * 2
			, nMsgC2
			, pfnHash, nHashC3
			, pOutCipher + nC1))
		{
			break;
		}

		// step 6  C2: M xor KDF()
		xor_buf(pMsg, pOutCipher + nC1, nMsgC2);

		// step 7 hash(x2 || M || y2)
		memcpy(pBuf + pCtx->ec.stcCurve.nSizeOfN
			, pMsg
			, nMsgC2);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigY
			, pBuf + pCtx->ec.stcCurve.nSizeOfN + nMsgC2
			, TRUE);
		if(ERR_OK != pfnHash(pBuf, pCtx->ec.stcCurve.nSizeOfN * 2 + nMsgC2
			, pOutCipher + nC1 + nMsgC2, nHashC3))
			break;

		err = ERR_OK;
	}while(0);

	if (pBuf)
	{
		free(pBuf);
		pBuf = NULL;
	}
	return err;
}

ErrCrypto sm2_decrypt(ecc* pCtx
	, const uint8_t* pCipher, uint32_t nCipher
	, uint8_t* pOutMsg, _Inout_ uint32_t* pnOutMsg
)
{
	ErrCrypto err = ERR_DECRYPT;
	PFnHash pfnHash = NULL;
	uint32_t nHashC3 = 0;
	enum_hash enumHash = enum_sm3;

	epoint *epointC1 = NULL;
	uint32_t nC1 = 0;


	big bigX = NULL;
	big bigY = NULL;
	int nLsbY = 0;

	uint8_t* pBuf = NULL;	// as KDF and hash input
	uint32_t nBuf = 0;

	uint32_t nMsgC2 = 0;

	if (!pCtx || !(pCtx->priKey.d)
		|| !pCipher || !pnOutMsg)
	{
		return ERR_NULL;
	}

	nHashC3 = GetDigestSize(enumHash);
	pfnHash = GetDigestFunc(enumHash);
	if (!pfnHash) return ERR_UNKNOWN;

	nC1 = pCtx->ec.stcCurve.nSizeOfN + 1; // compressed point C1: PC || x
	nMsgC2 = nCipher - nC1 - nHashC3;
	if (nMsgC2 > nCipher)
	{
		return ERR_PARAM;
	}

	if (*pnOutMsg < (nCipher - nC1 - nHashC3))
	{

		*pnOutMsg = nMsgC2;
		return ERR_MAX_OFFSET;
	}
	if (!pOutMsg)
	{
		return ERR_NULL;
	}

	bigX = mirvar(0);
	bigY = mirvar(0);
	epointC1 = epoint_init();
	do {

		// B1 reconstruct C1
		// check C1
		DecompressPoint(enum_compress
			, pCipher, nC1
			, pCtx->ec.stcCurve.nSizeOfN
			, &bigX, NULL, &nLsbY);
		epoint_set(bigX, bigX, nLsbY, epointC1);
		if(point_at_infinity(epointC1)) break;

		// B3 reconstruct (x2, y2)
		ecurve_mult(pCtx->priKey.d, epointC1, epointC1);
		epoint_get(epointC1, bigX, bigY);

		// step B4 KDF(x2 || y2 , nMsg)
		// cipher: | pc+x1 | xored msg | hash
		// buf max: | x2 | msg | y2
		nBuf = pCtx->ec.stcCurve.nSizeOfN + nCipher
			+ nHashC3;	// prevent stack overflow in KDF
		pBuf = (uint8_t*)calloc(nBuf, 1);
		if (!pBuf) break;
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigX
			, pBuf
			, TRUE);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigY
			, pBuf + pCtx->ec.stcCurve.nSizeOfN
			, TRUE);
		if (0 == KDF(pBuf, pCtx->ec.stcCurve.nSizeOfN * 2
			, nMsgC2
			, pfnHash, nHashC3
			, pBuf + pCtx->ec.stcCurve.nSizeOfN * 2))
		{
			break;
		}
		/*
		* pBuf:
		*	| x2 | y2 | KDF |
		*/


		// step B5 
		memcpy(pOutMsg, pCipher + nC1, nMsgC2);
		xor_buf(pBuf + pCtx->ec.stcCurve.nSizeOfN * 2, pOutMsg, nMsgC2);


		// step B6 check C3 == hash(x2 || M || y2)
		memcpy(pBuf + pCtx->ec.stcCurve.nSizeOfN
			, pOutMsg
			, nMsgC2);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN, bigY
			, pBuf + pCtx->ec.stcCurve.nSizeOfN + nMsgC2
			, TRUE);
		if (ERR_OK != pfnHash(pBuf, pCtx->ec.stcCurve.nSizeOfN * 2 + nMsgC2
			, pBuf, nHashC3))
			break;

		if(0 != memcmp(pBuf, pCipher + nC1 + nMsgC2, nHashC3))
			break;

		err = ERR_OK;
	}while(0);
	return err;
}

void test_sm2()
{
	ecc ctx = { 0 };

	uint8_t msg[] = { 
		"\x65\x6E\x63\x72\x79\x70\x74\x69\x6F\x6E\x20\x73\x74\x61\x6E\x64\x61\x72\x64"
	};
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t *pCipher = NULL;
	uint32_t nCipher = NULL;

	uint8_t* pDecrypt = NULL;
	uint32_t nDecrypt = 0;

	if (ERR_OK != InitECC(&ctx, EC_SM2))
	{
		return;
	}
	
	sm2_encrypt(&ctx
		, msg, nMsg
		, pCipher, &nCipher);
	pCipher = (uint8_t *)calloc(nCipher, 1);
	sm2_encrypt(&ctx
		, msg, nMsg
		, pCipher, &nCipher
		, NULL);

	// GBT_32918.5-2017
	// C1(compress): 0204ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73
	// C2: 21886ca989ca9c7d58087307ca93092d651efa
	// C3: 59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766
	printf("cipher:\n");
	output_buf(pCipher, nCipher);


	sm2_decrypt(&ctx
		, pCipher, nCipher
		, pDecrypt , &nDecrypt);


	pDecrypt = (uint8_t*)calloc(nDecrypt, 1);
	sm2_decrypt(&ctx
		, pCipher, nCipher
		, pDecrypt, &nDecrypt);

	if (0 == memcmp(msg, pDecrypt, nMsg))
	{
		printf("decrypt ok\n");
	}

	free(pDecrypt);
	pDecrypt = NULL;

	free(pCipher);
	pCipher = NULL;

	UninitMiracl();
}