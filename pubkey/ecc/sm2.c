#include "sm2.h"
#include <Hash/hash.h>
#include <common/endianess.h>
#include <common/util.h>
#include <stdlib.h>
#include <string.h>



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
	, uint8_t* pOutCipher, uint32_t nCipher
	, uint32_t *pnNeededOutBuffer
)
{
	ErrCrypto err = ERR_OK;

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
		|| !pMsg)
	{
		return ERR_NULL;
	}


	switch (enumHash)
	{
	case enum_sm3:
	{
		nHashC3 = SM3_DIGEST_SIZE;
		pfnHash = SM3_digest;
	}
	break;
	default:
		return 0;
	}
	nC1 = pCtx->ec.stcCurve.nSizeOfN + 1; // compressed point C1: x || lsbY
	if (nCipher < (nC1 + nMsgC2 + nHashC3))
	{
		if (pnNeededOutBuffer)
		{
			*pnNeededOutBuffer = nC1 + nMsgC2 + nHashC3;
		}
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
		// test for Appendix A
		//instr(bigK, "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");

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
		nBuf = pCtx->ec.stcCurve.nSizeOfN * 2 + nMsgC2 + nHashC3;
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

	}while(0);

	if (pBuf)
	{
		free(pBuf);
		pBuf = NULL;
	}
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
	if (ERR_OK != InitECC(&ctx, EC_SM2))
	{
		return;
	}
	instr(ctx.priKey.d, "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");

	sm2_encrypt(&ctx
		, msg, nMsg
		, pCipher, nCipher
		, &nCipher);
	pCipher = (uint8_t *)calloc(nCipher, 1);
	sm2_encrypt(&ctx
		, msg, nMsg
		, pCipher, nCipher
		, NULL);

	output_buf(pCipher, nCipher);

	free(pCipher);
	pCipher = NULL;

	UninitMiracl();
}