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




ErrCrypto sm2_sign(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, uint8_t* pOutR, uint32_t nOutR
	, uint8_t* pOutS, uint32_t nOutS
#ifdef _DEBUG
	, big dbgR
	, big dbgS
	, big dbgX1
#endif 
)
{
	ErrCrypto err = ERR_OK;

	big k = NULL;	// random
	big e = NULL;	// input msg/hash
	int nBits = 0;

	epoint* R = NULL;
	big xr = NULL;
	big s = NULL;
	big tmp = NULL;
#ifdef _DEBUG
	big t = mirvar(0);
#endif
	if (!pCtx || !(pCtx->priKey.d)
		|| !pHash || !pOutR)
	{
		return ERR_NULL;
	}

	if ((pCtx->ec.stcCurve.nSizeOfN > nOutR)
		|| pCtx->ec.stcCurve.nSizeOfN > nOutS)
	{
		return ERR_MEMORY;
	}

	k = mirvar(0);
	e = mirvar(0);
	R = epoint_init();
	xr = mirvar(0);
	s = mirvar(0);
	tmp = mirvar(0);

	// step 2
	bytes_to_big(nHash, pHash, e);
	if (pCtx->ec.stcCurve.nSizeOfN <= nHash)
	{
		// left bits: math.ceil(math.log(n, 2))
		nBits = logb2(pCtx->ec.stcCurve.n_or_q);
		nBits = pCtx->ec.stcCurve.nSizeOfN * 8 - nBits;
		nBits = 0 - nBits;
		sftbit(e, nBits, e);
	}

	// step 3 random k
	// random k: 0 < k < n
	irand(time(NULL));
	do {

		bigrand(pCtx->ec.stcCurve.n_or_q, k);
		// GBT_32918.5-2017
		//instr(k, "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21");

		// step 4
		ecurve_mult(k
			, pCtx->ec.stcCurve.G
			, R);
		epoint_get(R, xr, xr);
#ifdef _DEBUG
		copy(xr, dbgX1);
#endif
		// step 5 xr = (xr+e) % n
		add(xr, e, xr);
		divide(xr, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);

		if (0 == mr_compare(s, xr))	// s == 0
		{
			continue;
		}
		add(xr, k, tmp);
		if (0 == mr_compare(tmp, pCtx->ec.stcCurve.n_or_q))
		{
			continue;
		}

		// step 6 calc ss
		// tmp = 1/(1+d) mod q
		incr(pCtx->priKey.d, 1, tmp);
		xgcd(tmp, pCtx->ec.stcCurve.n_or_q, tmp, tmp, tmp);


		// step 9 s = (k-rd) / (1+d)  mod n
		// bug not fixed
		// s = rd
		multiply(xr, pCtx->priKey.d, s);
		//s = k-rd
		subtract(k, s, s);

		// s = (k-rd) / (1+d) mod n
		mad(s, tmp, tmp
			, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q
			, s);
		if (0 == mr_compare(zero, s))
		{
			continue;
		}

		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, xr
			, pOutR
			, TRUE);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, s
			, pOutS + 1
			, TRUE);
		*pOutS = ( exsign(s) == 1 ) ? 1 : 0;
#ifdef _DEBUG
		copy(xr, dbgR);
		copy(s, dbgS);
		// epoint *Q = epoint_init();
		// big x1 = mirvar(0);
		// // verify
		// // t = r+s mod n
		// add(xr, s, t);
		// divide(t, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		// 
		// if (!epoint_set(pCtx->pubKey.xq, pCtx->pubKey.xq
		// 	, pCtx->pubKey.nLSB_y
		// 	, Q)) break;
		// ecurve_mult2(s, pCtx->ec.stcCurve.G
		// 	, t, Q
		// 	, R);
		// epoint_get(R, x1, x1);
		// // x1 = (x1 + e) mod n
		// add(e, x1, x1);
		// divide(x1, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		// if (0 == mr_compare(x1, xr))
		// {
		// 	printf("verifyy ok\n");
		// }
#endif 
		break;
	}while(1);
	return err;
}

ErrCrypto sm2_verify(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, const uint8_t* pInR, uint32_t nR
	, const uint8_t* pInS, uint32_t nS
#ifdef _DEBUG
	, big dbgR
	, big dbgS
	, big dbgX1
#endif 
)
{
	ErrCrypto err = ERR_SIGNATURE_VERIFY;

	big r = NULL;
	big s = NULL;
	big e = NULL;
	int nBits = 0;
	big t = NULL;
	big tmp = NULL;
	big xr = NULL;
	epoint* Q = NULL;
	epoint* R = NULL;

	if (!pCtx || !(pCtx->pubKey.xq)
		|| !pHash || !pInR || !pInS
		)
	{
		return ERR_NULL;
	}

	r = mirvar(0);
	s = mirvar(0);
	e = mirvar(0);
	t = mirvar(0);
	xr = mirvar(0);
	tmp = mirvar(0);
	Q = epoint_init();
	R = epoint_init();
	do {
		// step 1 check
		// 0 < r < n
		// 0 < s < n
		bytes_to_big(pCtx->ec.stcCurve.nSizeOfN, pInR, r);
		bytes_to_big(pCtx->ec.stcCurve.nSizeOfN, pInS + 1, s);
		insign((*pInS == 1) ? PLUS : MINUS, s);
		if (( (0 > exsign(r))
				&& (mr_compare(pCtx->ec.stcCurve.n_or_q, r) <= 0))
			|| ( (0 > exsign(s))
				&& (mr_compare(pCtx->ec.stcCurve.n_or_q, s) <= 0))
			)
		{
			break;
		}
#ifdef _DEBUG
		int cmp = mr_compare(dbgR, r);
		cmp = mr_compare(dbgS, s);
		if((0 == mr_compare(dbgR, r))
			&& (0 == mr_compare(dbgS, s)))
		{
			printf("reconstruct r & s ok\n");
		}
#endif
		// step 3
		bytes_to_big(nHash, pHash, e);
		if (pCtx->ec.stcCurve.nSizeOfN <= nHash)
		{
			// left bits: math.ceil(math.log(n, 2))
			nBits = logb2(pCtx->ec.stcCurve.n_or_q);
			nBits = pCtx->ec.stcCurve.nSizeOfN * 8 - nBits;
			nBits = 0 - nBits;
			sftbit(e, nBits, e);
		}

	
		// step 4 t = (r+s) mod n
		add(r, s, t);
		divide(t, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);


		if (0 == mr_compare(tmp, t))
		{
			break;
		}

		// step 5 (x1, y1) = sG + tQ
		// reconstruct public key
		if (!epoint_set(pCtx->pubKey.xq, pCtx->pubKey.xq
			, pCtx->pubKey.nLSB_y
			, Q)) break;
		ecurve_mult2(s, pCtx->ec.stcCurve.G
			, t, Q
			, R);
		epoint_get(R, xr, xr);
#ifdef _DEBUG
		if (0 == mr_compare(xr, dbgX1))
		{
			printf("dbgX1 == X1\n");
		}
#endif
		// step 6 check R = (e + x) mod n  == r
		add(e, xr, xr);
		divide(xr, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		if (0 == mr_compare(r, xr))
		{
			err = ERR_OK;
		}
		
	} while (0);
	return err;
}

void test_sm2_sign()
{
	ecc ctx = { 0 };

	uint8_t msg[] = { "message digest" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t digest[MAX_SIZE_OF_DIGEST] = { 0 };
	uint8_t r[32] = { 0 };	// SIGN || r
	uint8_t s[33] = { 0 };
	uint32_t nSM2 = 32;

	big dbgR = NULL;
	big dbgS = NULL;
	big dbgX1 = NULL;
	if (ERR_OK != InitECC(&ctx, EC_SM2))
	{
		return;
	}

	printf("pubkey:\n");
	printf("y(lsb)==%d\nxq==", ctx.pubKey.nLSB_y);
	cotnum(ctx.pubKey.xq, stdout);

	printf("prikey:\n");
	cotnum(ctx.priKey.d, stdout);

	// hash
	//if (ERR_OK != SHA256_digest(msg, nMsg
	//	, digest, SHA1_DIGEST_SIZE))
	//{
	//	return;
	//}
	memcpy(digest
		, "\xf0\xb4\x3e\x94\xba\x45\xac\xca\xac\xe6\x92\xed\x53\x43\x82\xeb\x17\xe6\xab\x5a\x19\xce\x7b\x31\xf4\x48\x6f\xdf\xc0\xd2\x86\x40"
		, 32);

	dbgR = mirvar(0);
	dbgS = mirvar(0);
	dbgX1 = mirvar(0);
	printf("====sign====\n");
	sm2_sign(&ctx
		, digest, SHA256_DIGEST_SIZE
		, r, nSM2
		, s, nSM2 + 1
#ifdef _DEBUG
		, dbgR
		, dbgS
		, dbgX1
#endif
		);
	printf("r:");
	output_buf(r, nSM2);
	printf("s:");
	output_buf(s, nSM2);

	printf("====verify====\n");
	if (ERR_OK == sm2_verify(&ctx
		, digest, SHA256_DIGEST_SIZE
		, r, nSM2
		, s, nSM2 + 1
#ifdef _DEBUG
		, dbgR
		, dbgS
		, dbgX1
#endif
		))
	{
		printf("verify ok\n");
	}

	UninitMiracl();
}