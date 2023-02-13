#include "ecdsa.h"

#include <Hash/hash.h>
#include <common/util.h>
#include <time.h>



ErrCrypto ecdsa_sign(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, uint8_t* pOutR, uint32_t nOutR
	, uint8_t* pOutS, uint32_t nOutS)
{
	ErrCrypto err = ERR_OK;

	big k = NULL;	// random
	big e = NULL;	// input msg/hash
	int nBits = 0;

	epoint *R = NULL;
	big xr = NULL;
	big s = NULL;
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


	// step 2
	e = mirvar(0);
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
	bigrand(pCtx->ec.stcCurve.n_or_q, k);

	// step 5
	R = epoint_init();
	ecurve_mult(k
		, pCtx->ec.stcCurve.G
		, R);

	// step 6
	xr = mirvar(0);
	epoint_get(R, xr, xr);

	// calc s
	// step 4 k = 1/k mod q
	xgcd(k, pCtx->ec.stcCurve.n_or_q, k, k, k); 

	// step 8
	// r = r % q
	divide(xr
		, pCtx->ec.stcCurve.n_or_q
		, pCtx->ec.stcCurve.n_or_q);

	// step 9
	// s = (dr+hash) % q
	s = mirvar(0);
	mad(pCtx->priKey.d
		, xr
		, e
		, pCtx->ec.stcCurve.n_or_q
		, pCtx->ec.stcCurve.n_or_q
		, s);
	// s = (s*k) % q
	mad(s, k, k
		, pCtx->ec.stcCurve.n_or_q
		, pCtx->ec.stcCurve.n_or_q
		, s);

	big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
		, xr
		, pOutR
		, TRUE);
	big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
		, s
		, pOutS
		, TRUE);
	return err;
}

ErrCrypto ecdsa_verify(ecc* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, const uint8_t* pInR, uint32_t nR
	, const uint8_t* pInS, uint32_t nS)
{
	ErrCrypto err = ERR_SIGNATURE_VERIFY;

	big r = NULL;
	big s = NULL;
	big e = NULL;
	int nBits = 0;
	big u = NULL;
	big v = NULL;
	epoint* Q = NULL;
	epoint *R1 = NULL;

	if (!pCtx || !(pCtx->pubKey.xq)
			|| !pHash || !pInR || !pInS
		)
	{
		return ERR_NULL;
	}

	do{
		// step 1
		r = mirvar(0);
		s = mirvar(0);
		bytes_to_big(pCtx->ec.stcCurve.nSizeOfN, pInR, r);
		bytes_to_big(pCtx->ec.stcCurve.nSizeOfN, pInS, s);
		if ((mr_compare(pCtx->ec.stcCurve.n_or_q, r) <= 0)
			|| (mr_compare(pCtx->ec.stcCurve.n_or_q, s) <= 0)
			)
		{
			break;
		}
		// step 3
		e = mirvar(0);
		bytes_to_big(nHash, pHash, e);
		if (pCtx->ec.stcCurve.nSizeOfN <= nHash)
		{
			// left bits: math.ceil(math.log(n, 2))
			nBits = logb2(pCtx->ec.stcCurve.n_or_q);
			nBits = pCtx->ec.stcCurve.nSizeOfN * 8 - nBits;
			nBits = 0 - nBits;
			sftbit(e, nBits, e);
		}
		// step 4 s_inv = 1/s mod n
		xgcd(s, pCtx->ec.stcCurve.n_or_q, s, s, s);

		// step 5
		u = mirvar(0);
		v = mirvar(0);
		// u = e*s_inv % q
		mad(e, s, s
			, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q
			, u);   
		// v = r*s_inv % q
		mad(r, s, s
			, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q
			, v);
		// step 6
		// R1 = uG + vQ
		Q = epoint_init();
		R1 = epoint_init();
		if(!epoint_set(pCtx->pubKey.xq, pCtx->pubKey.xq
			, pCtx->pubKey.nLSB_y
			, Q)) break;
		ecurve_mult2(u, pCtx->ec.stcCurve.G
			, v, Q
			, R1);

		// step 7 xr
		epoint_get(R1, u, u);
		// step 8
		// step 9 
		// u = u % n
		divide(u, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		if (0 == mr_compare(u, r))
		{
			err = ERR_OK;
		}
	}while(0);
	return err;
}

void test_ecdsa()
{
	ecc ctx = {0};

	uint8_t msg[] = {"abcdef"};
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t digest[MAX_SIZE_OF_DIGEST] = {0};
	uint8_t r[24] = { 0 };
	uint8_t s[24] = { 0 };
	uint32_t nP192 = 24;
	if (ERR_OK != InitECC(&ctx, EC_P192))
	{
		return;
	}

	miracl* pMips = get_mip();
	pMips->IOBASE = 16;
	printf("pubkey:\n");
	printf("y(lsb)==%d\nxq==", ctx.pubKey.nLSB_y);
	cotnum(ctx.pubKey.xq, stdout);

	printf("prikey:\n");
	cotnum(ctx.priKey.d, stdout);

	// hash
	if (ERR_OK != SHA1_digest(msg, nMsg
		, digest, SHA1_DIGEST_SIZE))
	{
		return;
	}

	printf("====sign====\n");
	ecdsa_sign(&ctx
		, digest, SHA1_DIGEST_SIZE
		, r, nP192
		, s, nP192
	);
	printf("r:");
	output_buf(r, nP192);
	printf("s:");
	output_buf(s, nP192);

	printf("====verify====\n");
	if (ERR_OK == ecdsa_verify(&ctx
		, digest, SHA1_DIGEST_SIZE
		, r, nP192
		, s, nP192))
	{
		printf("verify ok\n");
	}

	UninitMiracl();
}
