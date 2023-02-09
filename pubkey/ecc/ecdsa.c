#include "ecdsa.h"

#include <Hash/hash.h>
#include <common/util.h>

ErrCrypto InitECDSA(ecdsa* pCtx, enum_ec typeEC)
{
	ErrCrypto err = ERR_OK;
	if (!pCtx)
	{
		return  ERR_NULL;
	}
	if (ERR_OK != (err = InitEc(&(pCtx->ec), typeEC)))
	{
		return err;
	}


	if (ERR_OK != (err = GenerateEcdsaKeys(pCtx)))
	{
		return err;
	}




	return err;
}

ErrCrypto GenerateEcdsaKeys(ecdsa* pCtx)
{
	ErrCrypto err = ERR_OK;
	if (!pCtx)
	{
		return ERR_NULL;
	}

	pCtx->priKey.d = mirvar(0);
	pCtx->pubKey.xq = mirvar(0);
	pCtx->pubKey.Q = epoint_init();
	
	irand(pCtx->ec.stcCurve.pSeed);
	bigrand(pCtx->ec.stcCurve.n_or_q
		, pCtx->priKey.d);
	ecurve_mult(pCtx->priKey.d
		, pCtx->ec.stcCurve.G
		, pCtx->pubKey.Q);
	pCtx->pubKey.nLSB_y = epoint_get(pCtx->pubKey.Q
		, pCtx->pubKey.xq
		, pCtx->pubKey.xq);
	

	return err;
}

ErrCrypto ecdsa_sign(ecdsa* pCtx
	, const uint8_t* pHash, uint32_t nHash
	, uint8_t* pOutR, uint32_t nOutR
	, uint8_t* pOutS, uint32_t nOutS)
{
	ErrCrypto err = ERR_OK;

	big k = NULL;	// random
	big e = NULL;	// input msg/hash
	big bigHash = NULL;
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
	irand(pCtx->ec.stcCurve.pSeed);
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

void test_ecdsa()
{
	ecdsa ctx = {0};

	uint8_t msg[] = {"abcdef"};
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t digest[MAX_SIZE_OF_DIGEST] = {0};
	uint8_t r[24] = { 0 };
	uint8_t s[24] = { 0 };
	uint32_t nP192 = 24;
	if (ERR_OK != InitECDSA(&ctx, EC_P192))
	{
		return;
	}

	miracl* pMips = get_mip();
	pMips->IOBASE = 16;
	printf("pubkey:\n");
	printf("y==%d\nxq==", ctx.pubKey.nLSB_y);
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
}
