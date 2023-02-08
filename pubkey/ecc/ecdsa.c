#include "ecdsa.h"



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
	bigrand(pCtx->ec.uniCurve.W_curve.n_or_q
		, pCtx->priKey.d);
	ecurve_mult(pCtx->priKey.d
		, pCtx->ec.uniCurve.W_curve.G
		, pCtx->pubKey.Q);
	pCtx->pubKey.nLSB_y = epoint_get(pCtx->pubKey.Q
		, pCtx->pubKey.xq
		, pCtx->pubKey.xq);

	return err;
}


void test_ecdsa()
{
	ecdsa ctx = {0};
	if (ERR_OK != InitECDSA(&ctx, EC_P192))
	{
		return;
	}

	miracl* pMips = get_mip();
	pMips->IOBASE = 16;
	printf("pubkey:\n");
	cotnum(ctx.pubKey.nLSB_y, stdout);
	cotnum(ctx.pubKey.xq, stdout);

	printf("prikey:\n");
	cotnum(ctx.priKey.d, stdout);

}
