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

	return err;
}


void test_ecdsa()
{
	ecdsa ctx = {0};
	if (ERR_OK != InitECDSA(&ctx, EC_P192))
	{
		return;
	}
}
