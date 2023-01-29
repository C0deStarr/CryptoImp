#include "rsa_oaep.h"

enum RSA_VARS{
	RSA_PUB_E = 65537
};


static ErrCrypto GenerateKeys(RSA *pCtx);

ErrCrypto RSA_Init(RSA* pCtx, RSA_BITS nBits)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCtx)
	{
		return ERR_NULL;
	}
	if ((RSA_1024 != nBits)
		&& (RSA_2048 != nBits)
		&& (RSA_3072 != nBits))
	{
		return ERR_KEY_SIZE;
	}
	pCtx->pMip = mirsys(nBits, 2);
	pCtx->pMip->IOBASE = 16;

	GenerateKeys(pCtx);

	return errRet;
}

ErrCrypto RSA_UnInit(RSA* pCtx)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCtx)
	{
		return ERR_NULL;
	}

	mirexit();
	return errRet;
}

static ErrCrypto GenerateKeys(RSA * pCtx)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCtx)
	{
		return ERR_NULL;
	}

	pCtx->pubKey.e = mirvar(RSA_PUB_E);

	return errRet;
}

void test_rsa()
{
	RSA ctx;
	RSA_Init(&ctx, 1024);
}