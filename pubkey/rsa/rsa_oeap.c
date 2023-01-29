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
	pCtx->nKeyBits = nBits;
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
	mr_small nSeed = 0;
	big * pBigTmp = NULL;
	big p = mirvar(0);
	big q = mirvar(0);
	int nWidth = 0;
	int nPQ_Width = 0;
	int nMSB = 0;	// the Most significant bit 
	int nLSB = 0;	// the Least significant bit 
	if (!pCtx)
	{
		return ERR_NULL;
	}

	pCtx->pMip->IOBASE = 16;

	pCtx->pubKey.e = mirvar(RSA_PUB_E);

	nPQ_Width = pCtx->nKeyBits / 2;
	pBigTmp = &p;
	do {
		nSeed = brand();
		bigbits(nPQ_Width, *pBigTmp);
		printf("The randomize generated number :");
		cotnum(*pBigTmp, stdout);
		nxprime(*pBigTmp, *pBigTmp);
		printf("The Next Prime number :");
		cotnum(*pBigTmp, stdout);
		if ((pBigTmp == q)
			&& (*pBigTmp == p))
		{
			printf("Invalid q Prime for p==q($d==%d) \n", p, q);
			continue;
		}

		nWidth = numdig(*pBigTmp);
#ifdef _DEBUG
		printf("The Width %d: \nRequired Width %d \n", nWidth, nPQ_Width);
#endif
		if (nWidth != nPQ_Width) {
			continue;
		}


		nMSB = getdig(*pBigTmp, nPQ_Width);	// the Most significant bit is 1
		nLSB = getdig(*pBigTmp, 0);	// ensure odd num
		if ((nMSB == 1) 
			&& (nLSB == 1))
		{
#ifdef _DEBUG
			printf("Valid prime \n");
#endif
		}
		else {
#ifdef _DEBUG
			printf("Invalid prime \n");
#endif
			continue;
		}
		printf("*********************************\n");

		if (pBigTmp == &p)
		{
			pBigTmp = &q;
			continue;
		}
		break;
	} while (1);
	printf("p:");
	cotnum(p, stdout);
	printf("q:");
	cotnum(q, stdout);
	
	return errRet;
}

void test_rsa()
{
	RSA ctx;
	RSA_Init(&ctx, 1024);

	RSA_UnInit(&ctx);
}