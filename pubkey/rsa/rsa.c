#include "rsa.h"

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
	pCtx->pubKey.n = mirvar(0);
	pCtx->pubKey.e = mirvar(0);
	pCtx->priKey.n = mirvar(0);
	pCtx->priKey.d = mirvar(0);

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
	big _1 = mirvar(-1);
	big L = mirvar(0);
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

		if (pBigTmp == &p)
		{
			pBigTmp = &q;
			continue;
		}
		break;
	} while (1);
#ifdef _DEBUG
	printf("*********************************\n");
	printf("p:");
	cotnum(p, stdout);
	printf("q:");
	cotnum(q, stdout);
#endif
	multiply(p, q, pCtx->pubKey.n);
	// n
	copy(pCtx->pubKey.n, pCtx->priKey.n);

	// p-1 q-1
	add(p, _1, p);
	add(q, _1, q);
	multiply(p, q, L);

	// d
	xgcd(pCtx->pubKey.e
		, L
		, pCtx->priKey.d
		, pCtx->priKey.d
		, pCtx->priKey.d);

#ifdef _DEBUG
	printf("n:");
	cotnum(pCtx->pubKey.n, stdout);
	printf("e:");
	cotnum(pCtx->pubKey.e, stdout);
	printf("d:");
	cotnum(pCtx->priKey.d, stdout);
	printf("*********************************\n");
#endif
	return errRet;
}

ErrCrypto RSA_Encrypt(RSA* pCtx, big msg, big cipher)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCtx || !msg)
	{
		return ERR_NULL;
	}

	if (!cipher)
	{
		cipher = mirvar(0);
	}
	powmod(msg
		, pCtx->pubKey.e
		, pCtx->pubKey.n
		, cipher);
	return errRet;
}
ErrCrypto RSA_Decrypt(RSA* pCtx, big cipher, big msg)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCtx || !cipher)
	{
		return ERR_NULL;
	}

	if (!msg)
	{
		msg = mirvar(0);
	}
	powmod(cipher
		, pCtx->priKey.d
		, pCtx->priKey.n
		, msg);
	return errRet;
}
void test_rsa()
{
	RSA ctx = {0};
	big bigMsg = NULL;
	big bigCipher = NULL;
	big bigDecrypt = NULL;
	uint8_t msg[] = {"abc"};
	uint32_t nMsg = sizeof(msg) - 1;
	RSA_Init(&ctx, RSA_1024);

	// ignore msg len padding(OAEP or PKCS1 V1.5) 
	bigMsg = mirvar(0);
	bigCipher = mirvar(0);
	bigDecrypt = mirvar(0);
	
	bigrand(ctx.pubKey.n, bigMsg);
	//bytes_to_big(nMsg, msg, bigMsg);
	printf("msg:\n");
	cotnum(bigMsg, stdout);
	
	RSA_Encrypt(&ctx, bigMsg, bigCipher);
	printf("cipher:\n");
	cotnum(bigCipher, stdout);

	RSA_Decrypt(&ctx, bigCipher, bigDecrypt);
	printf("decrypt:\n");
	cotnum(bigMsg, stdout);
	if (0 == mr_compare(bigMsg, bigDecrypt))
	{
		printf("decrypt ok\n");
	}
	
	RSA_UnInit(&ctx);
}