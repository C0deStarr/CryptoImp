#include "rsa.h"
#include <time.h>

#include <common/mr_util.h>

enum RSA_VARS{
	RSA_PUB_E = 65537
	//RSA_PUB_E = 3
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
	pCtx->pMip = InitMiracl(nBits, 2);
	pCtx->pMip->IOBASE = 16;
	pCtx->pubKey.n = mirvar(0);
	pCtx->pubKey.e = mirvar(0);
	pCtx->priKey.n = mirvar(0);
	pCtx->priKey.d = mirvar(0);

	GenerateKeys(pCtx);

	return errRet;
}

ErrCrypto RSA_UnInit()
{
	UninitMiracl();
	return ERR_OK;
}

static ErrCrypto GenerateKeys(RSA * pCtx)
{
	ErrCrypto errRet = ERR_OK;
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
		irand((unsigned int)time(NULL));
		bigbits(nPQ_Width, *pBigTmp);
		printf("The randomize generated number :");
		cotnum(*pBigTmp, stdout);
		nxprime(*pBigTmp, *pBigTmp);
		printf("The Next Prime number :");
		cotnum(*pBigTmp, stdout);
		if ((pBigTmp == &q)
			&& (0 == mr_compare(*pBigTmp, p)))
		{
#ifdef _DEBUG
			printf("Invalid q Prime for p==q \n");
#endif
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
		multiply(p, q, pCtx->pubKey.n);
		if(pCtx->nKeyBits != numdig(pCtx->pubKey.n))
			continue;
		break;
	} while (1);
#ifdef _DEBUG
	printf("*********************************\n");
	printf("p:");
	cotnum(p, stdout);
	printf("q:");
	cotnum(q, stdout);
#endif
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

ErrCrypto RSA_Encrypt(RSA_KEY* pKey, big msg, big cipher)
{
	ErrCrypto errRet = ERR_OK;
	if (!pKey || !msg
		|| !(pKey->e_or_d) || !(pKey->n))
	{
		return ERR_NULL;
	}

	int nMsgSize = numdig(msg);
	int nKeySize = numdig(pKey->n);
	if (nMsgSize > nKeySize)
	{
		return ERR_BLOCK_SIZE;
	}

	if (!cipher)
	{
		cipher = mirvar(0);
	}
	powmod(msg
		, pKey->e_or_d
		, pKey->n
		, cipher);
	//power(msg
	//	, 65537
	//	, pCtx->pubKey.n
	//	, cipher);
	return errRet;
}
ErrCrypto RSA_Decrypt(RSA_KEY* pKey, big cipher, big msg)
{
	ErrCrypto errRet = ERR_OK;
	if (!pKey || !cipher
		|| !(pKey->e_or_d) || !(pKey->n))
	{
		return ERR_NULL;
	}

	if (!msg)
	{
		msg = mirvar(0);
	}
	powmod(cipher
		, pKey->e_or_d
		, pKey->n
		, msg);
	return errRet;
}
void test_rsa()
{
	RSA ctx = {0};
	big bigMsg = NULL;
	big bigCipher = NULL;
	big bigDecrypt = NULL;
	uint8_t msg[] = {
		"\xff\x6f\xf8\x08\x00\x00\x00\x00"
		"\x81\x9d\x0c\xaa\x33\x8a\x3a\xa2"
		"\xa7\x1a\x98\xe8\x43\x9e\x39\x6b"
		"\x5a\x26\x78\xc2\xe7\x08\xad\xf4"
		"\x5d\x3a\xd2\x97\xef\x95\x57\xc4"
		"\xbc\x59\x56\x49\xdd\x4a\x60\xff"
		"\xa5\x17\xbb\x93\x4b\x9f\x13\x29"
		"\x7a\xde\x7f\x9f\xf7\xf2\x2e\x4f"
		"\xc6\x1d\xf3\x61\xf9\xde\xed\x51"
		"\x28\x84\x86\xfd\x67\x13\x31\xaf"
		"\x30\xf2\x4d\x8a\xb4\x89\x17\x09"
		"\xe6\xbf\x34\x5c\xd1\x28\x9d\xde"
		"\xd4\x97\x99\xfb\x41\x94\x34\xaf"
		"\x13\x86\x38\x3d\x29\x7f\xff\x5b"
		"\x45\xdf\x4d\x7a\x83\x3f\xfe\x27"
		"\x83\x3c\xa7\x4e\x6f\xf1\x87\xFF"
	};

	uint32_t nMsg = sizeof(msg) - 1;
	RSA_Init(&ctx, RSA_1024);

	// ignore msg len padding(OAEP or PKCS1 V1.5) 
	bigMsg = mirvar(0);
	bigCipher = mirvar(0);
	bigDecrypt = mirvar(0);
	
	//bigrand(ctx.pubKey.n, bigMsg);
	bytes_to_big(nMsg, msg, bigMsg);


	printf("msg:\n");
	cotnum(bigMsg, stdout);
	
	RSA_Encrypt(&(ctx.pubKey), bigMsg, bigCipher);
	printf("cipher:\n");
	cotnum(bigCipher, stdout);

	RSA_Decrypt(&(ctx.priKey), bigCipher, bigDecrypt);
	printf("decrypt:\n");
	cotnum(bigMsg, stdout);
	if (0 == mr_compare(bigMsg, bigDecrypt))
	{
		printf("decrypt ok\n");
	}
	
	RSA_UnInit(&ctx);
}