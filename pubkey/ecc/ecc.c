#include "ecc.h"
#include<stdio.h>
#include <common/util.h>


void test_ecc_demo()
{
	// ¡Ì“ª÷÷Ω‚ Õ
	miracl* mip = mirsys(10, 10);
	int i;

	int N = 10;
	int nP = N + 1;
	int nRet = 0;
	// y^2 = x^3 -2x - 3 mod 7
	big bigA = mirvar(-2);
	big bigB = mirvar(-3);
	big bigP = mirvar(7);


	// G(3, 2)
	big gx = mirvar(3);
	big gy = mirvar(2);
	epoint* epointG = epoint_init();

	epoint* epointAdd = epoint_init();

	// public key
	epoint* epointQ_Pubkey = epoint_init();
	// private key
	big bigK = mirvar(3);
	// random 
	big bigR = mirvar(3);
	// message
	epoint* epointM = epoint_init();
	// cipher (X1, C)
	epoint* epointC = epoint_init();
	epoint* epointX1 = epoint_init();
	// r * public key
	epoint* epointX2 = epoint_init();
	// dec
	epoint* epointDec = epoint_init();

	big bx = mirvar(0);
	big by = mirvar(0);
	big bn = mirvar(1);

	//init ecurve
	ecurve_init(bigA, bigB, bigP, MR_PROJECTIVE);

	//init generator
	if (epoint_set(gx, gy, 0, epointG))
	{
		// epointG is on the active EC
		for (i = 0; i < nP; i++)
		{
			ecurve_mult(bn, epointG, epointAdd);
			printf("%2dG: ", i+1);
			print_point(epointAdd);
			incr(bn, 1, bn);
		}

	}
	// public key Q = k*G
	ecurve_mult(bigK, epointG, epointQ_Pubkey);
	
	// encrypt
	printf("======encrypt========\n");
	convert(0, bx);
	convert(2, by);
	epoint_set(bx, by, 0, epointM);
	printf("msg:\n");
	print_point(epointM);

	epoint_copy(epointM, epointC);
	// X1 = R * G
	ecurve_mult(bigR, epointG, epointX1);
	printf("X1:\n");
	print_point(epointX1);

	// X2 = R * Q
	ecurve_mult(bigR, epointQ_Pubkey, epointX2);
	printf("X2:\n");
	print_point(epointX2);

	// C = M + X2 = M + R*Q
	ecurve_add(epointX2, epointC);
	printf("cipher: (X2 + M, X1)\n");
	print_point(epointC);
	print_point(epointX1);

	// decrypt
	printf("======decrypt========\n");
	ecurve_mult(bigK, epointX1, epointX2);
	printf("kX1 == X2\n");
	print_point(epointX2);
	epoint_copy(epointC, epointDec);
	ecurve_sub(epointX2, epointDec);
	printf("decrypt: C - kX1\n");
	print_point(epointDec);

/*
 1G: (3, 2)
 2G: (2, 6)
 3G: (4, 2)
 4G: (0, 5)
 5G: (5, 0)
 6G: (0, 2)
 7G: (4, 5)
 8G: (2, 1)
 9G: (3, 5)
10G: (0, 0)
11G: (3, 2)
======encrypt========
msg:
(0, 2)
X1:
(4, 2)
X2:
(3, 5)
cipher: (X2 + M, X1)
(5, 0)
(4, 2)
======decrypt========
kX1 == X2
(3, 5)
decrypt: C - kX1
(0, 2)
*/
	mirexit();
	getchar();
	return 0;
}

ErrCrypto InitECC(ecc* pCtx, enum_ec typeEC)
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


	if (ERR_OK != (err = GenerateEccKeys(pCtx)))
	{
		return err;
	}

	return err;
}

ErrCrypto GenerateEccKeys(ecc* pCtx)
{
	ErrCrypto err = ERR_OK;
	epoint* Q = NULL;
	if (!pCtx)
	{
		return ERR_NULL;
	}
	pCtx->priKey.d = mirvar(0);
	pCtx->pubKey.xq = mirvar(0);
	Q = epoint_init();

	// private key d = rand()
	irand(pCtx->ec.stcCurve.pSeed);
	bigrand(pCtx->ec.stcCurve.n_or_q
		, pCtx->priKey.d);
	// Q = dG
	ecurve_mult(pCtx->priKey.d
		, pCtx->ec.stcCurve.G
		, Q);
	pCtx->pubKey.nLSB_y = epoint_get(Q
		, pCtx->pubKey.xq
		, pCtx->pubKey.xq);


	return err;
}

ErrCrypto ecc_encrypt(ecc* pCtx
	, const uint8_t* pMsg, uint32_t nMsg
	, uint8_t* pOutXc, uint32_t nCx
	, int* pnOutLsbYc
	, uint8_t* pOutXx1, uint32_t nXx1
	, int* pnOutLsbYx1
#ifdef _DEBUG
	, big C
	, big X2
#endif
)
{
	ErrCrypto err = ERR_EC_ENC;
	big bigMsg = NULL;
	epoint *epointMsg = NULL;
	epoint *Q = NULL;
	epoint *epointX1 = NULL;
	epoint *epointX2 = NULL;
	int nBits = 0;


	big bigR = NULL;
	epoint* epointC = NULL;

	big x = NULL;

	if (!pCtx || !(pCtx->pubKey.xq)
		|| !pMsg
		|| !pOutXc || !pOutXx1
		|| !pnOutLsbYc || !pnOutLsbYx1)
	{
		return ERR_NULL;
	}

	if ((pCtx->ec.stcCurve.nSizeOfN > nCx)
		|| pCtx->ec.stcCurve.nSizeOfN > nXx1)
	{
		return ERR_MEMORY;
	}

	do {
		// msg : bytes -> big
		bigMsg = mirvar(0);
		bytes_to_big(nMsg, pMsg, bigMsg);
		if (pCtx->ec.stcCurve.nSizeOfN <= nMsg)
		{
			// left bits: math.ceil(math.log(n, 2))
			nBits = logb2(pCtx->ec.stcCurve.n_or_q);
			nBits = pCtx->ec.stcCurve.nSizeOfN * 8 - nBits;
			nBits = 0 - nBits;
			sftbit(bigMsg, nBits, bigMsg);
		}
#ifdef _DEBUG
		printf("msg:\n");
		cotnum(bigMsg, stdout);
#endif
		divide(bigMsg, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		epointMsg = epoint_init();
		epoint_set(bigMsg, bigMsg, 1/*or 0*/, epointMsg);

		// reconstruct public key
		Q = epoint_init();
		if(!epoint_set(pCtx->pubKey.xq, pCtx->pubKey.xq
			, pCtx->pubKey.nLSB_y
			, Q)) break;
#ifdef _DEBUG
		epoint* Q1 = epoint_init();
		ecurve_mult(pCtx->priKey.d
			, pCtx->ec.stcCurve.G
			, Q1);
		if (epoint_comp(Q, Q1))
		{
			printf("reconstruct pulic key ok\n");
		}
#endif

		// step 3 random r, 0 < r < n
		bigR = mirvar(0);
		irand(pCtx->ec.stcCurve.pSeed);
		bigrand(pCtx->ec.stcCurve.n_or_q, bigR);
		// X1 = R * G
		epointX1 = epoint_init();
		ecurve_mult(bigR, pCtx->ec.stcCurve.G, epointX1);

		// X2 = R * Q
		epointX2 = epoint_init();
		ecurve_mult(bigR, Q, epointX2);

		// C = M + X2 = M + R*Q
		epointC = epoint_init();
		epoint_copy(epointMsg, epointC);
		ecurve_add(epointX2, epointC);

		err = ERR_OK;

	}while(0);

	if (ERR_OK == err)
	{
		x = mirvar(0);
		*pnOutLsbYc = epoint_get(epointC, x, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, pOutXc
			, TRUE);

		*pnOutLsbYx1 = epoint_get(epointX1, x, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, pOutXx1
			, TRUE);
	}
#ifdef _DEBUG
	epoint_get(epointC, C, C);
	epoint_get(epointX2, X2, X2);
	ecurve_sub(epointX2, epointC);
	if (epoint_comp(epointC, epointMsg))
	{
		printf("decrypt in encrypt() ok\n");
	}

#endif
	return err;
}
ErrCrypto ecc_decrypt(ecc* pCtx
	, const uint8_t* pInXc, uint32_t nXc
	, int nLsbYc
	, const uint8_t* pInXx1, uint32_t nXx1
	, int nLsbYx1
	, uint8_t* pOutDec, uint32_t nOutDec
#ifdef _DEBUG
	, big C
	, big X2
#endif
)
{
	ErrCrypto err = ERR_EC_DEC;
	big x = NULL;
	//big y = NULL;
	epoint* epointX1 = NULL;
	epoint* epointC = NULL;
	epoint* epointDec = NULL;
	if (!pCtx || !(pCtx->priKey.d)
		|| !pInXc || !pInXx1
		|| !pOutDec)
	{
		return ERR_NULL;
	}
	if ((pCtx->ec.stcCurve.nSizeOfN > nXc)
		|| pCtx->ec.stcCurve.nSizeOfN > nXx1
		|| pCtx->ec.stcCurve.nSizeOfN > nOutDec)
	{
		return ERR_MEMORY;
	}

	do {
		x = mirvar(0);
		//y = mirvar(0);

		// reconstruct C
		epointC = epoint_init();
		bytes_to_big(nXc, pInXc, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		if(!epoint_set(x, x, nLsbYc, epointC)) break;
#ifdef _DEBUG
		epoint_get(epointC, x, x);
		if (0 == mr_compare(x, C))
		{
			printf("reconstruct point Cipher ok\n");
		}
#endif
		// reconstruct X1
		epointX1 = epoint_init();
		bytes_to_big(nXx1, pInXx1, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		if (!epoint_set(x, x, nLsbYx1, epointX1)) break;

		// X1 = X2 = d*X1
		epointDec = epoint_init();
		epoint_copy(epointC, epointDec);
		ecurve_mult(pCtx->priKey.d
			, epointX1, epointX1);
		// msg = C - X2
		ecurve_sub(epointX1, epointDec);

		err = ERR_OK;
#ifdef _DEBUG
		epoint_get(epointX1, x, x);
		if (0 == mr_compare(x, X2))
		{
			printf("reconstruct point X2 ok\n");
		}
		epoint_get(epointDec, x, x);
		printf("decrypt msg:\n");
		cotnum(x, stdout);
#endif
	}while(0);


	int n = 0;

	if (ERR_OK == err)
	{
		n = epoint_get(epointDec, x, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		n = big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, pOutDec
			, TRUE);
	}
	return err;
}

void test_ecc()
{
	// not always successful
	ecc ctx = { 0 };

	uint8_t msg[] = { "abcdefghijklmnopq" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t Xc[24] = { 0 };
	uint8_t Xx1[24] = { 0 };
	uint8_t decrypt[24] = { 0 };
	int nLsbYc = 0;
	int nLsbYx1 = 0;
	uint32_t nP192 = 0;
#ifdef _DEBUG
	big X2 = NULL;
	big C = NULL;
#endif
	if (ERR_OK != InitECC(&ctx, EC_P192))
	{
		return;
	}
	miracl* pMips = get_mip();
	pMips->IOBASE = 16;

	nP192 = ctx.ec.stcCurve.nSizeOfN;
#ifdef _DEBUG
	C = epoint_init();
	X2 = epoint_init();
#endif
	ecc_encrypt(&ctx
		, msg, nMsg
		, Xc, nP192
		, &nLsbYc
		, Xx1, nP192
		, &nLsbYx1
#ifdef _DEBUG
		,C
		,X2
#endif
	);

	ecc_decrypt(&ctx
		, Xc, nP192
		, &nLsbYc
		, Xx1, nP192
		, &nLsbYx1
		, decrypt, nP192
#ifdef _DEBUG
		, C
		, X2
#endif
	);

	output_buf(decrypt, nP192);

}
