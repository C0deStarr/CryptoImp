#include "ecc.h"
#include<stdio.h>
#include <time.h>
#include <common/util.h>


void test_ecc_demo()
{
	// ecc ElGamal
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
	irand(time(NULL));
	bigrand(pCtx->ec.stcCurve.n_or_q
		, pCtx->priKey.d);

	// GBT_32918.5-2017
	 //instr(pCtx->priKey.d, "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8");

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
	//, int* pnOutLsbYc
	, uint8_t* pOutX1, uint32_t nX1
#ifdef _DEBUG
	, big X2
#endif
)
{
	ErrCrypto err = ERR_ENCRYPT;
	big bigMsg = NULL;
	//epoint *epointMsg = NULL;
	epoint *Q = NULL;
	epoint *epointX1 = NULL;
	epoint *epointX2 = NULL;
	int nBits = 0;


	big bigR = NULL;
	epoint* epointC = NULL;

	big x = NULL;
	if (!pCtx || !(pCtx->pubKey.xq)
		|| !pMsg
		|| !pOutXc || !pOutX1)
	{
		return ERR_NULL;
	}

	if ((pCtx->ec.stcCurve.nSizeOfN > nCx)
		|| (pCtx->ec.stcCurve.nSizeOfN + 1) > nX1)
	{
		return ERR_MEMORY;
	}

	x = mirvar(0);

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
		irand(time(NULL));
		bigrand(pCtx->ec.stcCurve.n_or_q, bigR);
		// X1 = R * G
		epointX1 = epoint_init();
		ecurve_mult(bigR, pCtx->ec.stcCurve.G, epointX1);

		// X2 = R * Q
		epointX2 = epoint_init();
		ecurve_mult(bigR, Q, epointX2);

		// c = msg * x2 mod n
		epoint_get(epointX2, x, x);
		multiply(x, bigMsg, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);

		// output
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, pOutXc
			, TRUE);

		pOutX1[0] = epoint_get(epointX1, x, x);
		//divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, &(pOutX1[1])
			, TRUE);

		err = ERR_OK;

	}while(0);

#ifdef _DEBUG
	 epoint_get(epointX2, X2, X2);
#endif
	return err;
}
ErrCrypto ecc_decrypt(ecc* pCtx
	, const uint8_t* pInXc, uint32_t nXc
	//, int nLsbYc
	, const uint8_t* pInX1, uint32_t nX1
	, uint8_t* pOutDec, uint32_t nOutDec
#ifdef _DEBUG
	, big X2
#endif
)
{
	ErrCrypto err = ERR_DECRYPT;
	big x = NULL;
	epoint* epointX1 = NULL;
	//epoint* epointC = NULL;
	//epoint* epointDec = NULL;
	big cipher = NULL;

	if (!pCtx || !(pCtx->priKey.d)
		|| !pInXc || !pInX1
		|| !pOutDec)
	{
		return ERR_NULL;
	}
	if ((pCtx->ec.stcCurve.nSizeOfN > nXc)
		|| (pCtx->ec.stcCurve.nSizeOfN + 1) > nX1
		|| pCtx->ec.stcCurve.nSizeOfN > nOutDec)
	{
		return ERR_MEMORY;
	}

	do {
		x = mirvar(0);

		cipher = mirvar(0);
		bytes_to_big(nXc, pInXc, cipher);
		//divide(cipher, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);

		// reconstruct X1
		epointX1 = epoint_init();
		bytes_to_big(pCtx->ec.stcCurve.nSizeOfN, &(pInX1[1]), x);
		//divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);
		if (!epoint_set(x, x, pInX1[0], epointX1)) break;

		// X1 = X2 = d*X1
		//epointDec = epoint_init();
		ecurve_mult(pCtx->priKey.d
			, epointX1, epointX1);
		// msg = c * 1/x2 mod n
		epoint_get(epointX1, x, x);
#ifdef _DEBUG
		if (0 == mr_compare(x, X2))
		{
			printf("reconstruct point X2 ok\n");
		}
#endif
		// x = 1/x2 mod n
		xgcd(x, pCtx->ec.stcCurve.n_or_q, x, x, x);
		multiply(cipher, x, x);
		divide(x, pCtx->ec.stcCurve.n_or_q, pCtx->ec.stcCurve.n_or_q);

		big_to_bytes(pCtx->ec.stcCurve.nSizeOfN
			, x
			, pOutDec
			, TRUE);
		err = ERR_OK;

	}while(0);

	return err;
}

void test_ecc()
{
	ecc ctx = { 0 };

	uint8_t msg[] = { "abcdefghijklmn" };
	uint32_t nMsg = sizeof(msg) - 1;
	uint8_t Xc[24] = { 0 };
	uint8_t X1[25] = { 0 };
	uint8_t decrypt[24] = { 0 };
	uint32_t nP192 = 0;
#ifdef _DEBUG
	big X2 = NULL;
#endif
	if (ERR_OK != InitECC(&ctx, EC_P192))
	{
		return;
	}
	miracl* pMips = get_mip();
	pMips->IOBASE = 16;

	nP192 = ctx.ec.stcCurve.nSizeOfN;
#ifdef _DEBUG
	X2 = epoint_init();
#endif
	ecc_encrypt(&ctx
		, msg, nMsg
		, Xc, nP192
		, X1, nP192 + 1
#ifdef _DEBUG
		,X2
#endif
	);

	ecc_decrypt(&ctx
		, Xc, nP192
		, X1, nP192 + 1
		, decrypt, nP192
#ifdef _DEBUG
		, X2
#endif
	);

	output_buf(decrypt, nP192);

}
