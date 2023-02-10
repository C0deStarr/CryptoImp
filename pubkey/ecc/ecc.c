#include "ecc.h"
#include<stdio.h>



void test_ecc_demo()
{

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
	epoint* epointPubkey = epoint_init();
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
	// public key
	ecurve_mult(bigK, epointG, epointPubkey);
	
	// encrypt
	printf("======encrypt========\n");
	convert(0, bx);
	convert(2, by);
	epoint_set(bx, by, 0, epointM);
	printf("msg:\n");
	print_point(epointM);

	epoint_copy(epointM, epointC);

	ecurve_mult(bigR, epointG, epointX1);
	printf("X1:\n");
	print_point(epointX1);
	
	ecurve_mult(bigR, epointPubkey, epointX2);
	printf("X2:\n");
	print_point(epointX2);

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
