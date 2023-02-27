#include "ec.h"
#include <string.h>


/*
* Weierstrass curve parameters
*/
typedef struct {
	uint32_t nBytes;
	//int nA;
	uint8_t* pA;
	uint8_t* pB;
	uint8_t* pP;
	uint8_t* pN;
	uint8_t* pGx;
	uint8_t* pGy;
	//uint8_t* pSeed;
}W_curve_parameters;

/*
* Montgomery curve parameters
*/
typedef struct {
	uint32_t nBits;
}M_curve_parameters;

/*
* Edwards curve parameters
*/
typedef struct {
	uint32_t nBits;
}Ed_curve_parameters;

typedef union {
	W_curve_parameters* pW_curve;
	M_curve_parameters* pM_curve;
	Ed_curve_parameters* pEd_curve;
}curve_parameter;


static W_curve_parameters g_pEC[SUPPORTED_EC_TYPES] = {
	// EC_P192
	{
		//bytes == 192 bits
		24,		
		// a = -3
		"fffffffffffffffffffffffffffffffeffffffffffffffff",		
		// b
		"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",	
		// p
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",	
		// n
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",	
		// gx
		"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",	
		// gy
		"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",	
		//"\xd5\x96\x21\xe1"	// seed
		//"\xea\x20\x81\xd3"
		//"\x28\x95\x57\xed"
		//"\x64\x2f\x42\xc8"
		//"\x6f\xae\x45\x30"
	},
	// EC_P224
	{
		//bytes
		28,		
		// a = -3
		"fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",	
		// b
		"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",	
		// p
		"ffffffffffffffffffffffffffffffff000000000000000000000001",	
		// n
		"ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",	
		// gx
		"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",	
		// gy
		"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",	
	},
	// EC_P256
	{
		//bytes
		32,		
		// a = -3
		"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",		
		// b
		"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",	
		// p
		"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",	
		// n
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",	
		// gx
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",	
		// gy
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",	
	},
	// EC_P384
	{
		//bytes
		48,		
		// a = -3
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",		
		// b
		"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",	
		// p
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",	
		// n
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",	
		// gx
		"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",	
		// gy
		"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",	
	},
	// EC_P512
	{
		//bytes
		64,
		// a
		"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
		// b
		"051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
		// p
		"1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// n
		"1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		// gx
		"c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		// gy
		"11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
	},
	// EC_W25519
	{
		//bytes
		32,
		// a
		"2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144",
		// b
		"7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864",
		// p
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
		// n
		"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
		// gx
		"2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a",
		// gy
		"5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14",
	},
	// EC_W448
	{
		//bytes
		56,
		// a
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffffffffffffffffffffffffffffffffffffffffffffe1a76d41f",
		// b
		"5ed097b425ed097b425ed097b425ed097b425ed097b425ed097b425e71c71c71c71c71c71c71c71c71c71c71c71c71c71c72c87b7cc69f70",
		// p
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// n
		"3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
		// gx
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000000000cb91",
		// gy
		"7d235d1295f5b1f66c98ab6e58326fcecbae5d34f55545d060f75dc28df3f6edb8027e2346430d211312c4b150677af76fd7223d457b5b1a",
	},
	// sm2
	{
		32, // 256 bits
		//a
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 
		// b 
		"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 
		// p 
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 
		// n 
		"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 
		// Gx
		"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 
		// Gy
		"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 
	}
};

ErrCrypto InitEc(EC* pEC, enum_ec typeEC)
{
	ErrCrypto err = ERR_OK;
	curve_parameter param = { 0 };
	if (!pEC) {
		return ERR_NULL;
	}

	memset(pEC, 0, sizeof(EC));

	switch (typeEC)
	{
	case EC_P192:
	case EC_P224:
	case EC_P256:
	case EC_P384:
	case EC_P521:
	case EC_W25519:
	case EC_W448:
	case EC_SM2:
	{
		param.pW_curve = &g_pEC[typeEC];
		InitMiracl(param.pW_curve->nBytes * 2 // >= param.pW_curve->nBytes * 2
			, 16);

		pEC->stcCurve.nSizeOfN = param.pW_curve->nBytes;
		pEC->stcCurve.uniCurve.W_curve.a = mirvar(0);
		pEC->stcCurve.uniCurve.W_curve.b = mirvar(0);
		pEC->stcCurve.uniCurve.W_curve.p = mirvar(0);
		pEC->stcCurve.n_or_q = mirvar(0);
		pEC->stcCurve.gx = mirvar(0);
		pEC->stcCurve.gy = mirvar(0);
		instr(pEC->stcCurve.uniCurve.W_curve.a, param.pW_curve->pA);
		instr(pEC->stcCurve.uniCurve.W_curve.b, param.pW_curve->pB);
		instr(pEC->stcCurve.uniCurve.W_curve.p, param.pW_curve->pP);
		instr(pEC->stcCurve.n_or_q, param.pW_curve->pN);
		instr(pEC->stcCurve.gx, param.pW_curve->pGx);
		instr(pEC->stcCurve.gy, param.pW_curve->pGy);
		//pEC->stcCurve.pSeed = param.pW_curve->pSeed;
	}
	break;
	// for implementing
	default:
		return ERR_PARAM;
	}

	pEC->typeEC = typeEC;

	ecurve_init(pEC->stcCurve.uniCurve.W_curve.a
		, pEC->stcCurve.uniCurve.W_curve.b
		, pEC->stcCurve.uniCurve.W_curve.p
		, MR_PROJECTIVE);

	pEC->stcCurve.G = epoint_init();
	if (!epoint_set(pEC->stcCurve.gx
		, pEC->stcCurve.gy
		, 0
		, pEC->stcCurve.G))
	{
		// G not on the curve
		return ERR_EC_CURVE;
	}

	epoint* pointTmp = epoint_init();
	ecurve_mult(pEC->stcCurve.n_or_q
		, pEC->stcCurve.G
		, pointTmp);
	if (!point_at_infinity(pointTmp))
	{
		return  ERR_EC_CURVE;
	}

	return err;
}
