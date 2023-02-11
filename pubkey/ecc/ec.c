#include "ec.h"
#include <string.h>


/*
* Weierstrass curve parameters
*/
typedef struct {
	uint32_t nBytes;
	int nA;
	uint8_t* pB;
	uint8_t* pP;
	uint8_t* pN;
	uint8_t* pGx;
	uint8_t* pGy;
	uint8_t* pSeed;
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
		24,		//bytes == 192 bits
		-3,		// a
		"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",	// b
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",	// p
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",	// n
		"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",	// gx
		"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",	// gy
		"\xd5\x96\x21\xe1"	// seed
		"\xea\x20\x81\xd3"
		"\x28\x95\x57\xed"
		"\x64\x2f\x42\xc8"
		"\x6f\xae\x45\x30"
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
	{
		param.pW_curve = &g_pEC[EC_P192];
		InitMiracl(param.pW_curve->nBytes * 4 // >= param.pW_curve->nBytes * 2
			, 16);
		pEC->stcCurve.nSizeOfN = param.pW_curve->nBytes;
		pEC->stcCurve.uniCurve.W_curve.a = mirvar(0);
		pEC->stcCurve.uniCurve.W_curve.b = mirvar(0);
		pEC->stcCurve.uniCurve.W_curve.p = mirvar(0);
		pEC->stcCurve.n_or_q = mirvar(0);
		pEC->stcCurve.gx = mirvar(0);
		pEC->stcCurve.gy = mirvar(0);
		convert(param.pW_curve->nA, pEC->stcCurve.uniCurve.W_curve.a);
		instr(pEC->stcCurve.uniCurve.W_curve.b, param.pW_curve->pB);
		instr(pEC->stcCurve.uniCurve.W_curve.p, param.pW_curve->pP);
		instr(pEC->stcCurve.n_or_q, param.pW_curve->pN);
		instr(pEC->stcCurve.gx, param.pW_curve->pGx);
		instr(pEC->stcCurve.gy, param.pW_curve->pGy);
		pEC->stcCurve.pSeed = param.pW_curve->pSeed;
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
