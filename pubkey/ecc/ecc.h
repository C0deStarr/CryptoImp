#ifndef _ECC_H
#define _ECC_H

#include <common/common.h>
#include <common/mr_util.h>

#define SUPPORTED_EC_TYPES	1
typedef enum {
	EC_P192 = 0
}enum_ec;

typedef struct {
	enum_ec typeEC;
	union {
		struct {
			big p;
			big n_or_q;
			big a;
			big b;

			big gx;
			big gy;
			epoint* G;	// base point
			big d;	// private key
		}W_curve;	// Weierstrass curve


		struct {
			big a;
			big b;
		}M_curve;	// Montgomery Curve

		struct {
			big a;
			big d;
		}Ed_curve;	// Edwards Curve
	}uniCurve;
}EC;

ErrCrypto InitEc(EC *pEC, enum_ec typeEC);

typedef struct {
	big d;	// private key
	epoint *Q;	// public key
}EC_PRIKEY;

typedef struct {
	epoint* Q;	// public key
	big xq;
	
	// reconstruct a point from 
	//		its x coordinate 
	//		and just the least significant bit of y
	//big yq;
	int nLSB_y;		// yq is + or -
}EC_PUBKEY;


void test_ecc();
#endif // !_ECC_H
