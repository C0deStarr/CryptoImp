
#include <common/common.h>
#include <common/mr_util.h>

#define SUPPORTED_EC_TYPES	8
typedef enum {
	EC_P192 = 0,
	EC_P224 = 1,
	EC_P256 = 2,
	EC_P384 = 3,
	EC_P521 = 4,
	EC_W25519 = 5,
	EC_W448 = 6,
	EC_SM2 = 7
}enum_ec;

typedef struct {
	enum_ec typeEC;
	struct {
		big gx;
		big gy;
		epoint* G;	// base point
		uint8_t* pSeed;

		big n_or_q;
		uint32_t nSizeOfN;	// eg. P192 -> 24

		union {
			struct {
				big p;
				big a;
				big b;
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
	}stcCurve;
}EC;


typedef struct {
	big d;	// private key
}EC_PRIKEY;

typedef struct {
	//epoint* Q;	// public key
	big xq;

	// reconstruct a point from 
	//		its x coordinate 
	//		and just the least significant bit of y
	//big yq;
	int nLSB_y;		// yq is + or -
}EC_PUBKEY;

ErrCrypto InitEc(EC* pEC, enum_ec typeEC);
