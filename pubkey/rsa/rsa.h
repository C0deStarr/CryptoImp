#ifndef _RSA_H
#define _RSA_H

#include "miracl.h"

#include <common/common.h>

typedef enum {
	RSA_1024 = 1024,
	RSA_2048 = 2048,
	RSA_3072 = 3072,
	RSA_MAX_BITS = RSA_3072
}RSA_BITS;

typedef struct {
	big n;
	big e_or_d;
}RSA_KEY;

typedef struct {
	big n;
	big e;	// default 65537
}PubKey;

typedef struct {
	big n;
	big d;
}PriKey;

typedef struct {
	miracl * pMip;
	int nKeyBits;
	PubKey pubKey;
	PriKey priKey;
}RSA;

ErrCrypto RSA_Init(RSA * pCtx, RSA_BITS nBits);
ErrCrypto RSA_UnInit();

ErrCrypto RSA_Encrypt(RSA_KEY* pKey, big msg, big cipher);
ErrCrypto RSA_Decrypt(RSA_KEY* pKey, big cipher, big msg);


void test_rsa();

#endif // !_RSA_OAEP_H
