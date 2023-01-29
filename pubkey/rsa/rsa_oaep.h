#ifndef _RSA_OAEP_H
#define _RSA_OAEP_H

#include "miracl.h"

#include <common.h>

typedef enum {
	RSA_1024 = 1024,
	RSA_2048 = 2048,
	RSA_3072 = 3072,
}RSA_BITS;

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
	PubKey pubKey;
	PriKey priKey;
}RSA;

ErrCrypto RSA_Init(RSA * pCtx, RSA_BITS nBits);
ErrCrypto RSA_UnInit(RSA * pCtx);

void test_rsa();

#endif // !_RSA_OAEP_H
