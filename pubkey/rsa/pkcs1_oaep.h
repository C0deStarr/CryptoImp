#ifndef _PKCS1_OAEP_H
#define _PKCS1_OAEP_H

#include <common/common.h>
#include "rsa.h"
#include <Hash/hash.h>


typedef struct {
	RSA rsa;
}OAEP;

ErrCrypto pkcs1_oaep_init(OAEP* pCtx, RSA_BITS nBits);
ErrCrypto pkcs1_oaep_uninit(OAEP* pCtx);

/**
 * @brief 
 *		rfc 8017
 * @param nCipher 
 *		size of pCipher in bytes
*/
ErrCrypto pkcs1_oaep_encrypt(OAEP* pCtx
	, const uint8_t* pMsg
	, uint32_t nMsg	// mLen
	, enum_hash enumHash
	, uint8_t* pLabel
	, uint32_t nLabel
	, uint8_t* pCipher
	, uint32_t nCipher
#ifdef _DEBUG
	, big trueEM
	, big trueCipher
#endif // _DEBUG

	);

ErrCrypto pkcs1_oaep_decrypt(OAEP* pCtx
	, const uint8_t* pCipher
	, uint32_t nCipher	// mLen
	, enum_hash enumHash
	, uint8_t* pLabel
	, uint32_t nLabel
	, uint8_t* pOut
	, uint32_t nOut
#ifdef _DEBUG
	, big trueEM
	, big trueCipher
#endif // _DEBUG
	);

void test_rsa_oaep();

#endif // !_PKCS1_OAEP_H
