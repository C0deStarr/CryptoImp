#ifndef _PKCS1_PSS_H
#define _PKCS1_PSS_H

#include "rsa.h"
#include <common/common.h>
#include <Hash/hash.h>


uint32_t emsa_pss_encode(const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut);

ErrCrypto emsa_pss_verify(const uint8_t* pInMsg
	, uint32_t nMsgHash
	, const uint8_t* pInEM
	, uint32_t nEM
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits);

ErrCrypto pkcs1_pss_sign(RSA* pPriKey
	, const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, enum_hash enumHash
	, uint32_t nSalt
	//, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut);

ErrCrypto pkcs1_pss_verify(RSA* pPubKey
	, const uint8_t* pInMsgHash
	, uint32_t nMsgHash
	, const uint8_t* pInSignature
	, uint32_t nSignature
	, enum_hash enumHash
	, uint32_t nSalt
	//, uint32_t nEmBits
	);

void test_pss();
#endif // !_PKCS1_PSS_H

