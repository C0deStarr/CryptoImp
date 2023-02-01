#ifndef _PKCS1_PSS_H
#define _PKCS1_PSS_H

#include "rsa.h"
#include <common/common.h>
#include <Hash/hash.h>

ErrCrypto emsa_pss_encode(const uint8_t* pInMsg
	, uint32_t nMsg
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut);

ErrCrypto emsa_pss_verify(const uint8_t* pInMsg
	, uint32_t nMsg
	, const uint8_t* pInEM
	, uint32_t nEM
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits);

void test_pss();
#endif // !_PKCS1_PSS_H

