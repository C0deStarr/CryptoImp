#include "pkcs1_pss.h"

ErrCrypto pkca1_pss_encode(RSA* pPriKey
	, const uint8_t* pInMsg
	, uint32_t nMsg
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits
	, uint8_t* pOut
	, uint32_t nOut)
{
	ErrCrypto errRet = ERR_OK;
	if (!pInMsg || !pOut)
	{
		return ERR_NULL;
	}
	return errRet;
}

ErrCrypto pkca1_pss_verify(RSA* pPriKey
	, const uint8_t* pInMsg
	, uint32_t nMsg
	, const uint8_t* pInEM
	, uint32_t nEM
	, enum_hash enumHash
	, uint32_t nSalt
	, uint32_t nEmBits)
{
	ErrCrypto errRet = ERR_OK;
	if (!pInMsg || !pInEM)
	{
		return ERR_NULL;
	}
	return errRet;
}

void test_pss()
{

}
