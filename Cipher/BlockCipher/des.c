#include "des.h"



ErrCrypto des_init(block_state* pStcKey, const uint8_t* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;
	if(!pKey)
	{
		return ERR_NULL;
	}

	return errRet;
}


ErrCrypto des_encrypt(block_state *pState
	, uint32_t nKey
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pCipher
	, uint32_t nOutBuf
	, uint32_t* pnCipher
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	if (!pState || !pData || !pCipher || !pnCipher)
	{
		return ERR_NULL;
	}

	return errRet;
}

ErrCrypto des_decrypt(block_state *pState
	, uint32_t nKey
	, uint8_t* pCipher
	, uint32_t nCipher
	, uint8_t* pOutPlain
	, uint32_t nOutBuf
	, uint32_t* pnPlain
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	if (!pState || !pCipher || !pOutPlain || !pnPlain)
	{
		return ERR_NULL;
	}

	return errRet;
}



void test_des()
{
	block_state state = {0};
	uint8_t data[] = {"adcdefg"};
	uint8_t szKey[] = {"12345678"};
	uint8_t cipher[256] = { 0 };
	uint8_t buf[256] = { 0 };

	uint32_t nData = sizeof(data) - 1;
	uint32_t nKey = sizeof(szKey) - 1;
	uint32_t nBuf = sizeof(cipher);
	uint32_t nCipher = 0;
	uint32_t nDecrypt = 0;
	uint32_t i = 0;
	ErrCrypto err = ERR_OK;
	err = des_init(&state, szKey, nKey);
	err = des_encrypt(
		&state
		, nKey
		, data
		, nData
		, cipher
		, nBuf
		, &nCipher
		, MODE_ECB);

	for (i = 0; i < nCipher; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");


	err = des_decrypt(
		&state
		, nKey
		, cipher
		, nBuf
		, buf
		, nBuf
		, &nDecrypt
		, MODE_ECB);

	for (i = 0; i < nCipher; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");

}