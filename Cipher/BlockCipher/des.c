#include "des.h"



ErrCrypto des_init(des_key* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;
	if(!pKey)
	{
		return ERR_NULL;
	}

	return errRet;
}


ErrCrypto des_encrypt(des_key key
	, uint32_t nKey
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pCipher
	, uint32_t nOutBuf
	, uint32_t* pnCipher
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	if (!pData || !pCipher || !pnCipher)
	{
		return ERR_NULL;
	}

	return errRet;
}

ErrCrypto des_decrypt(des_key key
	, uint32_t nKey
	, uint8_t* pCipher
	, uint32_t nCipher
	, uint8_t* pOutPlain
	, uint32_t nOutBuf
	, uint32_t* pnPlain
	, OperationModes mode)
{
	ErrCrypto errRet = ERR_OK;
	if (!pCipher || !pOutPlain || !pnPlain)
	{
		return ERR_NULL;
	}

	return errRet;
}



void test_des()
{
	des_key key = {0};
	uint8_t data[] = {"adcdefg"};
	uint8_t key[] = {"12345678"};
	uint8_t cipher[256] = { 0 };
	uint8_t buf[256] = { 0 };

	uint32_t nData = sizeof(data) - 1;
	uint32_t nKey = sizeof(key) - 1;
	uint32_t nBuf = sizeof(cipher);
	uint32_t nCipher = 0;
	uint32_t nDecrypt = 0;
	uint32_t i = 0;
	ErrCrypto err = ERR_OK;
	err = des_init(&key, KEY_SIZE);
	err = des_encrypt(
		key
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
		key
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