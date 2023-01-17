#include "aes.h"

#include <string.h>
#include <common/util.h>

ErrCrypto aes_encrypt_cbc(StcAES* pStcAES
	, uint8_t* pIn
	, uint32_t nIn
	, uint8_t* pIV
	, uint32_t nIV/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t iv[AES_BLOCK_SIZE] = { 0 };
	uint8_t buf[AES_BLOCK_SIZE] = { 0 };
	uint32_t nOffset = 0;
	uint32_t i = 0;
	if (!pStcAES || !pIn || !pOut || !pIV)
	{
		return ERR_NULL;
	}

	/*
	if(!pIV)
	{
		random(iv);
	}
	*/

	if (AES_BLOCK_SIZE != nIV)
	{
		return ERR_BLOCK_SIZE;
	}

	if (0 != (nIn % AES_BLOCK_SIZE))
	{
		return ERR_BLOCK_SIZE;
	}
	if (nOut < nIn)
	{
		return ERR_MEMORY;
	}

	memcpy(iv, pIV, AES_BLOCK_SIZE);


	for (nOffset = 0; nOffset < nIn; nOffset += AES_BLOCK_SIZE)
	{
		memcpy(buf, pIn + nOffset, AES_BLOCK_SIZE);
		xor_buf(iv, buf, AES_BLOCK_SIZE);
		aes_encrypt(pStcAES, buf, AES_BLOCK_SIZE, pOut+nOffset, AES_BLOCK_SIZE);
		memcpy(iv, pOut + nOffset, AES_BLOCK_SIZE);
	}

	return errRet;
}

ErrCrypto aes_decrypt_cbc(StcAES* pStcAES
	, uint8_t* pIn
	, uint32_t nIn
	, uint8_t* pIV
	, uint32_t nIV/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t iv[AES_BLOCK_SIZE] = { 0 };
	uint8_t buf[AES_BLOCK_SIZE] = { 0 };
	uint32_t nOffset = 0;
	uint32_t i = 0;
	if (!pStcAES || !pIn || !pOut || !pIV)
	{
		return ERR_NULL;
	}

	/*
	if(!pIV)
	{
		random(iv);
	}
	*/

	if (AES_BLOCK_SIZE != nIV)
	{
		return ERR_BLOCK_SIZE;
	}

	if (0 != (nIn % AES_BLOCK_SIZE))
	{
		return ERR_BLOCK_SIZE;
	}
	if (nOut < nIn)
	{
		return ERR_MEMORY;
	}

	memcpy(iv, pIV, AES_BLOCK_SIZE);


	for (nOffset = 0; nOffset < nIn; nOffset += AES_BLOCK_SIZE)
	{
		memcpy(buf, pIn + nOffset, AES_BLOCK_SIZE);
		aes_decrypt_ex(pStcAES, buf, AES_BLOCK_SIZE, pOut + nOffset, AES_BLOCK_SIZE);
		xor_buf(iv, pOut + nOffset, AES_BLOCK_SIZE);
		memcpy(iv, pIn + nOffset, AES_BLOCK_SIZE);
	}

	return errRet;
}

void test_aes_cbc()
{
	StcAES stcAES = { 0 };
	uint32_t i = 0;
	uint8_t key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	uint8_t data[] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
		0x31, 0x42, 0xf3, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x33, 0x02, 0x31
	};
	uint8_t true_cipher[] = {
		0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
	};
	uint8_t iv[0x10] = { 
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
	};
	uint8_t cipher[0x20] = { 0 };
	uint8_t plain[0x20] = { 0 };
	uint32_t nKey = sizeof(key);
	aes_init(&stcAES, aes128, key, nKey);
	aes_encrypt_cbc(&stcAES, data, sizeof(data),iv, AES_BLOCK_SIZE,  cipher, sizeof(cipher));

	for (i = 0; i < sizeof(cipher); i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");
	if (!memcmp(true_cipher, cipher, 0x10))
	{
		printf("ok\n");
	}

	aes_decrypt_cbc(&stcAES, cipher, sizeof(cipher), iv, AES_BLOCK_SIZE, plain, sizeof(plain));

	for (i = 0; i < sizeof(plain); i++) {
		printf("%02x", plain[i]);
	}
	printf("\n");
	if (!memcmp(plain, data, 0x10))
	{
		printf("ok\n");
	}

}