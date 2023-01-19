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


ErrCrypto aes_encrypt_cfb(StcAES* pStcAES
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
		aes_encrypt(pStcAES, iv, AES_BLOCK_SIZE, pOut+nOffset, AES_BLOCK_SIZE);
		xor_buf(pIn+nOffset, pOut + nOffset, AES_BLOCK_SIZE);
		memcpy(iv, pOut + nOffset, AES_BLOCK_SIZE);
	}

	return errRet;
}

ErrCrypto aes_decrypt_cfb(StcAES* pStcAES
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
		aes_encrypt(pStcAES, iv, AES_BLOCK_SIZE, pOut + nOffset, AES_BLOCK_SIZE);
		xor_buf(pIn + nOffset, pOut + nOffset, AES_BLOCK_SIZE);
		memcpy(iv, pIn + nOffset, AES_BLOCK_SIZE);
	}

	return errRet;
}



ErrCrypto KeyStreamGeneratorOFB(
	StcAES* pStcAES
	, const uint8_t* pIV
	, const uint32_t nBlockSize
	, const uint8_t* pOut
	, uint32_t nStream)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nOffset = 0;
	uint32_t nOffsetPre = 0;
	if (!pIV || !pOut)
	{
		return ERR_NULL;
	}


	if (nStream % nBlockSize)
	{
		return ERR_BLOCK_SIZE;
	}

	memcpy(pOut, pIV, nBlockSize);
	nOffsetPre = 0;
	for (nOffset = 0; nOffset < nStream; nOffset += nBlockSize)
	{
		errRet = aes_encrypt(pStcAES, pOut + nOffsetPre, nBlockSize, pOut + nOffset, nBlockSize);
		if (ERR_OK != errRet) 
		{
			break;
		}
		nOffsetPre = nOffset;
	}

	return errRet;
}

ErrCrypto aes_ofb(StcAES* pStcAES
	, uint8_t* pIn
	, uint32_t nIn
	, uint8_t* pKeyStream
	, uint32_t nKeyStream/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nOffset = 0;
	uint32_t i = 0;
	if (!pStcAES || !pIn || !pOut || !pKeyStream)
	{
		return ERR_NULL;
	}

	/*
	if(!pIV)
	{
		random(iv);
	}
	*/

	if (nIn != nOut)
	{
		return ERR_KEY_SIZE;
	}

	if ((0 != (nIn % AES_BLOCK_SIZE))
		|| (0 != (nKeyStream % AES_BLOCK_SIZE)))
	{
		return ERR_BLOCK_SIZE;
	}
	if (nOut < nIn)
	{
		return ERR_MEMORY;
	}



	for (nOffset = 0; nOffset < nIn; nOffset += AES_BLOCK_SIZE)
	{
		memcpy(pOut+nOffset, pKeyStream + nOffset, AES_BLOCK_SIZE);
		xor_buf(pIn + nOffset, pOut + nOffset, AES_BLOCK_SIZE);
	}

	return errRet;
}



ErrCrypto KeyStreamGeneratorCTR(
	StcAES* pStcAES
	, const uint8_t* pCtr
	, const uint32_t nBlockSize
	, const uint8_t* pOut
	, uint32_t nStream)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t nOffset = 0;
	uint32_t nOffsetEnc = 0;
	if (!pCtr || !pOut)
	{
		return ERR_NULL;
	}


	if (nStream % nBlockSize)
	{
		return ERR_BLOCK_SIZE;
	}

	memcpy(pOut, pCtr, nBlockSize);
	nOffsetEnc = 0;
	for (nOffset = nBlockSize;
		nOffset < nStream;
		nOffset += nBlockSize)
	{
		memcpy(pOut + nOffset, pOut + nOffsetEnc, nBlockSize);
		increment_ctr(pOut + nOffset, nBlockSize);
		errRet = aes_encrypt(pStcAES, pOut + nOffsetEnc, nBlockSize, pOut + nOffsetEnc, nBlockSize);
		if (ERR_OK != errRet)
		{
			break;
		}
		nOffsetEnc = nOffset;
	}
	errRet = aes_encrypt(pStcAES, pOut + nOffsetEnc, nBlockSize, pOut + nOffsetEnc, nBlockSize);

	return errRet;
}

ErrCrypto aes_ctr(StcAES* pStcAES
	, uint8_t* pIn
	, uint32_t nIn
	, uint8_t* pKeyStream
	, uint32_t nKeyStream/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut)
{
	return aes_ofb(pStcAES
		, pIn
		, nIn
		, pKeyStream
		, nKeyStream
		, pOut
		, nOut);
}

void test_aes_modes()
{
	StcAES stcAES = { 0 };
	uint32_t i = 0;
	uint8_t key[] = {
		"0123456789012345"
		//0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	uint8_t data[] = {
		"0123456789012345"
		"0123456789012345"
		//0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
		//0x31, 0x42, 0xf3, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x33, 0x02, 0x31
	};

	uint8_t iv[0x10] = {
		"0123456789012345"
		//0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
	};
	uint8_t cipher[0x20] = { 0 };
	uint8_t plain[0x20] = { 0 };
	uint8_t keystream[0x20] = { 0 };

	//uint32_t nKey = sizeof(key);
	//uint32_t nCipherOrPlain = sizeof(data);
	uint32_t nKey = sizeof(key) - 1;
	uint32_t nData = sizeof(data) - 1;
	aes_init(&stcAES, aes128, key, nKey);


	// cbc
	{
		printf("\ncbc mode:\n");
		aes_encrypt_cbc(&stcAES, data, nData,iv, AES_BLOCK_SIZE,  cipher, nData);

		for (i = 0; i < sizeof(cipher); i++) {
			printf("%02x", cipher[i]);
		}
		printf("\n");


		aes_decrypt_cbc(&stcAES, cipher, nData, iv, AES_BLOCK_SIZE, plain, nData);

		for (i = 0; i < sizeof(plain); i++) {
			printf("%02x", plain[i]);
		}
		printf("\n");
		if (!memcmp(plain, data, 0x10))
		{
			printf("ok\n");
		}
	}

	// cfb
	{
		printf("\ncfb mode:\n");
		memset(cipher, 0, nData);
		memset(plain, 0, nData);
		aes_encrypt_cfb(&stcAES, data, nData, iv, AES_BLOCK_SIZE, cipher, nData);

		for (i = 0; i < sizeof(cipher); i++) {
			printf("%02x", cipher[i]);
		}
		printf("\n");


		aes_decrypt_cfb(&stcAES, cipher, nData, keystream, nData, plain, nData);

		for (i = 0; i < nData; i++) {
			printf("%02x", plain[i]);
		}
		printf("\n");
		if (!memcmp(plain, data, 0x10))
		{
			printf("ok\n");
		}

	}


	// ofb
	{
		printf("\nofb mode:\n");
		memset(cipher, 0, nData);
		memset(plain, 0, nData);
		KeyStreamGeneratorOFB(&stcAES, iv, AES_BLOCK_SIZE, keystream, nData);
		aes_ofb(&stcAES, data, nData, keystream, nData, cipher, nData);

		for (i = 0; i < sizeof(cipher); i++) {
			printf("%02x", cipher[i]);
		}
		printf("\n");


		aes_ofb(&stcAES, cipher, nData, keystream, nData, plain, nData);

		for (i = 0; i < nData; i++) {
			printf("%02x", plain[i]);
		}
		printf("\n");
		if (!memcmp(plain, data, 0x10))
		{
			printf("ok\n");
		}

	}

	// ctr
	{
		printf("\nctr mode:\n");
		memset(cipher, 0, nData);
		memset(plain, 0, nData);
		memset(keystream, 0, nData);
		KeyStreamGeneratorCTR(&stcAES, iv, AES_BLOCK_SIZE, keystream, nData);
		aes_ctr(&stcAES, data, nData, keystream, nData, cipher, nData);

		for (i = 0; i < sizeof(cipher); i++) {
			printf("%02x", cipher[i]);
		}
		printf("\n");


		aes_ctr(&stcAES, cipher, nData, keystream, nData, plain, nData);

		for (i = 0; i < nData; i++) {
			printf("%02x", plain[i]);
		}
		printf("\n");
		if (!memcmp(plain, data, 0x10))
		{
			printf("ok\n");
		}

	}
}


