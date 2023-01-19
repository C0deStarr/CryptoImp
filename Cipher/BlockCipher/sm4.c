#include "sm4.h"
#include "gf_mul.h"

#include <common/endianess.h>
#include <string.h>

#define RotWord32(x) (((x) << 8) | ((x) >> 24))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static ErrCrypto KeyExpansion(StcSM4* pStcSM4, uint8_t key[/*4*Nk*/]);



static ErrCrypto KeyExpansion(StcSM4* pStcSM4, uint8_t key[/*4*Nk*/])
{
	ErrCrypto errRet = ERR_OK;

	uint32_t i = 0;
	
	return errRet;
}


ErrCrypto sm4_init(StcSM4* pStcSM4, uint8_t* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;
	if (!pStcSM4 || !pKey)
	{
		return ERR_NULL;
	}

	return  errRet;
}


ErrCrypto sm4_encrypt(StcSM4* pStcSM4
	, uint8_t* in
	, uint32_t nIn/* = SM4_BLOCK_SIZE*/
	, uint8_t *pOut
	, uint32_t nOut/* = SM4_BLOCK_SIZE*/)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t i = 0;
	

	for (i = 0; i < SM4_BLOCK_SIZE; ++i)
	{
		pOut[i];
	}
	return errRet;
}

ErrCrypto sm4_decrypt(StcSM4* pStcSM4
	, uint8_t* in
	, uint32_t nIn/* = SM4_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = SM4_BLOCK_SIZE*/)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t i = 0;
	

	for (i = 0; i < SM4_BLOCK_SIZE; ++i)
	{
		pOut[i];
	}
	return errRet;
}


void test_sm4()
{
	StcSM4 stcSM4 = {0};
	uint32_t i = 0;
	uint8_t key[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	uint8_t data[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	uint8_t true_cipher[] = {
		0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 
		0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
	};
	uint8_t cipher[0x10] = { 0 };
	uint8_t plain[0x10] = {0};
	uint32_t nKey = sizeof(key);
	sm4_init(&stcSM4, key, nKey);
	sm4_encrypt(&stcSM4, data, sizeof(data), cipher, 0x10);

	for (i = 0; i < SM4_BLOCK_SIZE; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");
	if (!memcmp(true_cipher, cipher, 0x10))
	{
		printf("ok\n");
	}

	sm4_decrypt(&stcSM4, cipher, sizeof(cipher), plain, 0x10);

	for (i = 0; i < SM4_BLOCK_SIZE; i++) {
		printf("%02x", plain[i]);
	}
	printf("\n");
	if (!memcmp(plain, data, 0x10))
	{
		printf("ok\n");
	}

}