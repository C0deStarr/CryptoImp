#include "des3.h"


ErrCrypto des3_init(des3_key* pStcKey, const uint8_t* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;
	if (!pKey)
	{
		return ERR_NULL;
	}

	if ((KEY_SIZE * 2 != nKey) 
		&& (KEY_SIZE * 3 != nKey))
	{
		return ERR_KEY_SIZE;
	}
	des_init(&(pStcKey->desKeys[0]), pKey, KEY_SIZE);
	des_init(&(pStcKey->desKeys[1]), pKey+ KEY_SIZE, KEY_SIZE);
	if (KEY_SIZE * 3 == nKey)
	{
		des_init(&(pStcKey->desKeys[2]), pKey+ KEY_SIZE*2, KEY_SIZE);
	}
	else
	{
		des_init(&(pStcKey->desKeys[2]), pKey, KEY_SIZE);
	}

	return errRet;
}

ErrCrypto des3(des3_key* pStcKey
	, const uint8_t* pData
	, uint32_t nData
	, uint8_t* pOut
	, uint32_t nOutBuf
	, DES_OPERATION op)
{
	ErrCrypto errRet = ERR_OK;

	if (!pStcKey || !pData || !pOut)
	{
		return ERR_NULL;
	}
	if ((BLOCK_SIZE != nData) || (BLOCK_SIZE > nOutBuf))
	{
		return ERR_BLOCK_SIZE;
	}

	if (ENC == op)
	{
		des(&pStcKey->desKeys[0], pData, nData, pOut, nOutBuf, ENC);
		des(&pStcKey->desKeys[1], pOut, nData, pOut, nOutBuf, DEC);
		des(&pStcKey->desKeys[2], pOut, nData, pOut, nOutBuf, ENC);
	}
	else
	{
		des(&pStcKey->desKeys[2], pData, nData, pOut, nOutBuf, DEC);
		des(&pStcKey->desKeys[1], pOut, nData, pOut, nOutBuf, ENC);
		des(&pStcKey->desKeys[0], pOut, nData, pOut, nOutBuf, DEC);
	}

	return errRet;
}


void test_des3()
{
	des3_key stcKey = { 0 };
	uint8_t data[] = { 0x94, 0x74, 0xB8, 0xE8, 0xC7, 0x3B, 0xCA, 0x7D };
	uint8_t szKey[] = { 
		0x11, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4A,
		0x12, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4B,
		0x13, 0x31, 0x6E, 0x02, 0x8C, 0x8F, 0x3B, 0x4C
	};
	uint8_t cipher[256] = { 0 };
	uint8_t buf[256] = { 0 };

	uint32_t nData = sizeof(data);
	uint32_t nKey = sizeof(szKey);
	uint32_t nBuf = sizeof(cipher);

	uint32_t i = 0;
	ErrCrypto err = ERR_OK;
	err = des3_init(&stcKey, szKey, nKey);
	err = des3(
		&stcKey
		, data
		, nData
		, cipher
		, nBuf
		, ENC);

	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");


	err = des3(
		&stcKey
		, cipher
		, BLOCK_SIZE
		, buf
		, nBuf
		, DEC);

	for (i = 0; i < BLOCK_SIZE; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

}
