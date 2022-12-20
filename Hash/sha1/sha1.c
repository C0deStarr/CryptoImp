#include <string.h>
#include "sha1.h"

ErrCrypto SHA1_init(HashState* pHashState)
{
	ErrCrypto errRet = ERR_OK;

	if (!pHashState)
		return ERR_NULL;

	pHashState->hash[0] = 0x67452301;
	pHashState->hash[1] = 0xefcdab89;
	pHashState->hash[2] = 0x98badcfe;
	pHashState->hash[3] = 0x10325476;
	pHashState->hash[4] = 0xc3d2e1f0;

	return errRet;
}


static ErrCrypto AddBitsLen(HashState* pHashState, uint16_t nBits)
{
	// Maximum message length is 2**64 bits 
	pHashState->nBitsLen += nBits;
	return (pHashState->nBitsLen < nBits) ? ERR_MAX_DATA : ERR_OK;
}

static ErrCrypto sha1_compress(HashState* pHashState)
{
	ErrCrypto errRet = ERR_OK;
	if (!pHashState)
	{
		return ERR_NULL;
	}
	return errRet;
}
ErrCrypto SHA1_update(HashState* pHashState, const uint64_t* pBuf, uint64_t nLen)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t nBytesNeeded = 0;
	uint8_t nBytesCopy = 0;
	if(!pHashState || !pBuf)
		return ERR_NULL;

	while (nLen > 0)
	{
		nBytesNeeded = BLOCK_SIZE - pHashState->nBytesOffset;
		nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
		memcpy(pHashState->hash, pBuf, nBytesCopy);
		pBuf += nBytesCopy;
		pHashState->nBytesOffset += nBytesCopy;
		nLen -= nBytesCopy;

		if (BLOCK_SIZE == pHashState->nBytesOffset)
		{
			// let's do the 80 steps
			errRet = sha1_compress(pHashState);
			if (errRet)
				return errRet;

			// waiting for the next block
			pHashState->nBytesOffset = 0;
			errRet = AddBitsLen(pHashState, BLOCK_SIZE*8);
			if(errRet)
				return errRet;
		}
	}

	return errRet;
}

ErrCrypto SHA1_digest(const HashState* pHashState, uint64_t digest[DIGEST_SIZE])
{
	ErrCrypto errRet = ERR_OK;


	return errRet;
}

void test_sha1()
{
	HashState hashState = {0};
	ErrCrypto err = ERR_OK;
	uint8_t data[] = {"1234567890"};
	err = SHA1_init(&hashState);
	err = SHA1_update(&hashState, data, sizeof(data) - 1);
}