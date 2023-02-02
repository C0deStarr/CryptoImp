#include "util.h"
#include "endianess.h"
#include <Hash/hash.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

void output_buf(const uint8_t* pBuf, uint32_t nBuf)
{
	uint32_t i = 0;
	if (pBuf)
	{
		while (i != nBuf)
		{
			printf("%02x", pBuf[i]);
			++i;
		}
		printf("\n");
	}
}

void xor_buf(const uint8_t in[], uint8_t out[], uint32_t nLen)
{
	uint32_t i = 0;
	if (in && out)
	{
		for (i = 0; i < nLen; ++i)
		{
			out[i] ^= in[i];
		}
	}
}

void increment_ctr(uint8_t* pCtr, uint32_t nCtr/* = BLOCK SIZE*/)
{
	int i = 0;

	if (pCtr)
	{
		// big-endian
		for (i = nCtr - 1; i >= 0; --i) {
			++pCtr[i];
			if (0 != pCtr[i])
				break;
		}

	}
}

uint32_t MGF1(uint8_t* pSeed
	, uint32_t nSeed
	, uint32_t nMaskLen
	, enum_hash enumHash
	, uint8_t* pOut
	, uint32_t nOut)
{
	uint32_t nRet = 0;
	uint32_t nLoop = 0;
	uint32_t counter = 0;
	uint8_t* pBuf = NULL;
	uint8_t* pCounter = NULL;
	uint8_t* pHash = NULL;
	uint32_t nDigest = 0;
	uint32_t nBufLen = nSeed + 4;
	PFnHash  pFnHash = NULL;

	if (!pSeed || !pOut)
	{
		return 0;
	}


	switch (enumHash)
	{
	case enum_sha1:
	{
		nDigest = SHA1_DIGEST_SIZE;
		nLoop = nMaskLen / SHA1_DIGEST_SIZE;
		if (nMaskLen % SHA1_DIGEST_SIZE)
		{
			++nLoop;
		}
		pFnHash = SHA1_digest;
	}
	break;
	default:
		return 0;
	}
	if (nOut < (nLoop * nDigest))
	{
		return 0;
	}
	do {
		pBuf = (uint8_t*)calloc(nBufLen, 1);
		if (!pBuf) break;
		memcpy(pBuf, pSeed, nSeed);
		pCounter = pBuf + nSeed;
		pHash = pOut;
		for (counter = 0; counter < nLoop; ++counter)
		{
			u32to8_big(pCounter, counter);
			if(ERR_OK != pFnHash(
							pBuf, nBufLen
							, pHash, nOut - nDigest * counter))
				break;
			pHash += nDigest;
		}
		nRet = nLoop * nDigest;
	} while (0);

	if (pBuf)
	{
		free(pBuf);
		pBuf = NULL;
		pCounter = NULL;
	}

	return nRet;
}

void test_mgf()
{
	uint8_t seed[] = {
		"bar"
	};
	uint8_t maskedDB[] = {
		"\xbc\x0c\x65\x5e\x01\x6b\xc2\x93\x1d\x85\xa2\xe6\x75\x18\x1a\xdc\xef\x7f\x58\x1f\x76\xdf\x27\x39\xda\x74\xfa\xac\x41\x62\x7b\xe2\xf7\xf4\x15\xc8\x9e\x98\x3f\xd0\xce\x80\xce\xd9\x87\x86\x41\xcb\x48\x76"
	};
	uint8_t out[256] = { 0 };
	uint32_t nSeed = sizeof(seed) - 1;
	uint32_t nMask = sizeof(maskedDB) - 1;
	MGF1(seed, nSeed, nMask, enum_sha1, out, 256);
	if (0 == memcmp(maskedDB, out, nMask))
	{
		printf("ok\n");
	}
}



void GetRandomBytes(uint8_t* pBuf, uint32_t nLen)
{
	int nRand = 0;
	uint32_t i = 0;
	if (pBuf && nLen)
	{
		srand((unsigned int)time(NULL));
		
		for(i = 0; i < nLen ; ++i)
		//while (nLen);
		{
			nRand = rand() % 0x100;
			pBuf[i] = nRand;
		}

	}
}
