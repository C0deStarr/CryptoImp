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

ErrCrypto SHA1_update(HashState* pHashState, const uint64_t* pBuf, uint64_t nLen)
{
	ErrCrypto errRet = ERR_OK;


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
	err = SHA1_init(&hashState);
}