
#include "./sha256.h"

static const uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

ErrCrypto SHA256_init(HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;
    int i = 0;

    if (!pHashState)
        return ERR_NULL;


    pHashState->nBitsLen = 0;
    pHashState->nBytesLen = 0;

    for (i = 0; i < 8; i++) {
        pHashState->hash[i] = H[i];
    }
    return errRet;
}

ErrCrypto SHA256_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    ErrCrypto errRet = ERR_OK;

    return errRet;
}

ErrCrypto SHA256_digest(HashState* pHashState, uint8_t* digest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto errRet = ERR_OK;

    return errRet;
}

void test_sha256()
{
    HashState hashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abcde";
    SHA256_init(&hashState);
}