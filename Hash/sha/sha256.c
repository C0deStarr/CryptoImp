
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



ErrCrypto AddBitsLen(HashState* pHashState, uint16_t nBits)
{
    // Maximum message length is 2**64 bits 
    pHashState->nBitsLen += nBits;
    return (pHashState->nBitsLen < nBits) ? ERR_MAX_DATA : ERR_OK;
}


ErrCrypto SHA256_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    ErrCrypto errRet = ERR_OK;
    uint8_t nBytesNeeded = 0;
    uint8_t nBytesCopy = 0;

    if (!pHashState || !pBuf)
        return ERR_NULL;

    while (nLen > 0)
    {
        nBytesNeeded = BLOCK_SIZE - pHashState->nBytesLen;
        nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
        memcpy(pHashState->block, pBuf, nBytesCopy);
        pBuf += nBytesCopy;
        pHashState->nBytesLen += nBytesCopy;
        nLen -= nBytesCopy;

        if (BLOCK_SIZE == pHashState->nBytesLen)
        {
            // let's do the 80 steps
            errRet = sha256_compress(pHashState);
            if (errRet)
                return errRet;

            // waiting for the next block
            pHashState->nBytesLen = 0;
            errRet = AddBitsLen(pHashState, BLOCK_SIZE * 8);
            if (errRet)
                return errRet;
        }
    }
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
    SHA256_update(&hashState, data, sizeof(data) - 1);
}