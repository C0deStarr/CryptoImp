
#include "./sha384.h"
#include <stdio.h>
#include <common/endianess.h>
#include <string.h>


static const uint64_t H[8] = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

ErrCrypto SHA384_init(SHA512HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;
    int i = 0;

    if (!pHashState)
        return ERR_NULL;


    pHashState->nArrBitsLen[0] = 0;
    pHashState->nArrBitsLen[1] = 0;
    pHashState->nBytesLen = 0;

    for (i = 0; i < 8; i++) {
        pHashState->hash[i] = H[i];
    }
    return errRet;
}



ErrCrypto SHA384_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    return SHA512_update(pHashState, pBuf, nLen);
}

ErrCrypto SHA384_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto err = ERR_OK;
    uint8_t buf[SHA512_DIGEST_SIZE] = { 0 };
    if (nDigest < SHA384_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }
    err = SHA512_final(pHashState, buf, SHA512_DIGEST_SIZE);
    memcpy(pDigest, buf, SHA384_DIGEST_SIZE);
    return err;
}

void test_sha384()
{
    SHA512HashState SHA512HashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abc";
    uint8_t digest[SHA384_DIGEST_SIZE] = {0};
    int i = 0;
    SHA384_init(&SHA512HashState);
    SHA384_update(&SHA512HashState, data, sizeof(data) - 1);
    SHA384_final(&SHA512HashState, digest, SHA384_DIGEST_SIZE);
    for (i = 0; i < SHA384_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
