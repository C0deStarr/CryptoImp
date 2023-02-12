
#include "./sha224.h"
#include <common/endianess.h>
#include <string.h>

static const uint32_t H[8] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4
};

ErrCrypto SHA224_init(SHA256_HashState* pHashState)
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



ErrCrypto SHA224_update(SHA256_HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    
    return SHA256_update(pHashState, pBuf, nLen);
}

ErrCrypto SHA224_final(SHA256_HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto err = ERR_OK;
    uint8_t buf[SHA256_DIGEST_SIZE] = {0};
    if (nDigest < SHA224_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }
    err = SHA256_final(pHashState, buf, SHA256_DIGEST_SIZE);
    memcpy(pDigest, buf, SHA224_DIGEST_SIZE);
    return err;
}

void test_sha224()
{
    SHA256_HashState hashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abcde";
    uint8_t digest[SHA224_DIGEST_SIZE] = {0};
    int i = 0;
    SHA224_init(&hashState);
    SHA224_update(&hashState, data, sizeof(data) - 1);
    SHA224_final(&hashState, digest, SHA224_DIGEST_SIZE);
    for (i = 0; i < SHA224_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}