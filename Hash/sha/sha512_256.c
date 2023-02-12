
#include "./sha512_256.h"
#include <stdio.h>
#include <common/endianess.h>
#include <string.h>


static const uint64_t H[8] = {
    0x22312194FC2BF72CULL,
    0x9F555FA3C84C64C2ULL,
    0x2393B86B6F53B151ULL,
    0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL,
    0xBE5E1E2553863992ULL,
    0x2B0199FC2C85B8AAULL,
    0x0EB72DDC81C52CA2ULL
};

ErrCrypto SHA512_256_init(SHA512HashState* pHashState)
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



ErrCrypto SHA512_256_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    return SHA512_update(pHashState, pBuf, nLen);
}

ErrCrypto SHA512_256_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto err = ERR_OK;
    uint8_t buf[SHA512_DIGEST_SIZE] = { 0 };
    if (nDigest < SHA512_256_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }
    err = SHA512_final(pHashState, buf, SHA512_DIGEST_SIZE);
    memcpy(pDigest, buf, SHA512_256_DIGEST_SIZE);
    return err;
}

void test_sha512_256()
{
    SHA512HashState SHA512HashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abc";
    uint8_t digest[SHA512_256_DIGEST_SIZE] = {0};
    int i = 0;
    SHA512_256_init(&SHA512HashState);
    SHA512_256_update(&SHA512HashState, data, sizeof(data) - 1);
    SHA512_256_final(&SHA512HashState, digest, SHA512_256_DIGEST_SIZE);

    for (i = 0; i < SHA512_256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
