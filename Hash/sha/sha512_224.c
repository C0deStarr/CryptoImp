
#include "./sha512_224.h"
#include <stdio.h>
#include <common/endianess.h>
#include <string.h>


static const uint64_t H[8] = {
    0x8C3D37C819544DA2ULL,
    0x73E1996689DCD4D6ULL,
    0x1DFAB7AE32FF9C82ULL,
    0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL,
    0x77E36F7304C48942ULL,
    0x3F9D85A86A1D36C8ULL,
    0x1112E6AD91D692A1ULL
};

ErrCrypto SHA512_224_init(SHA512HashState* pHashState)
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



ErrCrypto SHA512_224_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    return SHA512_update(pHashState, pBuf, nLen);
}

ErrCrypto SHA512_224_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto err = ERR_OK;
    uint8_t buf[SHA512_DIGEST_SIZE] = { 0 };
    if (nDigest < SHA512_224_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }
    err = SHA512_final(pHashState, buf, SHA512_DIGEST_SIZE);
    memcpy(pDigest, buf, SHA512_224_DIGEST_SIZE);
    return err;
}

void test_sha512_224()
{
    SHA512HashState SHA512HashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abc";
    uint8_t digest[SHA512_224_DIGEST_SIZE] = {0};
    int i = 0;
    SHA512_224_init(&SHA512HashState);
    SHA512_224_update(&SHA512HashState, data, sizeof(data) - 1);
    SHA512_224_final(&SHA512HashState, digest, SHA512_224_DIGEST_SIZE);

    for (i = 0; i < SHA512_224_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
