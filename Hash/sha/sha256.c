
#include "./sha256.h"
#include <common/endianess.h>


static const uint32_t K[SCHEDULE_SIZE] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define CH(x,y,z)       (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR32(n, x)    (((x)>>(n)) | ((x)<<(32-(n))))
#define SHR(n,x)        ((x)>>(n))
#define SIGMA_0_256(x)    (ROTR32(2,x)  ^ ROTR32(13,x) ^ ROTR32(22,x))
#define SIGMA_1_256(x)    (ROTR32(6,x)  ^ ROTR32(11,x) ^ ROTR32(25,x))
#define sigma_0_256(x)    (ROTR32(7,x)  ^ ROTR32(18,x) ^ SHR(3,x))
#define sigma_1_256(x)    (ROTR32(17,x) ^ ROTR32(19,x) ^ SHR(10,x))

// W[t] for 16 <= t <= 63
#define SCHEDULE(t) (sigma_1_256(W[t-2])    \
    + W[t-7]        \
    + sigma_0_256(W[t-15])  \
    + W[t-16])


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



ErrCrypto sha256_compress(HashState* pHashState)
{
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    uint32_t e = 0;
    uint32_t f = 0;
    uint32_t g = 0;
    uint32_t h = 0;

    uint32_t W[SCHEDULE_SIZE] = {0};
    unsigned int i = 0;

    // Prepare the message schedule
    for (i = 0; i < 16; ++i)
    {
        W[i] = u8to32_big(&(pHashState->block[4 * i]));
    }
    for (; i < SCHEDULE_SIZE; i++) {
        W[i] = SCHEDULE(i);
    }
    // 64 steps

    // Initialize the eight working variables
    a = pHashState->hash[0];
    b = pHashState->hash[1];
    c = pHashState->hash[2];
    d = pHashState->hash[3];
    e = pHashState->hash[4];
    f = pHashState->hash[5];
    g = pHashState->hash[6];
    h = pHashState->hash[7];




    // Compute the intermediate hash value
    pHashState->hash[0] += a;
    pHashState->hash[1] += b;
    pHashState->hash[2] += c;
    pHashState->hash[3] += d;
    pHashState->hash[4] += e;
    pHashState->hash[5] += f;
    pHashState->hash[6] += g;
    pHashState->hash[7] += h;
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