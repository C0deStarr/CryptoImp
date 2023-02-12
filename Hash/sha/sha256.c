
#include "./sha256.h"
#include <common/endianess.h>
#include <string.h>

static const uint32_t K[SHA256_SCHEDULE_SIZE] = {
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

// 64 steps
#define CYCLE(a,b,c,d,e,f,g,h,t) \
    h += SIGMA_1_256(e) + CH(e,f,g) + K[t]  + W[t]; \
    d += h; \
    h += SIGMA_0_256(a) + MAJ(a,b,c);

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

ErrCrypto SHA256_init(SHA256_HashState* pHashState)
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



static ErrCrypto AddBitsLen(SHA256_HashState* pHashState, uint64_t nBits)
{
    // Maximum message length is 2**64 bits 
    pHashState->nBitsLen += nBits;
    return (pHashState->nBitsLen < nBits) ? ERR_MAX_DATA : ERR_OK;
}



ErrCrypto sha256_compress(SHA256_HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;

    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    uint32_t e = 0;
    uint32_t f = 0;
    uint32_t g = 0;
    uint32_t h = 0;

    uint32_t W[SHA256_SCHEDULE_SIZE] = {0};
    unsigned int i = 0;

    // Prepare the message schedule
    for (i = 0; i < 16; ++i)
    {
        W[i] = u8to32_big(&(pHashState->block[SHA256_WORD_SIZE * i]));
    }
    for (; i < SHA256_SCHEDULE_SIZE; i++) {
        W[i] = SCHEDULE(i);
    }

    // Initialize the eight working variables
    a = pHashState->hash[0];
    b = pHashState->hash[1];
    c = pHashState->hash[2];
    d = pHashState->hash[3];
    e = pHashState->hash[4];
    f = pHashState->hash[5];
    g = pHashState->hash[6];
    h = pHashState->hash[7];

    // 64 steps
    CYCLE(a, b, c, d, e, f, g, h, 0);
    CYCLE(h, a, b, c, d, e, f, g, 1);
    CYCLE(g, h, a, b, c, d, e, f, 2);
    CYCLE(f, g, h, a, b, c, d, e, 3);
    CYCLE(e, f, g, h, a, b, c, d, 4);
    CYCLE(d, e, f, g, h, a, b, c, 5);
    CYCLE(c, d, e, f, g, h, a, b, 6);
    CYCLE(b, c, d, e, f, g, h, a, 7);
    CYCLE(a, b, c, d, e, f, g, h, 8);
    CYCLE(h, a, b, c, d, e, f, g, 9);
    CYCLE(g, h, a, b, c, d, e, f, 10);
    CYCLE(f, g, h, a, b, c, d, e, 11);
    CYCLE(e, f, g, h, a, b, c, d, 12);
    CYCLE(d, e, f, g, h, a, b, c, 13);
    CYCLE(c, d, e, f, g, h, a, b, 14);
    CYCLE(b, c, d, e, f, g, h, a, 15);
    CYCLE(a, b, c, d, e, f, g, h, 16);
    CYCLE(h, a, b, c, d, e, f, g, 17);
    CYCLE(g, h, a, b, c, d, e, f, 18);
    CYCLE(f, g, h, a, b, c, d, e, 19);
    CYCLE(e, f, g, h, a, b, c, d, 20);
    CYCLE(d, e, f, g, h, a, b, c, 21);
    CYCLE(c, d, e, f, g, h, a, b, 22);
    CYCLE(b, c, d, e, f, g, h, a, 23);
    CYCLE(a, b, c, d, e, f, g, h, 24);
    CYCLE(h, a, b, c, d, e, f, g, 25);
    CYCLE(g, h, a, b, c, d, e, f, 26);
    CYCLE(f, g, h, a, b, c, d, e, 27);
    CYCLE(e, f, g, h, a, b, c, d, 28);
    CYCLE(d, e, f, g, h, a, b, c, 29);
    CYCLE(c, d, e, f, g, h, a, b, 30);
    CYCLE(b, c, d, e, f, g, h, a, 31);
    CYCLE(a, b, c, d, e, f, g, h, 32);
    CYCLE(h, a, b, c, d, e, f, g, 33);
    CYCLE(g, h, a, b, c, d, e, f, 34);
    CYCLE(f, g, h, a, b, c, d, e, 35);
    CYCLE(e, f, g, h, a, b, c, d, 36);
    CYCLE(d, e, f, g, h, a, b, c, 37);
    CYCLE(c, d, e, f, g, h, a, b, 38);
    CYCLE(b, c, d, e, f, g, h, a, 39);
    CYCLE(a, b, c, d, e, f, g, h, 40);
    CYCLE(h, a, b, c, d, e, f, g, 41);
    CYCLE(g, h, a, b, c, d, e, f, 42);
    CYCLE(f, g, h, a, b, c, d, e, 43);
    CYCLE(e, f, g, h, a, b, c, d, 44);
    CYCLE(d, e, f, g, h, a, b, c, 45);
    CYCLE(c, d, e, f, g, h, a, b, 46);
    CYCLE(b, c, d, e, f, g, h, a, 47);
    CYCLE(a, b, c, d, e, f, g, h, 48);
    CYCLE(h, a, b, c, d, e, f, g, 49);
    CYCLE(g, h, a, b, c, d, e, f, 50);
    CYCLE(f, g, h, a, b, c, d, e, 51);
    CYCLE(e, f, g, h, a, b, c, d, 52);
    CYCLE(d, e, f, g, h, a, b, c, 53);
    CYCLE(c, d, e, f, g, h, a, b, 54);
    CYCLE(b, c, d, e, f, g, h, a, 55);
    CYCLE(a, b, c, d, e, f, g, h, 56);
    CYCLE(h, a, b, c, d, e, f, g, 57);
    CYCLE(g, h, a, b, c, d, e, f, 58);
    CYCLE(f, g, h, a, b, c, d, e, 59);
    CYCLE(e, f, g, h, a, b, c, d, 60);
    CYCLE(d, e, f, g, h, a, b, c, 61);
    CYCLE(c, d, e, f, g, h, a, b, 62);
    CYCLE(b, c, d, e, f, g, h, a, 63);



    // Compute the intermediate hash value
    pHashState->hash[0] += a;
    pHashState->hash[1] += b;
    pHashState->hash[2] += c;
    pHashState->hash[3] += d;
    pHashState->hash[4] += e;
    pHashState->hash[5] += f;
    pHashState->hash[6] += g;
    pHashState->hash[7] += h;

    return errRet;
}

ErrCrypto SHA256_update(SHA256_HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    ErrCrypto errRet = ERR_OK;
    uint8_t nBytesNeeded = 0;
    uint8_t nBytesCopy = 0;

    if (!pHashState || !pBuf)
        return ERR_NULL;

    while (nLen > 0)
    {
        nBytesNeeded = SHA256_BLOCK_SIZE - pHashState->nBytesLen;
        nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
        memcpy(&(pHashState->block[pHashState->nBytesLen]), pBuf, nBytesCopy);
        pBuf += nBytesCopy;
        pHashState->nBytesLen += nBytesCopy;
        nLen -= nBytesCopy;

        if (SHA256_BLOCK_SIZE == pHashState->nBytesLen)
        {
            // let's do the 64 steps
            errRet = sha256_compress(pHashState);
            if (errRet)
                return errRet;

            // waiting for the next block
            pHashState->nBytesLen = 0;
            errRet = AddBitsLen(pHashState, SHA256_BLOCK_SIZE * 8);
            if (errRet)
                return errRet;
        }
    }
    return errRet;
}

ErrCrypto SHA256_final(SHA256_HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
    ErrCrypto errRet = ERR_OK;
    uint8_t nPadLen = 0;
    int i = 0;
    int nWordInDigest = 0;
    uint8_t arrMsgLength[8] = { 0 };
    static uint8_t PADDING[64] = {
       0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!pHashState || !pDigest)
        return ERR_NULL;
    if (SHA256_DIGEST_SIZE > nDigest)
        return ERR_MAX_OFFSET;

    // After last SHA1_update()
    // maybe 0 < nBytesLen <= BLOCK_SIZE
    errRet = AddBitsLen(pHashState, (pHashState->nBytesLen) * 8);
    if (errRet) {
        return ERR_MAX_DATA;
    }
    u64to8_big(arrMsgLength, pHashState->nBitsLen);

    // Padding the Message
    // 1 + 0s + 8-byte msg length
    nPadLen = (pHashState->nBytesLen < 56)
        ? (56 - pHashState->nBytesLen)
        : (SHA256_BLOCK_SIZE + 56 - pHashState->nBytesLen);

    SHA256_update(pHashState, PADDING, nPadLen);
    SHA256_update(pHashState, arrMsgLength, 8);

    for (i = 0; i < 8; i++) {
        u32to8_big(pDigest, pHashState->hash[i]);
        pDigest += SHA256_WORD_SIZE;
    }
    return errRet;
}


ErrCrypto SHA1256_HMAC(const uint8_t* pKey, int nKey,
    const uint8_t* pData, uint32_t nData,
    uint8_t* md, uint32_t* nMd)
{
    ErrCrypto errRet = ERR_OK;
    SHA256_HashState hashState = {0};
    uint8_t key_ipad[SHA256_BLOCK_SIZE] = { 0 };
    uint8_t key_opad[SHA256_BLOCK_SIZE] = {0};
    uint32_t i = 0;
    if(!pKey || !pData)
        return ERR_NULL;
    if(nMd < SHA256_DIGEST_SIZE)
        return ERR_DIGEST_SIZE;

    // 1. pad key
    if (nKey > SHA256_BLOCK_SIZE)
    {
        // hash then pad
        SHA256_init(&hashState);
        SHA256_update(&hashState, pKey, nKey);
        SHA256_final(&hashState, md, SHA256_DIGEST_SIZE);
        nKey = SHA256_DIGEST_SIZE;
        
        memcpy(key_ipad, md, nKey);
        memcpy(key_opad, md, nKey);
    }
    else
    {
        memcpy(key_ipad, pKey, nKey);
        memcpy(key_opad, pKey, nKey);
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; ++i)
    {
        key_ipad[i] ^= 0x36;
        key_opad[i] ^= 0x5c;
    }

    // inner hash
    SHA256_init(&hashState);
    SHA256_update(&hashState, key_ipad, SHA256_BLOCK_SIZE);
    SHA256_update(&hashState, pData, nData);
    SHA256_final(&hashState, md, SHA256_DIGEST_SIZE);

    // outer hash
    SHA256_init(&hashState);
    SHA256_update(&hashState, key_opad, SHA256_BLOCK_SIZE);
    SHA256_update(&hashState, md, SHA256_DIGEST_SIZE);
    SHA256_final(&hashState, md, SHA256_DIGEST_SIZE);

    return errRet;
}

void test_sha256()
{
    SHA256_HashState hashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t digest[SHA256_DIGEST_SIZE] = {0};
    int i = 0;
    SHA256_init(&hashState);
    SHA256_update(&hashState, data, sizeof(data) - 1);
    SHA256_final(&hashState, digest, SHA256_DIGEST_SIZE);
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

void test_sha256_hmac()
{
    uint8_t data[] = "Hello";
    uint8_t key[] = "Swordfish";
    uint8_t digest[SHA256_DIGEST_SIZE] = { 0 };
    int i = 0;
    SHA1256_HMAC(key, sizeof(key)-1,
        data, sizeof(data)-1,
        digest, SHA256_DIGEST_SIZE);
    for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}