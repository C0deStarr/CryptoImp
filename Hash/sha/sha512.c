
#include "./sha512.h"
#include <stdio.h>
#include <common/endianess.h>
#include <common/util.h>
#include <string.h>

static const uint64_t K[SHA512_SCHEDULE_SIZE] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define CH(x,y,z)       (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))


#define SHR(n,x)        ((x)>>(n))
#define SIGMA_0_512(x)    (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define SIGMA_1_512(x)    (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma_0_512(x)    (ROTR64(x, 1)  ^ ROTR64(x, 8)  ^ SHR(7,x))
#define sigma_1_512(x)    (ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR(6,x))

// W[t] for 16 <= t <= 80
#define SCHEDULE(t) (sigma_1_512(W[t-2])    \
    + W[t-7]        \
    + sigma_0_512(W[t-15])  \
    + W[t-16])

// 64 steps
#define CYCLE(a,b,c,d,e,f,g,h,t) \
    h += SIGMA_1_512(e) + CH(e,f,g) + K[t]  + W[t]; \
    d += h; \
    h += SIGMA_0_512(a) + MAJ(a,b,c);

static const uint64_t H[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL
};

ErrCrypto SHA512_init(SHA512HashState* pHashState)
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


ErrCrypto SHA512_t_init(SHA512HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;
    int i = 0;

    if (!pHashState)
        return ERR_NULL;


    pHashState->nArrBitsLen[0] = 0;
    pHashState->nArrBitsLen[1] = 0;
    pHashState->nBytesLen = 0;

    // SHA-512/t IV Generation Function
    for (i = 0; i < 8; i++) {
        pHashState->hash[i] = H[i] ^ 0xa5a5a5a5a5a5a5a5ULL;
    }
    return errRet;
}


static ErrCrypto AddBitsLen(SHA512HashState* pHashState, uint64_t nBits)
{
    // Maximum message length is 2**64 bits 
    pHashState->nArrBitsLen[0] += nBits;
    if (pHashState->nArrBitsLen[0] >= nBits)
    {
        // not overflow
        return ERR_OK;
    }

    // overflow
    pHashState->nArrBitsLen[1] += 1;
    if (pHashState->nArrBitsLen[1] > 0)
    {
        return ERR_OK;
    }
    return ERR_MAX_DATA;
}



ErrCrypto sha512_compress(SHA512HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;

    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t c = 0;
    uint64_t d = 0;
    uint64_t e = 0;
    uint64_t f = 0;
    uint64_t g = 0;
    uint64_t h = 0;

    uint64_t W[SHA512_SCHEDULE_SIZE] = {0};
    unsigned int i = 0;

    // Prepare the message schedule
    for (i = 0; i < 16; ++i)
    {
        W[i] = u8to64_big(&(pHashState->block[SHA512_WORD_SIZE * i]));
    }
    for (; i < SHA512_SCHEDULE_SIZE; i++) {
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

    // 80 steps
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

    CYCLE(a, b, c, d, e, f, g, h, 64);
    CYCLE(h, a, b, c, d, e, f, g, 65);
    CYCLE(g, h, a, b, c, d, e, f, 66);
    CYCLE(f, g, h, a, b, c, d, e, 67);
    CYCLE(e, f, g, h, a, b, c, d, 68);
    CYCLE(d, e, f, g, h, a, b, c, 69);
    CYCLE(c, d, e, f, g, h, a, b, 70);
    CYCLE(b, c, d, e, f, g, h, a, 71);
    CYCLE(a, b, c, d, e, f, g, h, 72);
    CYCLE(h, a, b, c, d, e, f, g, 73);
    CYCLE(g, h, a, b, c, d, e, f, 74);
    CYCLE(f, g, h, a, b, c, d, e, 75);
    CYCLE(e, f, g, h, a, b, c, d, 76);
    CYCLE(d, e, f, g, h, a, b, c, 77);
    CYCLE(c, d, e, f, g, h, a, b, 78);
    CYCLE(b, c, d, e, f, g, h, a, 79);


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

ErrCrypto SHA512_update(SHA512HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    ErrCrypto errRet = ERR_OK;
    uint32_t nBytesNeeded = 0;
    uint32_t nBytesCopy = 0;

    if (!pHashState || !pBuf)
        return ERR_NULL;

    while (nLen > 0)
    {
        nBytesNeeded = SHA512_BLOCK_SIZE - pHashState->nBytesLen;
        nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
        memcpy(&(pHashState->block[pHashState->nBytesLen]), pBuf, nBytesCopy);
        pBuf += nBytesCopy;
        pHashState->nBytesLen += nBytesCopy;
        nLen -= nBytesCopy;

        if (SHA512_BLOCK_SIZE == pHashState->nBytesLen)
        {
            // let's do the 80 steps
            errRet = sha512_compress(pHashState);
            if (errRet)
                return errRet;

            // waiting for the next block
            pHashState->nBytesLen = 0;
            errRet = AddBitsLen(pHashState, SHA512_BLOCK_SIZE * 8);
            if (errRet)
                return errRet;
        }
    }
    return errRet;
}

ErrCrypto SHA512_final(SHA512HashState* pHashState, uint8_t* pDigest, int nDigest/* SHA512_DIGEST_SIZE */)
{
    ErrCrypto errRet = ERR_OK;
    uint8_t nPadLen = 0;
    int i = 0;
    uint8_t arrMsgLength[16] = { 0 };

    static uint8_t PADDING[128] = {
        0x80, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };

    if (!pHashState || !pDigest)
        return ERR_NULL;
    if (SHA512_DIGEST_SIZE > nDigest)
        return ERR_MAX_OFFSET;

    // After last SHA1_update()
    // maybe 0 < nBytesLen <= BLOCK_SIZE
    errRet = AddBitsLen(pHashState, (pHashState->nBytesLen) * 8);
    if (errRet) {
        return ERR_MAX_DATA;
    }
    u64to8_big(arrMsgLength
        , pHashState->nArrBitsLen[1]);
    u64to8_big(&(arrMsgLength)[8]
        , pHashState->nArrBitsLen[0]);

    // Padding the Message
    // 1 + 0s + 16-byte msg length
    nPadLen = (pHashState->nBytesLen < 112)
        ? (112 - pHashState->nBytesLen)
        : (SHA512_BLOCK_SIZE + 112 - pHashState->nBytesLen);
    SHA512_update(pHashState, PADDING, nPadLen);
    SHA512_update(pHashState, arrMsgLength, 16);

    for (i = 0; i < 8; i++) {
        u64to8_big(pDigest, pHashState->hash[i]);
        pDigest += SHA512_WORD_SIZE;
    }
    return errRet;
}

void test_sha512()
{
    SHA512HashState SHA512HashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t digest[SHA512_DIGEST_SIZE] = {0};
    int i = 0;
    SHA512_init(&SHA512HashState);
    SHA512_update(&SHA512HashState, data, sizeof(data) - 1);
    SHA512_final(&SHA512HashState, digest, SHA512_DIGEST_SIZE);
    for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

void sha512_t_iv_generator()
{
    SHA512HashState SHA512HashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t sha512_224[] = "SHA-512/224";
    uint8_t sha512_256[] = "SHA-512/256";
    uint8_t digest[SHA512_DIGEST_SIZE] = { 0 };
    int i = 0;
    SHA512_t_init(&SHA512HashState);
    SHA512_update(&SHA512HashState, sha512_224, sizeof(sha512_224) - 1);
    SHA512_final(&SHA512HashState, digest, SHA512_DIGEST_SIZE);
    for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
        printf("%02x%c", digest[i], 
            ((i+1) % 8) ? '\x0' : '\n' );
    }
    printf("\n");

    SHA512_t_init(&SHA512HashState);
    SHA512_update(&SHA512HashState, sha512_256, sizeof(sha512_256) - 1);
    SHA512_final(&SHA512HashState, digest, SHA512_DIGEST_SIZE);
    for (i = 0; i < SHA512_DIGEST_SIZE; i++) {
        printf("%02x%c", digest[i],
            ((i+1) % 8) ? '\x0' : '\n');
    }
    printf("\n");
}