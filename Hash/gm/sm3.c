#include "sm3.h"
#include <common/endianess.h>
#include <common/util.h>
#include <string.h>
#include <stdio.h>
#define SM3_NUMBER_OF_ROUNDS 64


static const uint32_t IV[8] = {
	0x7380166f,
	0x4914b2b9,
	0x172442d7,
	0xda8a0600,
	0xa96f30bc,
	0x163138aa,
	0xe38dee4d,
	0xb0fb0e4e
};

// constants
// T[ j < 16 ? 0 : 1 ]
static const uint32_t T[2] =
{
	0x79CC4519, 0x7A879D8A
};


/**
 * @brief 
 *      bool func
 * @return 
*/
static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, uint32_t j)
{
    // 0 <= j <= 15
    if (j < 16) 
    {
        return x ^ y ^ z;
    }
    // 16 <= j <= 63
    else 
    {
        return (x & y) | (x & z) | (y & z);
    }
}

static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, uint32_t j)
{
    // 0 <= j <= 15
    if (j < 16) 
    {
        return x ^ y ^ z;
    }
    // 16 <= j <= 63
    else 
    {
        return (x & y) | (~x & z);
    }
}


/**
 * @brief 
 *      Permutation func
 *      P0 for CF
 *      P1 for extending
 * @return 
*/
static uint32_t P0(uint32_t x)
{
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}

static uint32_t P1(uint32_t x)
{
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}


static int SM3_ProcessBlock(SM3_HashState* pState)
{
    ErrCrypto errRet = ERR_OK;
    uint32_t j;
    uint32_t W[SM3_NUMBER_OF_ROUNDS + 4] = {0};
    uint32_t W1[SM3_NUMBER_OF_ROUNDS] = {0};
    uint32_t SS1 = 0;
    uint32_t SS2 = 0;
    uint32_t TT1 = 0;
    uint32_t TT2 = 0;
    uint32_t  A = 0;
    uint32_t  B = 0;
    uint32_t  C = 0;
    uint32_t  D = 0;
    uint32_t  E = 0;
    uint32_t  F = 0;
    uint32_t  G = 0;
    uint32_t  H = 0;
    uint8_t* pBlock = NULL;
    if (!pState)
    {
        return ERR_NULL;
    }

    A = pState->hash[0];
    B = pState->hash[1];
    C = pState->hash[2];
    D = pState->hash[3];
    E = pState->hash[4];
    F = pState->hash[5];
    G = pState->hash[6];
    H = pState->hash[7];
    
    pBlock = pState->block;

    for (j = 0; j < (SM3_NUMBER_OF_ROUNDS + 4); j++)
    {
        if (j < 16)
        {
            // init 16 uint32 
            // big endian
            W[j] = u8to32_big(pBlock + j * 4);
        }
        else
        {
            // extend W[16:68]
            W[j] = P1(
                    W[j - 16]
                    ^ W[j - 9]
                    ^ ROTL32(W[j - 3], 15)
                    )
                ^ ROTL32(W[j - 13], 7)
                ^ W[j - 6];
        }
    }

    // extend W[68:132] == W1
    for (j = 0; j < SM3_NUMBER_OF_ROUNDS; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }



    // CF
    for (j = 0; j < SM3_NUMBER_OF_ROUNDS; j++)
    {
        SS1 = ROTL32(
            ROTL32(A, 12)
                + E
                + ROTL32(T[j < 16 ? 0 : 1], j)
            , 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    pState->hash[0] ^= A;
    pState->hash[1] ^= B;
    pState->hash[2] ^= C;
    pState->hash[3] ^= D;
    pState->hash[4] ^= E;
    pState->hash[5] ^= F;
    pState->hash[6] ^= G;
    pState->hash[7] ^= H;
    return errRet;
}


ErrCrypto SM3_init(SM3_HashState* pHashState)
{
    ErrCrypto errRet = ERR_OK;
    uint8_t i = 0;
    if (!pHashState)
    {
        return ERR_NULL;
    }
    pHashState->nBitsLen = 0;
    pHashState->nBytesLen = 0;

    for (i = 0; i < 8; i++) {
        pHashState->hash[i] = IV[i];
    }
    return errRet;
}

static ErrCrypto AddBitsLen(SM3_HashState* pHashState, uint64_t nBits)
{
    // Maximum message length is 2**64 bits 
    pHashState->nBitsLen += nBits;
    return (pHashState->nBitsLen < nBits) ? ERR_MAX_DATA : ERR_OK;
}

ErrCrypto SM3_update(SM3_HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
    ErrCrypto errRet = ERR_OK;
    uint32_t nBytesNeeded = 0;
    uint32_t nBytesCopy = 0;
    if (!pHashState || !pBuf)
    {
        return ERR_NULL;
    }

    while (nLen > 0)
    {
        nBytesNeeded = SM3_BLOCK_SIZE - pHashState->nBytesLen;
        nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
        memcpy(&(pHashState->block[pHashState->nBytesLen]), pBuf, nBytesCopy);
        pBuf += nBytesCopy;
        pHashState->nBytesLen += nBytesCopy;
        nLen -= nBytesCopy;

        if (SM3_BLOCK_SIZE == pHashState->nBytesLen)
        {
            // let's do the 64 steps
            errRet = SM3_ProcessBlock(pHashState);
            if (errRet)
                return errRet;

            // waiting for the next block
            pHashState->nBytesLen = 0;
            errRet = AddBitsLen(pHashState, SM3_BLOCK_SIZE * 8);
            if (errRet)
                return errRet;
        }
    }
    return errRet;
}
ErrCrypto SM3_final(SM3_HashState* pHashState, uint8_t* pDigest, int nDigest)

{
    ErrCrypto errRet = ERR_OK;
    uint8_t nPadLen = 0;
    uint8_t nWordInDigest = 0;
    uint8_t i = 0;
    uint8_t arrMsgLength[8] = {0};
    static uint8_t PADDING[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    if (!pHashState)
    {
        return ERR_NULL;
    }

    if (nDigest < SM3_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }

    errRet = AddBitsLen(pHashState, (pHashState->nBytesLen) * 8);
    if (ERR_OK != errRet) {
        return ERR_MAX_DATA;
    }

    u64to8_big(arrMsgLength, pHashState->nBitsLen);
    // Padding the Message
    // 1 + 0s + 8-byte msg length
    nPadLen = (pHashState->nBytesLen < 56)
        ? (56 - pHashState->nBytesLen)
        : (SM3_BLOCK_SIZE + 56 - pHashState->nBytesLen);

    SM3_update(pHashState, PADDING, nPadLen);
    
    SM3_update(pHashState, arrMsgLength, 8);


   
    for (i = 0; i < 8; i++) {
        u32to8_big(pDigest, pHashState->hash[i]);
        pDigest += WORD_SIZE;
    }
    return errRet;
}


ErrCrypto SM3_digest(
    const uint8_t* pData, uint64_t nData
    , uint8_t* pDigest, uint32_t nDigest)
{
    ErrCrypto err = ERR_OK;
    SM3_HashState hashState = { 0 };

    if (!pData || !pDigest)
    {
        return ERR_NULL;
    }
    if (SM3_DIGEST_SIZE > nDigest)
    {
        return ERR_MAX_OFFSET;
    }
    do {
        if(ERR_OK != (err = SM3_init(&hashState)))
            break;
        if(ERR_OK != (err = SM3_update(&hashState, pData, nData)))
            break;
        
        if(ERR_OK != (err = SM3_final(&hashState, pDigest, SM3_DIGEST_SIZE)))
            break;

    }while(0);
    return err;
}

void test_sm3()
{
    SM3_HashState hashState = { 0 };
    ErrCrypto err = ERR_OK;
    uint8_t data[128] = 
        "\x64\xD2\x0D\x27\xD0\x63\x29\x57\xF8\x02\x8C\x1E\x02\x4F\x6B\x02\xED\xF2\x31\x02\xA5\x66\xC9\x32\xAE\x8B\xD6\x13\xA8\xE8\x65\xFE\x65\x6E\x63\x72\x79\x70\x74\x69\x6F\x6E\x20\x73\x74\x61\x6E\x64\x61\x72\x64\x58\xD2\x25\xEC\xA7\x84\xAE\x30\x0A\x81\xA2\xD4\x82\x81\xA8\x28\xE1\xCE\xDF\x11\xC4\x21\x90\x99\x84\x02\x65\x37\x50\x77\xBF\x78"
    ;
    uint8_t digest[SM3_DIGEST_SIZE] = { 0 };
	uint8_t true_digest[SM3_DIGEST_SIZE] = {
		"\x66\xc7\xf0\xf4\x62\xee\xed\xd9"
		"\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2"
		"\x41\x67\xc4\x87\x5c\xf2\xf7\xa2"
		"\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0"
	};
    int i = 0;
    SM3_init(&hashState);
    SM3_update(&hashState, data, 83);
    SM3_final(&hashState, digest, SM3_DIGEST_SIZE);
    if (0 == memcmp(true_digest, digest, SM3_DIGEST_SIZE))
    {
        printf("sm3(\"abc\") ok\n");
    }
    

    memcpy(data, 
        "\x64\xD2\x0D\x27\xD0\x63\x29\x57\xF8\x02\x8C\x1E\x02\x4F\x6B\x02\xED\xF2\x31\x02\xA5\x66\xC9\x32\xAE\x8B\xD6\x13\xA8\xE8\x65\xFE\x65\x6E\x63\x72\x79\x70\x74\x69\x6F\x6E\x20\x73\x74\x61\x6E\x64\x61\x72\x64\x58\xD2\x25\xEC\xA7\x84\xAE\x30\x0A\x81\xA2\xD4\x82\x81\xA8\x28\xE1\xCE\xDF\x11\xC4\x21\x90\x99\x84\x02\x65\x37\x50\x77\xBF\x78",
        83);
    memcpy(true_digest,
        "\x9C\x3D\x73\x60\xC3\x01\x56\xFA\xB7\xC8\x0A\x02\x76\x71\x2D\xA9\xD8\x09\x4A\x63\x4B\x76\x6D\x3A\x28\x5E\x07\x48\x06\x53\x42\x6D",
        SM3_DIGEST_SIZE);
     SM3_digest(data, 83,
         digest, SM3_DIGEST_SIZE 
     );
    
    if (0 == memcmp(true_digest, digest, SM3_DIGEST_SIZE))
    {
        printf("sm3_digest(512 bits) ok\n");
    }
    output_buf(digest, SM3_DIGEST_SIZE);
}