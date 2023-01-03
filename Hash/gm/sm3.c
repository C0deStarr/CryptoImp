#include "sm3.h"
#include <common/endianess.h>

#define SM3_NUMBER_OF_ROUNDS 64

#define ROTL(x,y) ( ((x) << (y)) | (x) >> (32-(y)) )

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
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

static uint32_t P1(uint32_t x)
{
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}


static int SM3_ProcessBlock(SM3_State* pState, const uint8_t* pBlock)
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

    if (!pState || !pBlock)
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
                    ^ ROTL(W[j - 3], 15)
                    )
                ^ ROTL(W[j - 13], 7)
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
        SS1 = ROTL(
            ROTL(A, 12)
                + E
                + ROTL(T[j < 16 ? 0 : 1], j)
            , 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    return errRet;
}