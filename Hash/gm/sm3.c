#include "sm3.h"


#define ROTL32(x,y) ( ((x) << (y)) | (x) >> (32-(y)) )

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
 * @param x 
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