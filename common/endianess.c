#include "./endianess.h"

uint32_t u8to32_big(const uint8_t* pCh)
{
    uint32_t nRet = 0;
    if (pCh)
    {
        nRet = (uint32_t)pCh[3]
            | (uint32_t)pCh[2] << 8
            | (uint32_t)pCh[1] << 16
            | (uint32_t)pCh[0] << 24;
    }
    return nRet;
}

uint64_t u8to64_big(const uint8_t* pCh)
{
    uint64_t ullRet = 0;
    if (pCh)
    {
        ullRet = (uint64_t)pCh[7]
            | (uint64_t)pCh[6] << 8
            | (uint64_t)pCh[5] << 16
            | (uint64_t)pCh[4] << 24
            | (uint64_t)pCh[3] << 32
            | (uint64_t)pCh[2] << 40
            | (uint64_t)pCh[1] << 48
            | (uint64_t)pCh[0] << 56;
    }
    return ullRet;
}

void u32to8_big(uint8_t* p, const uint32_t w)
{
    if (p)
    {
        p[0] = (uint8_t)(w >> 24);
        p[1] = (uint8_t)(w >> 16);
        p[2] = (uint8_t)(w >> 8);
        p[3] = (uint8_t)w;
    }
}

uint32_t u8to32_little(const uint8_t* pCh)
{
    uint32_t nRet = 0;
    if (pCh)
    {
        nRet =(uint32_t)pCh[0]
            | (uint32_t)pCh[1] << 8
            | (uint32_t)pCh[2] << 16
            | (uint32_t)pCh[3] << 24;
    }
    return nRet;
}
void u32to8_little(uint8_t* p, const uint32_t w)
{
    if (p)
    {
        p[0] = (uint8_t)w;
        p[1] = (uint8_t)(w >> 8);
        p[2] = (uint8_t)(w >> 16);
        p[3] = (uint8_t)(w >> 24);
    }
}

void u64to8_big(uint8_t* p, const uint64_t w)
{
    if (p)
    {
        p[0] = (uint8_t)(w >> 56);
        p[1] = (uint8_t)(w >> 48);
        p[2] = (uint8_t)(w >> 40);
        p[3] = (uint8_t)(w >> 32);
        p[4] = (uint8_t)(w >> 24);
        p[5] = (uint8_t)(w >> 16);
        p[6] = (uint8_t)(w >> 8);
        p[7] = (uint8_t)w;
    }
}

uint64_t u8to64_little(const uint8_t* pCh)
{
    uint64_t ullRet = 0;
    if (pCh)
    {
        ullRet = (uint64_t)pCh[0]
            | (uint64_t)pCh[1] << 8
            | (uint64_t)pCh[2] << 16
            | (uint64_t)pCh[3] << 24
            | (uint64_t)pCh[4] << 32
            | (uint64_t)pCh[5] << 40
            | (uint64_t)pCh[6] << 48
            | (uint64_t)pCh[7] << 56;
    }
    return ullRet;
}

void u64to8_little(uint8_t* p, const uint64_t w)
{
    if (p)
    {
        p[0] = (uint8_t)w;
        p[1] = (uint8_t)(w >> 8);
        p[2] = (uint8_t)(w >> 16);
        p[3] = (uint8_t)(w >> 24);
        p[4] = (uint8_t)(w >> 32);
        p[5] = (uint8_t)(w >> 40);
        p[6] = (uint8_t)(w >> 48);
        p[7] = (uint8_t)(w >> 56);
    }
}