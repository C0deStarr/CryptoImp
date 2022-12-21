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



