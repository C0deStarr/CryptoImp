#include "b64.h"


const char b64::_b64_enc_tbl[] = { 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};

int b64::b64_encode(char* pChIn, int nLen, char* pChOut)
{
    int nOffset = 0;
    int i, mod;
    int nOutLen = -1;
    int n24bits = 0;
    if (!pChIn || !pChOut)
    {
        return nOutLen;
    }

    mod = nLen % 3;
    n24bits = nLen - mod;
    for (i = 0; i < n24bits; i += 3)
    {
        pChOut[nOffset++] = _b64_enc_tbl[
            (pChIn[i] >> 2) 
                & 0x3F
        ];//i [7,2]
        pChOut[nOffset++] = _b64_enc_tbl[
            (((pChIn[i] & 0x3) << 4) | (pChIn[i + 1] >> 4)) 
                & 0x3F
        ];//i [1,0]   i+1 [7,4]
        pChOut[nOffset++] = _b64_enc_tbl[
            (((pChIn[i + 1] & 0xF) << 2) | (pChIn[i + 2] >> 6)) 
                & 0x3F
        ];//i+1 [3,0]   i+2 [7,6]
        pChOut[nOffset++] = _b64_enc_tbl[
            pChIn[i + 2] 
                & 0x3F
        ];//i+2 [5,0]
    }

    if (mod == 1) {
        pChOut[nOffset++] = _b64_enc_tbl[
            (pChIn[i] >> 2) & 0x3F
        ];//i [7,2]
        pChOut[nOffset++] = _b64_enc_tbl[
            (pChIn[i] & 0x3) << 4
        ];//i [1,0]
        pChOut[nOffset++] = '=';
        pChOut[nOffset++] = '=';
    }
    else if (mod == 2) {
        pChOut[nOffset++] = _b64_enc_tbl[
            (pChIn[i] >> 2) & 0x3F
        ];//i [7,2]
        pChOut[nOffset++] = _b64_enc_tbl[
            (((pChIn[i] & 0x3) << 4) | (pChIn[i + 1] >> 4)) 
                & 0x3F
        ];//i [1,0] i+1 [7,4]
        pChOut[nOffset++] = _b64_enc_tbl[
            (pChIn[i + 1] & 0xF) << 2
        ];
        pChOut[nOffset++] = '=';
    }
    pChOut[nOffset] = '\0';
    nOutLen = nOffset;
    return nOutLen;
}


