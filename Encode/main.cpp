#include <iostream>
#include "b64.h"

int main()
{
    char pChMsg[] = "���a";
    char pChB64[1024] = { 0 };
    int nMsgLen = sizeof(pChMsg);
    if (-1 != b64::b64_encode(pChMsg, nMsgLen, pChB64))
    {
        printf("%s\n", pChB64);
    }
    getchar();
}