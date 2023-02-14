#include "chacha20.h"
#include <common/util.h>

// quarter round
#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL32(d,16); \
    c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d,8);  \
    c+=d; b^=c; b=ROTL32(b,7);  \
}

void test_chacha20()
{
    uint32_t a = 0x11111111;
    uint32_t b = 0x01020304;
    uint32_t c = 0x9b8d6f43;
    uint32_t d = 0x01234567;
    QR(a, b, c, d);

    return;
}