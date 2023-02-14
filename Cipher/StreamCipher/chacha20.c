#include "chacha20.h"
#include <common/util.h>
#include <common/endianess.h>
#include <string.h>


// quarter round
#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL32(d,16); \
    c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d,8);  \
    c+=d; b^=c; b=ROTL32(b,7);  \
}

ErrCrypto chacha20_init(chacha20* pState,
    const uint8_t* pKey,
    uint32_t nKey,
    const uint8_t* pNonce,
    uint32_t nNonce)
{
    ErrCrypto err = ERR_OK;
    uint8_t nonce[24] = {0};
    uint32_t i = 0;

    if (!pState || !pKey)
    {
        return ERR_NULL;
    }
    if (CHACHA20_KEY_SIZE != nKey)
    {
        return ERR_KEY_SIZE;
    }

    if (!pNonce || 
        ((8 != nNonce) && (12 != nNonce)))
    {
        GetRandomBytes(nonce, 12);
        pNonce = nonce;
    }

    memset(pState->hash, 0, sizeof(pState->hash));

    pState->hash[0] = 0x61707865;
    pState->hash[1] = 0x3320646e;
    pState->hash[2] = 0x79622d32;
    pState->hash[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        pState->hash[4 + i] = u8to32_little(pKey + 4 * i);
    }
    switch (nNonce) {
    case 8: {
        /*
        cccccccc  cccccccc  cccccccc  cccccccc
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        bbbbbbbb  BBBBBBBB  nnnnnnnn  nnnnnnnn

        c=constant k=key b=blockcount(low) B=blockcount(high) n=nonce
        */

        /** h[12] remains 0 (offset) **/
        /** h[13] remains 0 (offset) **/
        pState->hash[14] = u8to32_little(pNonce + 0);
        pState->hash[15] = u8to32_little(pNonce + 4);
        break;
    }
    case 12: {
        /*
        cccccccc  cccccccc  cccccccc  cccccccc
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
        bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

        c=constant k=key b=blockcount n=nonce
        */

        /** h[12] remains 0 (offset) **/
        pState->hash[13] = u8to32_little(pNonce + 0);
        pState->hash[14] = u8to32_little(pNonce + 4);
        pState->hash[15] = u8to32_little(pNonce + 8);
        break;
    }
    // case 16: {
    //     /*
    //     cccccccc  cccccccc  cccccccc  cccccccc
    //     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    //     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    //     nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
    // 
    //     c=constant k=key n=nonce
    //     */
    // 
    //     pState->hash[12] = u8to32_little(nonce + 0);
    //     pState->hash[13] = u8to32_little(nonce + 4);
    //     pState->hash[14] = u8to32_little(nonce + 8);
    //     pState->hash[15] = u8to32_little(nonce + 12);
    //     break;
    // }
    default:
        return ERR_NONCE_SIZE;
    }

    return err;
}

void test_chacha20()
{
    chacha20 state = {0};
    uint8_t key[] = {
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    };
    uint32_t nKey = sizeof(key) - 1;
    uint8_t nonce[] = {
        "\x00\x00\x00\x09\x00\x00\x00\x4a\x00\x00\x00\x00"
    };
    uint32_t nNonce = sizeof(nonce) - 1;
    chacha20_init(&state
        , key, nKey
        , nonce, nNonce);
#ifdef _DEBUG
    state.hash[12] = u8to32_little("\x01\x00\x00\x00");
#endif
    return;
}