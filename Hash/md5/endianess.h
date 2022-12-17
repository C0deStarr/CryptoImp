

#ifndef ENDIANESS_H
#define ENDIANESS_H

#include "err.h"

static inline void u32to8_little(unsigned char *p, const unsigned long *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (unsigned char)*w;
    p[1] = (unsigned char)(*w >> 8);
    p[2] = (unsigned char)(*w >> 16);
    p[3] = (unsigned char)(*w >> 24);
#endif
}

static inline void u8to32_little(unsigned long *w, const unsigned char *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (unsigned long)p[0] | (unsigned long)p[1]<<8 | (unsigned long)p[2]<<16 | (unsigned long)p[3]<<24;
#endif
}

static inline void u32to8_big(unsigned char *p, const unsigned long *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (unsigned char)(*w >> 24);
    p[1] = (unsigned char)(*w >> 16);
    p[2] = (unsigned char)(*w >> 8);
    p[3] = (unsigned char)*w;
#endif
}

static inline void u8to32_big(unsigned long *w, const unsigned char *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (unsigned long)p[3] | (unsigned long)p[2]<<8 | (unsigned long)p[1]<<16 | (unsigned long)p[0]<<24;
#endif
}

static inline unsigned long load_u8to32_little(const unsigned char *p)
{
    unsigned long w;

    u8to32_little(&w, p);
    return w;
}

static inline unsigned long load_u8to32_big(const unsigned char *p)
{
    unsigned long w;

    u8to32_big(&w, p);
    return w;
}

#define LOAD_U32_LITTLE(p) load_u8to32_little(p)
#define LOAD_U32_BIG(p) load_u8to32_big(p)

#define STORE_U32_LITTLE(p, w) u32to8_little((p), &(w))
#define STORE_U32_BIG(p, w) u32to8_big((p), &(w))

static inline void u64to8_little(unsigned char *p, const unsigned long long *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (unsigned char)*w;
    p[1] = (unsigned char)(*w >> 8);
    p[2] = (unsigned char)(*w >> 16);
    p[3] = (unsigned char)(*w >> 24);
    p[4] = (unsigned char)(*w >> 32);
    p[5] = (unsigned char)(*w >> 40);
    p[6] = (unsigned char)(*w >> 48);
    p[7] = (unsigned char)(*w >> 56);
#endif
}

static inline void u8to64_little(unsigned long long *w, const unsigned char *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (unsigned long long)p[0]       |
         (unsigned long long)p[1] << 8  |
         (unsigned long long)p[2] << 16 |
         (unsigned long long)p[3] << 24 |
         (unsigned long long)p[4] << 32 |
         (unsigned long long)p[5] << 40 |
         (unsigned long long)p[6] << 48 |
         (unsigned long long)p[7] << 56;
#endif
}

static inline void u64to8_big(unsigned char *p, const unsigned long long *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (unsigned char)(*w >> 56);
    p[1] = (unsigned char)(*w >> 48);
    p[2] = (unsigned char)(*w >> 40);
    p[3] = (unsigned char)(*w >> 32);
    p[4] = (unsigned char)(*w >> 24);
    p[5] = (unsigned char)(*w >> 16);
    p[6] = (unsigned char)(*w >> 8);
    p[7] = (unsigned char)*w;
#endif
}

static inline void u8to64_big(unsigned long long *w, const unsigned char *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (unsigned long long)p[0] << 56 |
         (unsigned long long)p[1] << 48 |
         (unsigned long long)p[2] << 40 |
         (unsigned long long)p[3] << 32 |
         (unsigned long long)p[4] << 24 |
         (unsigned long long)p[5] << 16 |
         (unsigned long long)p[6] << 8  |
         (unsigned long long)p[7];
#endif
}

static inline unsigned long long load_u8to64_little(const unsigned char *p)
{
    unsigned long long w;

    u8to64_little(&w, p);
    return w;
}

static inline unsigned long long load_u8to64_big(const unsigned char *p)
{
    unsigned long long w;

    u8to64_big(&w, p);
    return w;
}

#define LOAD_U64_LITTLE(p) load_u8to64_little(p)
#define LOAD_U64_BIG(p) load_u8to64_big(p)

#define STORE_U64_LITTLE(p, w) u64to8_little((p), &(w))
#define STORE_U64_BIG(p, w) u64to8_big((p), &(w))

/**
 * Convert a big endian-encoded number in[] into a little-endian
 * 64-bit word array x[]. There must be enough words to contain the entire
 * number.
 */
static inline int bytes_to_words(unsigned long long *x, size_t words, const unsigned char *in, size_t len)
{
    unsigned char buf8[8];
    size_t words_used, bytes_in_msw, i;
    unsigned long long *xp;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == in)
        return ERR_NULL;

    memset(x, 0, words*sizeof(unsigned long long));

    /** Shorten the input **/
    for (; len > 0 && 0 == *in; in++, len--);
    if (0 == len)
        return 0;

    /** How many words we actually need **/
    words_used = (len + 7) / 8;
    if (words_used > words)
        return ERR_MAX_DATA;

    /** Not all bytes in the most-significant words are used **/
    bytes_in_msw = len % 8;
    if (bytes_in_msw == 0)
        bytes_in_msw = 8;

    /** Do most significant word **/
    memset(buf8, 0, 8);
    memcpy(buf8 + (8 - bytes_in_msw), in, bytes_in_msw);
    xp = &x[words_used-1];
    *xp = LOAD_U64_BIG(buf8);
    in += bytes_in_msw;

    /** Do the other words **/
    for (i=0; i<words_used-1; i++, in += 8) {
        xp--;
        *xp = LOAD_U64_BIG(in);
    }
    return 0;
}

/**
 * Convert a little-endian 64-bit word array x[] into a big endian-encoded
 * number out[]. The number is left-padded with zeroes if required.
 */
static inline int words_to_bytes(unsigned char *out, size_t len, const unsigned long long *x, size_t words)
{
    size_t i;
    const unsigned long long *msw;
    unsigned char buf8[8];
    size_t partial, real_len;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == out)
        return ERR_NULL;

    memset(out, 0, len);

    /* Shorten the input, so that the rightmost word is
     * the most significant one (and non-zero)
     */
    for (; words>0 && x[words-1]==0; words--);
    if (words == 0)
        return 0;
    msw = &x[words-1];

    /* Find how many non-zero bytes there are in the most-significant word */
    STORE_U64_BIG(buf8, *msw);
    for (partial=8; partial>0 && buf8[8-partial] == 0; partial--);
    assert(partial > 0);
    
    /** Check if there is enough room **/
    real_len = partial + 8*(words-1);
    if (real_len > len)
        return ERR_MAX_DATA;

    /** Pad **/
    out += len - real_len;

    /** Most significant word **/
    memcpy(out, buf8+(8-partial), partial);
    out += partial;
    msw--;

    /** Any remaining full word **/
    for (i=0; i<words-1; i++, out += 8, msw--)
        STORE_U64_BIG(out, *msw);

    return 0;
}

#endif
