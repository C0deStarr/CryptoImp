#include <string.h>
#include "sha1.h"
#include <common/endianess.h>
#include <common/util.h>

#define CH(x,y,z)       ((x & y) ^ (~x & z))            /** 0  <= t <= 19 **/
#define PARITY(x,y,z)   (x ^ y ^ z)                     /** 20 <= t <= 39  and 60 <= t <= 79 **/
#define MAJ(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))   /** 40 <= t <= 59 **/

#define ROTL1(x)        (((x)<<1)  | ((x)>>(32-1)))
#define ROTL5(x)        (((x)<<5)  | ((x)>>(32-5)))
#define ROTL30(x)       (((x)<<30) | ((x)>>(32-30)))

#define Kx  0x5a827999  /** 0  <= t <= 19 **/
#define Ky  0x6ed9eba1  /** 20 <= t <= 39 **/
#define Kz  0x8f1bbcdc  /** 40 <= t <= 59 **/
#define Kw  0xca62c1d6  /** 60 <= t <= 79 **/

// Prepare the message schedule 
// W[t] for t>=16
#define SCHEDULE(t)        (W[t&15] = ROTL1(    \
    W[(t-3)&15]     \
    ^ W[(t-8)&15]   \
    ^ W[(t-14)&15]  \
    ^ W[t&15]))

#define ROUND_0_15(t) {                                 \
    uint32_t T;                                         \
    T = ROTL5(a) + CH(b,c,d) + e + Kx + W[t];           \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_16_19(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + CH(b,c,d) + e + Kx + SCHEDULE(t);       \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_20_39(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + PARITY(b,c,d) + e + Ky + SCHEDULE(t); \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_40_59(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + MAJ(b,c,d) + e + Kz + SCHEDULE(t);      \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_60_79(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + PARITY(b,c,d) + e + Kw + SCHEDULE(t);   \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }


ErrCrypto SHA1_init(HashState* pHashState)
{
	ErrCrypto errRet = ERR_OK;

	if (!pHashState)
		return ERR_NULL;


    pHashState->nBitsLen = 0;
    pHashState->nBytesLen = 0;

	pHashState->hash[0] = 0x67452301;
	pHashState->hash[1] = 0xefcdab89;
	pHashState->hash[2] = 0x98badcfe;
	pHashState->hash[3] = 0x10325476;
	pHashState->hash[4] = 0xc3d2e1f0;

	return errRet;
}


static ErrCrypto AddBitsLen(HashState* pHashState, uint64_t nBits)
{
	// Maximum message length is 2**64 bits 
	pHashState->nBitsLen += nBits;
	return (pHashState->nBitsLen < nBits) ? ERR_MAX_DATA : ERR_OK;
}



static ErrCrypto sha1_compress(HashState* pHashState)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t a = 0;
	uint32_t b = 0;
	uint32_t c = 0;
	uint32_t d = 0;
	uint32_t e = 0;
    uint32_t W[16] = { 0 };
    int i = 0;
	if (!pHashState)
	{
		return ERR_NULL;
	}

    // Prepare the message schedule
    // t <= 15
    for (i = 0; i < 16; ++i)
    {
        W[i] = u8to32_big(&(pHashState->block[4 * i]));
    }
    
	// Initialize the five working variables
	a = pHashState->hash[0];
	b = pHashState->hash[1];
	c = pHashState->hash[2];
	d = pHashState->hash[3];
	e = pHashState->hash[4];

    // 0 <= t <= 15
    ROUND_0_15(0);
    ROUND_0_15(1);
    ROUND_0_15(2);
    ROUND_0_15(3);
    ROUND_0_15(4);
    ROUND_0_15(5);
    ROUND_0_15(6);
    ROUND_0_15(7);
    ROUND_0_15(8);
    ROUND_0_15(9);
    ROUND_0_15(10);
    ROUND_0_15(11);
    ROUND_0_15(12);
    ROUND_0_15(13);
    ROUND_0_15(14);
    ROUND_0_15(15);
    // 16 <= t <= 19 
    ROUND_16_19(16);
    ROUND_16_19(17);
    ROUND_16_19(18);
    ROUND_16_19(19);
    // 20 <= t <= 39
    ROUND_20_39(20);
    ROUND_20_39(21);
    ROUND_20_39(22);
    ROUND_20_39(23);
    ROUND_20_39(24);
    ROUND_20_39(25);
    ROUND_20_39(26);
    ROUND_20_39(27);
    ROUND_20_39(28);
    ROUND_20_39(29);
    ROUND_20_39(30);
    ROUND_20_39(31);
    ROUND_20_39(32);
    ROUND_20_39(33);
    ROUND_20_39(34);
    ROUND_20_39(35);
    ROUND_20_39(36);
    ROUND_20_39(37);
    ROUND_20_39(38);
    ROUND_20_39(39);
    // 40 <= t <= 59
    ROUND_40_59(40);
    ROUND_40_59(41);
    ROUND_40_59(42);
    ROUND_40_59(43);
    ROUND_40_59(44);
    ROUND_40_59(45);
    ROUND_40_59(46);
    ROUND_40_59(47);
    ROUND_40_59(48);
    ROUND_40_59(49);
    ROUND_40_59(50);
    ROUND_40_59(51);
    ROUND_40_59(52);
    ROUND_40_59(53);
    ROUND_40_59(54);
    ROUND_40_59(55);
    ROUND_40_59(56);
    ROUND_40_59(57);
    ROUND_40_59(58);
    ROUND_40_59(59);
    // 60 <= t <= 79
    ROUND_60_79(60);
    ROUND_60_79(61);
    ROUND_60_79(62);
    ROUND_60_79(63);
    ROUND_60_79(64);
    ROUND_60_79(65);
    ROUND_60_79(66);
    ROUND_60_79(67);
    ROUND_60_79(68);
    ROUND_60_79(69);
    ROUND_60_79(70);
    ROUND_60_79(71);
    ROUND_60_79(72);
    ROUND_60_79(73);
    ROUND_60_79(74);
    ROUND_60_79(75);
    ROUND_60_79(76);
    ROUND_60_79(77);
    ROUND_60_79(78);
    ROUND_60_79(79);

    // Compute the intermediate hash value
    pHashState->hash[0] += a;
    pHashState->hash[1] += b;
    pHashState->hash[2] += c;
    pHashState->hash[3] += d;
    pHashState->hash[4] += e;

	return errRet;
}

ErrCrypto SHA1_update(HashState* pHashState, const uint8_t* pBuf, uint64_t nLen)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t nBytesNeeded = 0;
	uint8_t nBytesCopy = 0;
	if(!pHashState || !pBuf)
		return ERR_NULL;

	while (nLen > 0)
	{
		nBytesNeeded = SHA1_BLOCK_SIZE - pHashState->nBytesLen;
		nBytesCopy = (nBytesNeeded > nLen) ? nLen : nBytesNeeded;
		memcpy(&(pHashState->block[pHashState->nBytesLen]), pBuf, nBytesCopy);
		pBuf += nBytesCopy;
		pHashState->nBytesLen += nBytesCopy;
		nLen -= nBytesCopy;

		if (SHA1_BLOCK_SIZE == pHashState->nBytesLen)
		{
			// let's do the 80 steps
			errRet = sha1_compress(pHashState);
			if (errRet)
				return errRet;

			// waiting for the next block
			pHashState->nBytesLen = 0;
			errRet = AddBitsLen(pHashState, SHA1_BLOCK_SIZE*8);
			if(errRet)
				return errRet;
		}
	}

	return errRet;
}

ErrCrypto SHA1_final(HashState* pHashState, uint8_t* pDigest, int nDigest/* DIGEST_SIZE */)
{
	ErrCrypto errRet = ERR_OK;
    uint8_t nPadLen = 0;
    int i = 0;
    uint8_t arrMsgLength[8] = { 0 };
    static uint8_t PADDING[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if(!pHashState || !pDigest)
        return ERR_NULL;
    if (SHA1_DIGEST_SIZE > nDigest)
        return ERR_MAX_OFFSET;

    // After last SHA1_update()
    // maybe 0 < nBytesLen <= BLOCK_SIZE
    errRet = AddBitsLen(pHashState, (pHashState->nBytesLen) * 8);
    if (errRet) {
        return ERR_MAX_DATA;
    }
    u64to8_big(arrMsgLength, pHashState->nBitsLen);

    // Padding the Message
    // 1 + 0s + 8-byte msg length
    nPadLen = (pHashState->nBytesLen < 56)
        ? (56 - pHashState->nBytesLen) 
        : (SHA1_BLOCK_SIZE + 56 - pHashState->nBytesLen);

    SHA1_update(pHashState, PADDING, nPadLen);
    /*
      abcde-->
        61626364 65800000 00000000 00000000
        00000000 00000000 00000000 00000000
        00000000 00000000 00000000 00000000
        00000000 00000000 00000000 00000028
    */

    SHA1_update(pHashState, arrMsgLength, 8);

    for (i = 0; i < 5; i++) {
        u32to8_big(pDigest, pHashState->hash[i]);
        pDigest += 4;
    }
	return errRet;
}

ErrCrypto SHA1_digest(const uint8_t* pData, uint64_t nData, uint8_t* pDigest, uint32_t nDigest)
{
    ErrCrypto errRet = ERR_OK;
    HashState hashState = { 0 };
    if (!pData || !pDigest)
    {
        return ERR_NULL;
    }
    if (nDigest < SHA1_DIGEST_SIZE)
    {
        return ERR_MAX_OFFSET;
    }
    do {
        errRet = SHA1_init(&hashState);
        if(ERR_OK != errRet) break;
        errRet = SHA1_update(&hashState, pData, nData);
        if (ERR_OK != errRet) break;
        errRet = SHA1_final(&hashState, pDigest, SHA1_DIGEST_SIZE);
        if (ERR_OK != errRet) break;
    }while(0);
    return errRet;
}


void test_sha1()
{
	HashState hashState = {0};
	ErrCrypto err = ERR_OK;
    uint8_t data[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    uint8_t digest[SHA1_DIGEST_SIZE] = {0};
    int i = 0 ;
    /*
    * 17c21161345819046652e358d69182560ed9ac34
    */
	err = SHA1_init(&hashState);
	err = SHA1_update(&hashState, data, sizeof(data) - 1);
    err = SHA1_final(&hashState, digest, SHA1_DIGEST_SIZE);
    output_buf(digest, SHA1_DIGEST_SIZE);

    SHA1_digest(data, sizeof(data)-1, digest, SHA1_DIGEST_SIZE);
    output_buf(digest, SHA1_DIGEST_SIZE);

}