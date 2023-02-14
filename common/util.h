#ifndef _UTIL_H
#define _UTIL_H
#include "common.h"
#include <Hash/hash.h>

#define ROTL32(x, n)	(((x) << (n)) | ((x) >> (32-(n))))
#define ROTL64(x, n)	(((x) << (n)) | ((x) >> (64-(n))))
#define ROTR32(x, n)	(((x) >> (n)) | ((x) << (32-(n))))
#define ROTR64(x, n)    (((x) >> (n)) | ((x) << (64-(n))))

void output_buf(const uint8_t *pBuf, uint32_t nBuf);

void xor_buf(const uint8_t in[], uint8_t out[], uint32_t len);
void increment_ctr(uint8_t* pCtr/*ctr[BLOCK SIZE]*/, uint32_t nCtr);
/**
 * @brief 
 *		rfc 8017 B.2.1
*/
uint32_t MGF1(uint8_t* pSeed
	, uint32_t nSeed
	, uint32_t nMaskLen
	, enum_hash enumHash
	, uint8_t* pOut
	, uint32_t nOut);
void test_mgf();

void GetRandomBytes(uint8_t* pBuf, uint32_t nLen);
#endif 
