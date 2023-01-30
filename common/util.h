#ifndef _UTIL_H
#define _UTIL_H
#include "common.h"
#include <Hash/hash.h>
void xor_buf(const uint8_t in[], uint8_t out[], uint32_t len);
void increment_ctr(uint8_t* pCtr/*ctr[BLOCK SIZE]*/, uint32_t nCtr);

ErrCrypto MGF1(uint8_t* pSeed
	, uint32_t nSeed
	, uint32_t nMaskLen
	, enum_hash enumHash
	, uint8_t* pOut
	, uint32_t nOut);
void test_mgf();
#endif 
