#ifndef _UTIL_H
#define _UTIL_H
#include "common.h"
void xor_buf(const uint8_t in[], uint8_t out[], uint32_t len);
void increment_ctr(uint8_t* pCtr/*ctr[BLOCK SIZE]*/, uint32_t nCtr);
#endif 
