#ifndef _ENDIANESS_H
#define _ENDIANESS_H

#include "./common.h"

uint32_t u8to32_big(const uint8_t* pCh);
void u32to8_big(uint8_t* p, const uint32_t w);

 #endif
