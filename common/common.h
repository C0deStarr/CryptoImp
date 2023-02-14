/* COMMON.H - RSAREF types and constants
 */
 
#ifndef _COMMON_H
#define _COMMON_H

#include "./errors.h"

#define MAX(a,b)  (((a) > (b)) ? (a) : (b))
#define MIN(a,b)  (((a) > (b)) ? (b) : (a))

 // POINTER defines a generic pointer type
typedef unsigned char* POINTER;
// UINT2 defines a 1-byte int
typedef unsigned char uint8_t;
// UINT2 defines a 2-byte int
typedef unsigned short int uint16_t;
// UINT4 defines a 4-byte int
typedef unsigned long int uint32_t;
// UINT8 defines a 8-byte int
typedef unsigned long long int uint64_t;
#endif