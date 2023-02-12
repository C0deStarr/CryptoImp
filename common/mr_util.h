#ifndef _MR_UTIL_H
#define _MR_UTIL_H

#include <miracl.h>
#include <common/common.h>

miracl* InitMiracl(int nd, mr_small nb);
void UninitMiracl();

void print_point(epoint* p);



/*
* http://www.sca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b791a9f908bb4803875ab6aeeb7b4e03.pdf
* Part 1 Section 4.2.8
*/
typedef enum {
	enum_nocompress = 0,	// 04 || x || y
	enum_compress = 1,	// PC || x, PC == 2 or 3
	enum_mix = 2	// PC || x || y, PC == 6 or 7
}EnumCompress;
/**
 * @brief 
 * @param nSizeX 
 *		sizeof X or Y
*/
void CompressPoint(EnumCompress compress
	, uint32_t nSizeX
	, int nLsbY
	, big x
	, big y
	, uint8_t* pOut
	, uint32_t nOut);

void DecompressPointY(EnumCompress compress
	, const uint8_t* pIn
	, uint32_t nIn
	, uint32_t nSizeX
	, big *x
	, big *y
	, int *pnLsbY);

#endif // !_MR_UTIL_H
