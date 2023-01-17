#include "util.h"


void xor_buf(const uint8_t in[], uint8_t out[], uint32_t nLen)
{
	uint32_t i = 0;
	if (in && out)
	{
		for (i = 0; i < nLen; ++i)
		{
			out[i] ^= in[i];
		}
	}
}