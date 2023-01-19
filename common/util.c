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

void increment_ctr(uint8_t* pCtr, uint32_t nCtr/* = BLOCK SIZE*/)
{
	int i = 0;

	if (pCtr)
	{
		// big-endian
		for (i = nCtr - 1; i >= 0; --i) {
			++pCtr[i];
			if (0 != pCtr[i])
				break;
		}

	}
}

