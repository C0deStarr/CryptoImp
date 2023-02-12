#include "mr_util.h"

miracl *g_pMip = NULL;

miracl* InitMiracl(int nd, mr_small nb)
{
	miracl* pMip = get_mip();
	if (pMip)
	{
		g_pMip = pMip;
	}
	if (!g_pMip && !pMip)
	{
		g_pMip = mirsys(nd, nb);
	}
	g_pMip->IOBASE = nb;
	return g_pMip;
}

void UninitMiracl()
{
	if (g_pMip)
	{
		mirexit();
		g_pMip = NULL;
	}
}


void print_point(epoint* p)
{
	big bx = mirvar(0);
	big by = mirvar(0);
	char x = 0, y = 0;

	epoint_get(p, bx, by);

	big_to_bytes(1, bx, &x, TRUE);
	big_to_bytes(1, by, &y, TRUE);
	printf("(%d, %d)\n", x, y);
}



void CompressPoint(EnumCompress compress
	, uint32_t nSizeX
	, int nLsbY
	, big x
	, big y
	, uint8_t* pOut
	, uint32_t nOut)
{
	if (!pOut)
	{
		return;
	}
	switch (compress)
	{
	case enum_nocompress:
	{
		if (!x || !y) break;
		if(nOut < (nSizeX*2 + 1)) break;

		*pOut = 4;
		big_to_bytes(nSizeX, x
			, pOut + 1
			, TRUE);
		big_to_bytes(nSizeX, y
			, pOut + 1 + nSizeX
			, TRUE);
	}
	break;
	case enum_compress:
	{
		if(!x) break;
		if (nOut < (nSizeX + 1)) break;

		*pOut = (0 == nLsbY) ? 2 : 3;
		big_to_bytes(nSizeX, x
			, pOut + 1
			, TRUE);
	}
	break;
	case enum_mix:
	{
		if (!x || !y) break;
		if (nOut < (nSizeX * 2 + 1)) break;

		*pOut = (0 == nLsbY) ? 6 : 7;
		big_to_bytes(nSizeX, x
			, pOut + 1
			, TRUE);
		big_to_bytes(nSizeX, y
			, pOut + 1 + nSizeX
			, TRUE);
	}
	break;
	default:
	break;
	}
}

void DecompressPoint(EnumCompress compress
	, const uint8_t* pIn
	, uint32_t nIn
	, uint32_t nSizeX
	, big *x
	, big *y
	, int *pnLsbY)
{
	if(!pIn) return;

	switch (*pIn)
	{
	// compress
	case 2:
	case 3:
	{
		if(!pnLsbY) break;
		if(!x) break;

		*pnLsbY = (2 == *pIn) ? 0 : 1;
		if (!(*x)) 
		{
			*x = mirvar(0);
		}
		bytes_to_big(nSizeX, pIn+1, *x);
	}
	break;
	// no compress
	case 4:
	{
		if (!x || !y) break;
		if (!(*x))
		{
			*x = mirvar(0);
		}
		if (!(*y))
		{
			*y = mirvar(0);
		}
		bytes_to_big(nSizeX, pIn + 1, *x);
		bytes_to_big(nSizeX, pIn + 1 + nSizeX, *y);
	}
	break;
	// mix
	case 6:
	case 7:
	{
		*pnLsbY = (6 == *pIn) ? 0 : 1;
		if (!(*x))
		{
			*x = mirvar(0);
		}
		if (!(*y))
		{
			*y = mirvar(0);
		}
		bytes_to_big(nSizeX, pIn + 1, *x);
		bytes_to_big(nSizeX, pIn + 1 + nSizeX, *y);
	}
	break;
	}
}