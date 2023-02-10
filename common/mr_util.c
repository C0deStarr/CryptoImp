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
