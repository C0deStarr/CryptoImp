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

