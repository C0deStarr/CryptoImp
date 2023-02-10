#ifndef _MR_UTIL_H
#define _MR_UTIL_H

#include <miracl.h>


miracl* InitMiracl(int nd, mr_small nb);
void UninitMiracl();

void print_point(epoint* p);

#endif // !_MR_UTIL_H
