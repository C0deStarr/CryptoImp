#include <stdio.h>
#include "Encode/b64.h"
#include "Hash/md/mddriver.h"
//#include "Hash/sha/sha1.h"
//#include "./Hash/sha/sha256.h"
//#include "./Hash/sha/sha224.h"
#include "./Hash/sha/sha512.h"

int main()
{
	test_base64();
	//test_sha256();
	//test_sha224();
	//test_sha512();
	getchar();
	return 0;
}


