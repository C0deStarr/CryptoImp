#include "hash.h"
#include <stdlib.h>



uint32_t GetDigestSize(enum_hash enumHash)
{
	if (enumHash >= NUMBER_OF_HASHES)
	{
		return NULL;
	}
	static uint32_t s_arrDigestSizeTable[NUMBER_OF_HASHES] = {
		SHA1_DIGEST_SIZE,
		SM3_DIGEST_SIZE
	};
	return s_arrDigestSizeTable[enumHash];
}

PFnHash GetDigestFunc(enum_hash enumHash)
{
	static uint32_t s_arrHashFuncs[NUMBER_OF_HASHES] = {
			SHA1_digest,
			SM3_digest
	};
	if (enumHash >= NUMBER_OF_HASHES)
	{
		return NULL;
	}
	return s_arrHashFuncs[enumHash];
}

