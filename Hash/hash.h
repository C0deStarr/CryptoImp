#ifndef _HASH_H
#define _HASH_H

#include <common/common.h>

#include "sha/sha1.h"
#include "sha/sha256.h"
#include "sha/sha512.h"
#include "gm/sm3.h"

#define MAX_SIZE_OF_DIGEST	SHA512_DIGEST_SIZE
#define NUMBER_OF_HASHES	2
typedef enum {
	enum_sha1 = 0,
	enum_sm3 = 1
}enum_hash;

uint32_t GetDigestSize(enum_hash enumHash);

typedef
ErrCrypto(*PFnHash)
(const uint8_t* pData
	, uint64_t nData
	, uint8_t* pDigest
	, uint32_t nDigest);
PFnHash GetDigestFunc(enum_hash enumHash);


//...

#endif // !_HASH_H
