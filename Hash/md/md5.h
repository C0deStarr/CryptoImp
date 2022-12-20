/* MD5.H - header file for MD5C.C
 */
 /* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 rights reserved.
 License to copy and use this software is granted provided that it
 is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 Algorithm" in all material mentioning or referencing this software
 or this function.
 License is also granted to make and use derivative works provided
 that such works are identified as "derived from the RSA Data
 Security, Inc. MD5 Message-Digest Algorithm" in all material
 mentioning or referencing the derived work.
 RSA Data Security, Inc. makes no representations concerning either
 the merchantability of this software or the suitability of this
 software for any particular purpose. It is provided "as is"
 without express or implied warranty of any kind.
 These notices must be retained in any copies of any part of this
documentation and/or software.
 */

 #ifndef _MD5_H
 #define _MD5_H
 #include "../../common/common.h"
 /* MD5 context. */
typedef struct {
	uint32_t state[4]; /* state (ABCD) */
	//UINT4 count[2]; /* number of bits, modulo 2^64 (lsb first) */
	uint64_t nBits;	/* Maximum message length for MD5 is 2**64 bits */
	unsigned char buffer[64]; /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX* context /* context */);
void MD5Update(
	MD5_CTX* context, /* context */
	unsigned char* input, /* input block */
	unsigned int inputLen /* length of input block */
);
void MD5Final(
	unsigned char digest[16], /* message digest */
	MD5_CTX* context /* context */
);

#endif