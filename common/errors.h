#ifndef _ERRORS_H
#define _ERRORS_H

typedef enum _Err_Crypto {
	ERR_OK					= 0 ,
	ERR_NULL                = 1	,
	ERR_MEMORY              = 2	,
	ERR_NOT_ENOUGH_DATA     = 3	,
	ERR_ENCRYPT             = 4	,
	ERR_DECRYPT             = 5	,
	ERR_KEY_SIZE            = 6	,
	ERR_NONCE_SIZE          = 7	,
	ERR_NR_ROUNDS           = 8	,
	ERR_DIGEST_SIZE         = 9	,
	ERR_MAX_DATA            = 10,
	ERR_MAX_OFFSET          = 11,
	ERR_BLOCK_SIZE          = 12,
	ERR_TAG_SIZE            = 13,
	ERR_VALUE               = 14,
	ERR_EC_POINT            = 15,
	ERR_EC_CURVE            = 16,
	ERR_MODULUS             = 17,
	ERR_PARAM				= 18,
	ERR_SIGNATURE_SIZE		= 19,
	ERR_SIGNATURE_VERIFY	= 20,
	ERR_UNKNOWN             = 32
}ErrCrypto;

#endif
