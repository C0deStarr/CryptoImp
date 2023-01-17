
#ifndef _DES_H
#define _DES_H


#include <common/common.h>


#define NUMBER_OF_ROUNDS    16
#define KEY_SIZE    8
#define BLOCK_SIZE    8

typedef enum {
	ENC = 0,
	DEC = 1
}DES_OPERATION;

typedef struct {
	// big endian
    uint64_t subkeys[NUMBER_OF_ROUNDS];
}des_key;


ErrCrypto des_init(des_key *pStcKey, const uint8_t *pKey, uint32_t nKey);

ErrCrypto des(des_key *pStcKey
	, const uint8_t *pData
	, uint32_t nData
	, uint8_t * pOut
	, uint32_t nOutBuf
	, DES_OPERATION op);



//ErrCrypto des_finalize();

void test_des();


#endif