
#include "./keccak.h"


ErrCrypto keccak_init(KeccakState* pKeccakState, uint32_t c)
{
	ErrCrypto err = ERR_OK;
	if(!pKeccakState)
		return ERR_NULL;

	if(c >= KECCAK_b_200BYTES)
		return ERR_DIGEST_SIZE;
	pKeccakState->nByCapacity = c;
	pKeccakState->nByRate = KECCAK_b_200BYTES - c;

	pKeccakState->nr = NUMBER_OF_ROUNDS;
	return err;
}

//static ErrCrypto keccak_p(uint64_t* pArrState, uint32_t nr)
static ErrCrypto keccak_f(uint64_t* pArrState, uint32_t nr/*==24 == 12+2*l*/)	
{
	ErrCrypto err = ERR_OK;
	uint32_t ir = 0;	// ir = 12+2*l-nr
	if(!pArrState)
		return ERR_NULL;
	if(nr >= NUMBER_OF_ROUNDS)
		return ERR_NR_ROUNDS;
	

	for (ir = NUMBER_OF_ROUNDS - nr/*=0*/; ir < nr; ++ir)
	{

	}

	return err;
}


ErrCrypto keccak_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pBuf)
		return ERR_NULL;
	return err;
}
ErrCrypto keccak_digest(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	ErrCrypto err = ERR_OK;
	if (!pKeccakState || !pDigest)
		return ERR_NULL;
	return err;
}

void test_keccak()
{
	KeccakState keccakState = {0};

	uint8_t data[] = "abc";
	uint8_t digest[MAX_MD_SIZE] = {0};
	uint8_t nDigest = 28;
	uint8_t i = 0;
	keccak_init(&keccakState);
	keccak_update(&keccakState, data, sizeof(data) - 1);
	keccak_digest(&keccakState, digest, nDigest);
	for (i = 0; i < nDigest; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}