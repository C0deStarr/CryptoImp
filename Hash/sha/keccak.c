
#include "./keccak.h"

ErrCrypto keccak_init(KeccakState* pKeccakState)
{
	ErrCrypto err = ERR_OK;

	return err;
}
ErrCrypto keccak_update(KeccakState* pKeccakState, const uint8_t* pBuf, uint64_t nLen)
{
	ErrCrypto err = ERR_OK;

	return err;
}
ErrCrypto keccak_digest(KeccakState* pKeccakState, uint8_t* pDigest, int nDigest)
{
	ErrCrypto err = ERR_OK;

	return err;
}

void test_keccak()
{
	KeccakState keccakState = {0};

	uint8_t data[] = "abc";
	uint8_t digest[MAX_MD_SIZE] = {0};
	uint8_t nDigest = 224;
	uint8_t i = 0;
	keccak_init(&keccakState);
	keccak_update(&keccakState, data, sizeof(data) - 1);
	keccak_digest(&keccakState, digest, nDigest);
	for (i = 0; i < nDigest; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}