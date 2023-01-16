#include "aes.h"


ErrCrypto aes_init(StcAES* pStcAES, aes_key_size nAesKeySize, uint8_t* pKey, uint32_t nKey)
{
	ErrCrypto errRet = ERR_OK;
	if (!pStcAES || !pKey)
	{
		return ERR_NULL;
	}

	if (nKey != (nAesKeySize / 8))
	{
		return ERR_KEY_SIZE;
	}

	switch (nAesKeySize)
	{
		case aes128:
		{
			pStcAES->Nk = 4;
			pStcAES->Nr = 10;
		}
		break;
		case aes192:
		{
			pStcAES->Nk = 6;
			pStcAES->Nr = 12;
		}
		break;
		case aes256:
		{
			pStcAES->Nk = 8;
			pStcAES->Nr = 14;
		}
		break;
		default:
			return ERR_KEY_SIZE;
	}
	pStcAES->nKeySize = nAesKeySize;
	pStcAES->Nb = AES_Nb;

	errRet = KeyExpansion(pKey, pStcAES->w, pStcAES->Nk);

	return errRet;
}

ErrCrypto KeyExpansion(uint8_t key[/*4*Nk*/], uint32_t w[/*Nb*(Nr+1)*/], uint32_t Nk)
{

}

