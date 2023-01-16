#include "aes.h"
#include <common/endianess.h>

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

	errRet = KeyExpansion(pStcAES, pKey);

	return errRet;
}

ErrCrypto KeyExpansion(StcAES* pStcAES, uint8_t key[/*4*Nk*/])
{
	ErrCrypto errRet = ERR_OK;

	uint32_t i = 0;
	uint32_t temp = 0;
	uint32_t nW = 0;
	/* py generator
	a = 0x01
	mx = 0x011b
	listRcon = []
	for i in range(15):
		# print("0x57 * %s == %s" %(hex(i+1), hex(a)) )
		if(a & 0x0100):
			a = a ^ mx
			# print("^ mx->%s" % hex(a))
		listRcon.append(a << 24)
		a = a << 1;

	for i in listRcon:
		print("0x%08x" % i, end=",")
	*/
	static const Rcon[15] = {
		0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
		0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000,
		0x6c000000,0xd8000000,0xab000000,0x4d000000,0x9a000000
	};


	if (!pStcAES || !key)
	{
		return ERR_NULL;
	}

	for (i = 0; i < pStcAES->Nk; ++i)
	{
		pStcAES->w[i] = u8to32_big(&key[4*i]);
	}

	nW = pStcAES->Nb * (pStcAES->Nr + 1);
	while (i < nW)
	{
		temp = pStcAES->w[i - 1];
		if (0 == (i % pStcAES->Nk))
		{
			temp = SubWord(RotWord(temp)) ^ Rcon[i / pStcAES->Nk];
		}
		else if ((pStcAES->Nk)> 6 && ((i % pStcAES->Nk) == 4))
		{

			temp = SubWord(temp);
		}
		pStcAES->w[i] = pStcAES->w[i - pStcAES->Nk] ^ temp;

		++i;
	}

	return errRet;
}

