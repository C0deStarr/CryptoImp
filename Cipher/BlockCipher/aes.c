#include "aes.h"
#include "gf_mul.h"

#include <common/endianess.h>
#include <common/util.h>
#include <string.h>


#define RotWord(x) ROTL32(x,8)

ErrCrypto KeyExpansion(StcAES* pStcAES, uint8_t key[/*4*Nk*/]);

ErrCrypto AddRoundKey(StcAES* pStcAES, uint8_t* pState, uint32_t nRound);
ErrCrypto AddRoundKeyDecrypt(StcAES* pStcAES, uint8_t* pState, uint32_t nRound);

ErrCrypto SubBytes(uint8_t* pState);
ErrCrypto InvSubBytes(uint8_t* pState);

ErrCrypto ShiftRows(uint8_t* pState);
ErrCrypto InvShiftRows(uint8_t* pState);

ErrCrypto MixColumns(uint8_t* pState);
ErrCrypto InvMixColumns(uint8_t* pState);

static const uint8_t sbox[16][16] = {
	{0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
	{0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
	{0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
	{0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
	{0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
	{0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
	{0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
	{0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
	{0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
	{0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
	{0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
	{0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
	{0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
	{0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
	{0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
	{0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}
};

static const uint8_t inv_sbox[16][16] = {
	{0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
	{0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
	{0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
	{0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
	{0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
	{0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
	{0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
	{0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
	{0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
	{0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
	{0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
	{0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
	{0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
	{0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
	{0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
	{0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D}
};

uint32_t SubWord(uint32_t a)
{
	uint32_t nRet = 0;
	nRet += sbox[(a >> 4) & 0xF][a & 0xF];
	nRet += sbox[(a >> 12) & 0xF][(a >> 8) & 0xF] << 8;
	nRet += sbox[(a >> 20) & 0xF][(a >> 16) & 0xF] << 16;
	nRet += sbox[(a >> 28) & 0xF][(a >> 24) & 0xF] << 24;

	return  nRet;
}

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
	pStcAES->nKeyBitsSize = nAesKeySize;
	//pStcAES->Nb = AES_Nb;

	errRet = KeyExpansion(pStcAES, pKey);

	return errRet;
}

ErrCrypto KeyExpansion(StcAES* pStcAES, uint8_t key[/*4*Nk*/])
{
	ErrCrypto errRet = ERR_OK;

	uint32_t i = 0;
	uint32_t temp = 0;
	uint32_t nW = 0;

	// for dw
	uint8_t state[4][AES_Nb] = { 0 };
	uint32_t nOffsetDW = 0;
	uint32_t j = 0;


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

	memset(pStcAES->w, 0, sizeof(pStcAES->w));
	memset(pStcAES->dw, 0, sizeof(pStcAES->dw));

	for (i = 0; i < pStcAES->Nk; ++i)
	{
		pStcAES->w[i] = u8to32_big(&key[4*i]);
	}

	nW = AES_Nb * (pStcAES->Nr + 1);
	while (i < nW)
	{
		temp = pStcAES->w[i - 1];
		if (0 == (i % pStcAES->Nk))
		{
			temp = SubWord(RotWord(temp)) 
				^ Rcon[(i-1) / pStcAES->Nk];
		}
		else if ((pStcAES->Nk)> 6 && ((i % pStcAES->Nk) == 4))
		{

			temp = SubWord(temp);
		}
		pStcAES->w[i] = pStcAES->w[i - pStcAES->Nk] ^ temp;

		++i;
	}


	for (i = 0; i < nW; ++i)
	{
		pStcAES->dw[i] = pStcAES->w[i];
	}

	i = nW - AES_Nb;
	for (nOffsetDW = AES_Nb; nOffsetDW < i; nOffsetDW += AES_Nb)
	{
		for (j = 0; j < 4; ++j)
		{
			state[0][j] = (pStcAES->dw[nOffsetDW + j] >> 24) & 0xFF;
			state[1][j] = (pStcAES->dw[nOffsetDW + j] >> 16) & 0xFF;
			state[2][j] = (pStcAES->dw[nOffsetDW + j] >> 8) & 0xFF;
			state[3][j] = (pStcAES->dw[nOffsetDW + j]) & 0xFF;
		}
		
		InvMixColumns(state);

		for (j = 0; j < 4; ++j)
		{
			pStcAES->dw[nOffsetDW + j] =
				(state[0][j] << 24)
				^ (state[1][j] << 16)
				^ (state[2][j] << 8)
				^ (state[3][j]);
		}
	}
	return errRet;
}


ErrCrypto AddRoundKey(StcAES* pStcAES, uint8_t* pState, uint32_t nRound)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t i = 0;
	uint32_t nOffsetKey = nRound * AES_Nb;
	if (!pStcAES || !pState)
	{
		return ERR_NULL;
	}
	
	if ( nRound  > pStcAES->Nr)
	{
		return ERR_NR_ROUNDS;
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pState[i] ^= (pStcAES->w[nOffsetKey + i % AES_Nb]
			>> (24 - (i / AES_Nb ) * 8))
			& 0xFF;
	}

	return errRet;
}

ErrCrypto AddRoundKeyDecrypt(StcAES* pStcAES, uint8_t* pState, uint32_t nRound)
{
	ErrCrypto errRet = ERR_OK;
	uint32_t i = 0;
	uint32_t nOffsetKey = nRound * AES_Nb;
	if (!pStcAES || !pState)
	{
		return ERR_NULL;
	}

	if (nRound > pStcAES->Nr)
	{
		return ERR_NR_ROUNDS;
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pState[i] ^= (pStcAES->dw[nOffsetKey + i % AES_Nb]
			>> (24 - (i / AES_Nb) * 8))
			& 0xFF;
	}

	return errRet;
}


ErrCrypto SubBytes(uint8_t* pState)
{
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}
	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pState[i] = sbox[pState[i] >> 4][pState[i] & 0x0F];
	}

	return ERR_OK;
}

ErrCrypto InvSubBytes(uint8_t* pState)
{
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}
	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pState[i] = inv_sbox[pState[i] >> 4][pState[i] & 0x0F];
	}

	return ERR_OK;
}


ErrCrypto ShiftRows(uint8_t* pState)
{
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}

	for (i = 1; i < 4; ++i)
	{
		// bytes shift left
		// == little endian dword shift right
		*(uint32_t*)&(pState[i * AES_Nb]) = ROTR32(*(uint32_t*)&(pState[i * AES_Nb]), i * 8);
	}


	return ERR_OK;
}

ErrCrypto InvShiftRows(uint8_t* pState)
{
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}

	for (i = 1; i < 4; ++i)
	{
		// bytes shift left
		// == little endian dword shift right
		*(uint32_t*)&(pState[i * AES_Nb]) = ROTL32(*(uint32_t*)&(pState[i * AES_Nb]), i * 8);
	}


	return ERR_OK;
}

uint8_t xtime(uint16_t a, uint8_t b)
{
	static const uint16_t mx = 0x011B;
	uint16_t nRet = 0;
	int i = 0;
	for (i = 0; i < 8; ++i)
	{
		if (b & 0x01)
		{
			nRet ^= a;
		}
		b >>= 1;
		a <<= 1;
		if (a & 0x0100)
		{
			a ^= mx;
		}
	}
	return nRet & 0xFF;
}

ErrCrypto MixColumns(uint8_t* pState)
{
	uint8_t byCols[4] = { 0 };
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}

	// 4 cols of state
	for (i = 0; i < 4; ++i)
	{
		byCols[0] = pState[i];
		byCols[1] = pState[AES_Nb + i];
		byCols[2] = pState[2 * AES_Nb + i];
		byCols[3] = pState[3 * AES_Nb + i];

		pState[i] =
			/*xtime(0x02, byCols[0])
			^ xtime(0x03, byCols[1])*/
			 gf_mul[0x02][byCols[0]]
			 ^ gf_mul[0x03][byCols[1]]
			^ byCols[2]
			^ byCols[3];
		pState[AES_Nb + i] = byCols[0]
			 /*^ xtime(0x02, byCols[1])
			 ^ xtime(0x03, byCols[2])*/
			^ gf_mul[0x02][byCols[1]]
			^ gf_mul[0x03][byCols[2]]
			^ byCols[3];
		pState[2 * AES_Nb + i] = byCols[0]
			^ byCols[1]
			//^ xtime(0x02, byCols[2])
			^ gf_mul[0x02][byCols[2]]
			//^ xtime(0x03, byCols[3]);
			^ gf_mul[0x03][byCols[3]];
		pState[3 * AES_Nb + i] =
			//xtime(0x03, byCols[0])
			gf_mul[0x03][byCols[0]]
			^ byCols[1]
			^ byCols[2]
			//^ xtime(0x02, byCols[3]);
			^ gf_mul[0x02][byCols[3]];
		
	}
	
	return ERR_OK;
}

ErrCrypto InvMixColumns(uint8_t* pState)
{
	uint8_t byCols[4] = { 0 };
	uint32_t i = 0;
	if (!pState)
	{
		return ERR_NULL;
	}

	// 4 cols of state
	for (i = 0; i < 4; ++i)
	{
		byCols[0] = pState[i];
		byCols[1] = pState[AES_Nb + i];
		byCols[2] = pState[2 * AES_Nb + i];
		byCols[3] = pState[3 * AES_Nb + i];

		pState[i] =
			gf_mul[0x0e][byCols[0]]
			^ gf_mul[0x0b][byCols[1]]
			^ gf_mul[0x0d][byCols[2]]
			^ gf_mul[0x09][byCols[3]];
		pState[AES_Nb + i] = 
			gf_mul[0x09][byCols[0]]
			^ gf_mul[0x0e][byCols[1]]
			^ gf_mul[0x0b][byCols[2]]
			^ gf_mul[0x0d][byCols[3]];
		pState[2 * AES_Nb + i] = 
			gf_mul[0x0d][byCols[0]]
			^ gf_mul[0x09][byCols[1]]
			^ gf_mul[0x0e][byCols[2]]
			^ gf_mul[0x0b][byCols[3]];
		pState[3 * AES_Nb + i] =
			gf_mul[0x0b][byCols[0]]
			^ gf_mul[0x0d][byCols[1]]
			^ gf_mul[0x09][byCols[2]]
			^ gf_mul[0x0e][byCols[3]];

	}

	return ERR_OK;
}

ErrCrypto aes_encrypt(StcAES* pStcAES
	, uint8_t* pIn
	, uint32_t nIn/* = AES_BLOCK_SIZE*/
	, uint8_t *pOut
	, uint32_t nOut/* = AES_BLOCK_SIZE*/)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t state[4][AES_Nb] = {0};
	uint32_t i = 0;
	if (!pStcAES || !pIn || !pOut)
	{
		return ERR_NULL;
	}
	if ((AES_BLOCK_SIZE != nIn)
		|| (AES_BLOCK_SIZE != nOut))
	{
		return ERR_BLOCK_SIZE;
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		state[i % 4][i / 4] = pIn[i];
	}

	AddRoundKey(pStcAES, state, 0);
	for (i = 1; i < pStcAES->Nr; ++i)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(pStcAES, state, i);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(pStcAES, state, i);

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pOut[i] = state[i % 4][i / 4];
	}
	return errRet;
}

ErrCrypto aes_decrypt(StcAES* pStcAES
	, uint8_t* in
	, uint32_t nIn/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = AES_BLOCK_SIZE*/)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t state[4][AES_Nb] = { 0 };
	uint32_t i = 0;
	if (!pStcAES || !in || !pOut)
	{
		return ERR_NULL;
	}
	if ((AES_BLOCK_SIZE != nIn)
		|| (AES_BLOCK_SIZE != nOut))
	{
		return ERR_BLOCK_SIZE;
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		state[i % 4][i / 4] = in[i];
	}

	AddRoundKey(pStcAES, state, pStcAES->Nr);
	for (i = pStcAES->Nr - 1; i >= 1; --i)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(pStcAES, state, i);
		InvMixColumns(state);
	}
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(pStcAES, state, 0);


	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pOut[i] = state[i % 4][i / 4];
	}
	return errRet;
}

ErrCrypto aes_decrypt_ex(StcAES* pStcAES
	, uint8_t* in
	, uint32_t nIn/* = AES_BLOCK_SIZE*/
	, uint8_t* pOut
	, uint32_t nOut/* = AES_BLOCK_SIZE*/)
{
	ErrCrypto errRet = ERR_OK;
	uint8_t state[4][AES_Nb] = { 0 };
	uint32_t i = 0;
	if (!pStcAES || !in || !pOut)
	{
		return ERR_NULL;
	}
	if ((AES_BLOCK_SIZE != nIn)
		|| (AES_BLOCK_SIZE != nOut))
	{
		return ERR_BLOCK_SIZE;
	}

	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		state[i % 4][i / 4] = in[i];
	}

	AddRoundKeyDecrypt(pStcAES, state, pStcAES->Nr);
	for (i = pStcAES->Nr - 1; i >= 1; --i)
	{
		InvSubBytes(state);
		InvShiftRows(state);
		InvMixColumns(state);
		AddRoundKeyDecrypt(pStcAES, state, i);
	}
	InvSubBytes(state);
	InvShiftRows(state);
	AddRoundKeyDecrypt(pStcAES, state, 0);


	for (i = 0; i < AES_BLOCK_SIZE; ++i)
	{
		pOut[i] = state[i % 4][i / 4];
	}
	return errRet;
}


void test_aes()
{
	StcAES stcAES = {0};
	uint32_t i = 0;
	uint8_t key[] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	uint8_t data[] = {
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
	};
	uint8_t true_cipher[] = {
		0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
	};
	uint8_t cipher[0x10] = { 0 };
	uint8_t plain[0x10] = {0};
	uint32_t nKey = sizeof(key);
	aes_init(&stcAES, aes128, key, nKey);
	aes_encrypt(&stcAES, data, sizeof(data), cipher, 0x10);

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%02x", cipher[i]);
	}
	printf("\n");
	if (!memcmp(true_cipher, cipher, 0x10))
	{
		printf("ok\n");
	}

	aes_decrypt(&stcAES, cipher, sizeof(cipher), plain, 0x10);

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%02x", plain[i]);
	}
	printf("\n");
	if (!memcmp(plain, data, 0x10))
	{
		printf("ok\n");
	}

	memset(plain, 0, 0x10);
	aes_decrypt_ex(&stcAES, cipher, sizeof(cipher), plain, 0x10);

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%02x", plain[i]);
	}
	printf("\n");
	if (!memcmp(plain, data, 0x10))
	{
		printf("ok\n");
	}
}