#include <iostream>
#include "b64.h"

const char b64::m_arr_b64_enc_tbl[65] = { 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};
/*
m_arr_b64_enc_tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
m_arr_b64_dec_tbl = [-1] * 123
for i in range(64) :
	m_arr_b64_dec_tbl[ord(m_arr_b64_enc_tbl[i])] = i
print(m_arr_b64_dec_tbl)
*/
const char b64::m_arr_b64_dec_tbl[123] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
	54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
	-1, -1, -1, -1, -1,  0,  1,  2,  3,  4,
	 5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
	39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51
};


int b64::b64_encode(char* pChIn, int nLen, char* pChOut)
{
	int nOffset = 0;
	int i, mod;
	int nOutLen = -1;
	int n24bits = 0;
	if (!pChIn || !pChOut)
	{
		return nOutLen;
	}
	if (nLen == 0) {
		nLen = strlen(pChIn);
	}
	mod = nLen % 3;
	n24bits = nLen - mod;
	//3 bytes --> 4 bytes
	for (i = 0; i < n24bits; i += 3)
	{
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(pChIn[i] >> 2) //i [7,2]
				& 0x3F
		];
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(( (pChIn[i] & 0x3) << 4)	// i [1,0]  
				| ((pChIn[i + 1] >> 4) & 0x0F))  // i+1 [7,4]
				& 0x3F
		];
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(((pChIn[i + 1] & 0xF) << 2) // i+1 [3,0] 
				| ((pChIn[i + 2] >> 6) & 0x03))  // i+2 [7,6]
				& 0x3F
		];
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			pChIn[i + 2] 
				& 0x3F
		];//i+2 [5,0]
	}

	if (mod == 1) {
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(pChIn[i] >> 2) & 0x3F
		];//i [7,2]
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(pChIn[i] & 0x3) << 4
		];//i [1,0]
		pChOut[nOffset++] = '=';
		pChOut[nOffset++] = '=';
	}
	else if (mod == 2) {
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(pChIn[i] >> 2) & 0x3F
		];//i [7,2]
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(((pChIn[i] & 0x3) << 4)	// i [1,0]  
				| ((pChIn[i + 1] >> 4) & 0x0F))  // i+1 [7,4]
				& 0x3F
		];
		pChOut[nOffset++] = m_arr_b64_enc_tbl[
			(pChIn[i + 1] & 0xF) << 2
		];
		pChOut[nOffset++] = '=';
	}
	pChOut[nOffset] = '\0';
	nOutLen = nOffset;
	return nOutLen;
}

//int b64::b64_decode(char* pChIn, int nLen, char* pChOut);
int b64::b64_decode(char* pChIn, int nLen, char* pChOut)
{
	

	int nOffset = 0;
	int i, mod;
	int nOutLen = -1;
	int n24bits = 0;
	if (!pChIn || !pChOut)
	{
		return nOutLen;
	}

	if (nLen == 0) {
		nLen = strlen(pChIn);
	}

	// check valid Base64 length and char 
	if (nLen == 0 || nLen % 4 != 0) {
		printf("Invalid base64 length\n");
		return nOutLen;
	}
	for (i = 0; i < nLen; i += 4)
	{
		if (('=' != pChIn[i])
			&& (-1 == m_arr_b64_dec_tbl[pChIn[i]]))
		{
				printf("Invalid base64 char\n");
				return nOutLen;
		}
	}

	//4 bytes --> 3 bytes
	n24bits = nLen - 4;
	for (i = 0; i < n24bits; i += 4)
	{
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i]] << 2) // i [5,0]
			| ((m_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) & 0x3)   // i+1 [4,5]
			& 0xFF;
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i + 1]] << 4)  // i+1 [3,0]
			| ((m_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) & 0xF)	// i+2 [5,2]
			& 0xFF;
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i + 2]] << 6)	// i+2 [0,1]
			| ((m_arr_b64_dec_tbl[pChIn[i + 3]]) & 0x3F) //  i+3 [5,0]
			& 0xFF;

	}
	// the last 4 bytes
	if (pChIn[i + 2] == '=') {
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i]] << 2)
			| (m_arr_b64_dec_tbl[pChIn[i + 1]] >> 4)
			& 0xFF;
	}
	else if (pChIn[i + 3] == '=') {
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i]] << 2) 
			| (m_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) 
			& 0xFF;
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i + 1]] << 4) 
			| (m_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) 
			& 0xFF;
	}
	else {
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i]] << 2) // i [5,0]
			| ((m_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) & 0x3)   // i+1 [4,5]
			& 0xFF;
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i + 1]] << 4)  // i+1 [3,0]
			| ((m_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) & 0xF)	// i+2 [5,2]
			& 0xFF;
		pChOut[nOffset++] = (m_arr_b64_dec_tbl[pChIn[i + 2]] << 6)	// i+2 [0,1]
			| ((m_arr_b64_dec_tbl[pChIn[i + 3]]) & 0x3F) //  i+3 [5,0]
			& 0xFF;
	}

	nOutLen= nOffset;

	return 0;
}

void b64::test()
{
	char pChMsg[] = "ÄãºÃa";
	char pChB64[1024] = { 0 };
	char pChDec[1024] = { 0 };
	int nMsgLen = sizeof(pChMsg);
	int nB64Len = 0;

	printf("%s\n", pChMsg);
	if (-1 != b64::b64_encode(pChMsg, nMsgLen, pChB64))
	{
		printf("%s\n", pChB64);
	}
	nB64Len = strlen(pChB64);
	if (-1 != b64::b64_decode(pChB64, nB64Len, pChDec))
	{
		printf("%s\n", pChDec);
	}
}

