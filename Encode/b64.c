#include <stdio.h>
#include "b64.h"

const char s_arr_b64_enc_tbl[65] = { 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};
/*
m_arr_b64_enc_tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
m_arr_b64_dec_tbl = [-1] * 123
for i in range(64) :
	m_arr_b64_dec_tbl[ord(m_arr_b64_enc_tbl[i])] = i
print(m_arr_b64_dec_tbl)
*/
const char s_arr_b64_dec_tbl[123] = {
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

/*
* ret: 
*	-1 : error
*	>=0: out len
*/
int b64_encode(char* pChIn, int nInLen, char* pChOut, int nOutLen)
{
	int nOffset = 0;
	int i, mod;
	int nRet = -1;
	int n24bits = 0;
	if (!pChIn || !pChOut)
	{
		return nRet;
	}
	if (nInLen == 0) {
		nInLen = strlen(pChIn);
	}

	// check out memory size
	if ((nInLen / 3 + 1) * 4 > nOutLen)
	{
		printf("No sufficient out memory space\n");
		return nRet;
	}
	mod = nInLen % 3;
	n24bits = nInLen - mod;
	//3 bytes --> 4 bytes
	for (i = 0; i < n24bits; i += 3)
	{
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(pChIn[i] >> 2) //i [7,2]
				& 0x3F
		];
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(( (pChIn[i] & 0x3) << 4)	// i [1,0]  
				| ((pChIn[i + 1] >> 4) & 0x0F))  // i+1 [7,4]
				& 0x3F
		];
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(((pChIn[i + 1] & 0xF) << 2) // i+1 [3,0] 
				| ((pChIn[i + 2] >> 6) & 0x03))  // i+2 [7,6]
				& 0x3F
		];
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			pChIn[i + 2] 
				& 0x3F
		];//i+2 [5,0]
	}

	if (mod == 1) {
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(pChIn[i] >> 2) & 0x3F
		];//i [7,2]
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(pChIn[i] & 0x3) << 4
		];//i [1,0]
		pChOut[nOffset++] = '=';
		pChOut[nOffset++] = '=';
	}
	else if (mod == 2) {
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(pChIn[i] >> 2) & 0x3F
		];//i [7,2]
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(((pChIn[i] & 0x3) << 4)	// i [1,0]  
				| ((pChIn[i + 1] >> 4) & 0x0F))  // i+1 [7,4]
				& 0x3F
		];
		pChOut[nOffset++] = s_arr_b64_enc_tbl[
			(pChIn[i + 1] & 0xF) << 2
		];
		pChOut[nOffset++] = '=';
	}
	pChOut[nOffset] = '\0';
	nRet = nOffset;
	return nRet;
}

/*
* ret: 
*	-1 : error
*	>=0: out len
*/
int b64_decode(char* pChIn, int nInLen, char* pChOut, int nOutLen)
{
	
	int nOffset = 0;
	int i, mod;
	int nRet = -1;
	int n24bits = 0;
	if (!pChIn || !pChOut)
	{
		return nRet;
	}

	if (nInLen == 0) {
		nInLen = strlen(pChIn);
	}
	// check valid Base64 length and char 
	if (nInLen == 0 || nInLen % 4 != 0) {
		printf("Invalid base64 length\n");
		return nRet;
	}
	for (i = 0; i < nInLen; i += 4)
	{
		if (('=' != pChIn[i])
			&& (-1 == s_arr_b64_dec_tbl[pChIn[i]]))
		{
				printf("Invalid base64 char\n");
				return nRet;
		}
	}

	// check out memory size
	if (((nInLen / 4) * 3) > nOutLen)
	{
		printf("No sufficient out memory space\n");
		return nRet;
	}
	//4 bytes --> 3 bytes
	n24bits = nInLen - 4;
	for (i = 0; i < n24bits; i += 4)
	{
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i]] << 2) // i [5,0]
			| ((s_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) & 0x3)   // i+1 [4,5]
			& 0xFF;
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i + 1]] << 4)  // i+1 [3,0]
			| ((s_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) & 0xF)	// i+2 [5,2]
			& 0xFF;
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i + 2]] << 6)	// i+2 [0,1]
			| ((s_arr_b64_dec_tbl[pChIn[i + 3]]) & 0x3F) //  i+3 [5,0]
			& 0xFF;

	}
	// the last 4 bytes
	if (pChIn[i + 2] == '=') {
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i]] << 2)
			| (s_arr_b64_dec_tbl[pChIn[i + 1]] >> 4)
			& 0xFF;
	}
	else if (pChIn[i + 3] == '=') {
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i]] << 2) 
			| (s_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) 
			& 0xFF;
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i + 1]] << 4) 
			| (s_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) 
			& 0xFF;
	}
	else {
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i]] << 2) // i [5,0]
			| ((s_arr_b64_dec_tbl[pChIn[i + 1]] >> 4) & 0x3)   // i+1 [4,5]
			& 0xFF;
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i + 1]] << 4)  // i+1 [3,0]
			| ((s_arr_b64_dec_tbl[pChIn[i + 2]] >> 2) & 0xF)	// i+2 [5,2]
			& 0xFF;
		pChOut[nOffset++] = (s_arr_b64_dec_tbl[pChIn[i + 2]] << 6)	// i+2 [0,1]
			| ((s_arr_b64_dec_tbl[pChIn[i + 3]]) & 0x3F) //  i+3 [5,0]
			& 0xFF;
	}

	nRet = nOffset;

	return nRet;
}

void test_base64()
{
	char pChMsg[] = "ÄãºÃa";
	char pChB64[1024] = { 0 };
	char pChDec[1024] = { 0 };
	int nMsgLen = sizeof(pChMsg) - 1;
	int nB64Len = 0;

	printf("%s\n", pChMsg);
	if (-1 != b64_encode(pChMsg, nMsgLen, pChB64, sizeof(pChB64)))
	{
		printf("%s\n", pChB64);
	}
	nB64Len = strlen(pChB64);
	if (-1 != b64_decode(pChB64, nB64Len, pChDec, sizeof(pChDec)))
	{
		printf("%s\n", pChDec);
	}
}

