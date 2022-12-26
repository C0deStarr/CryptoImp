#ifndef B64_H
#define B64_H
static const char s_arr_b64_enc_tbl[65];
//  max([ord(i) for i in m_arr_b64_enc_tbl]) == 122 == 'z'
static const char s_arr_b64_dec_tbl[123];

int b64_encode(char* pChIn, int nInLen, char* pChOut, int nOutLen);
int b64_decode(char* pChIn, int nInLen, char* pChOut, int nOutLen);
void test_base64();


#endif
