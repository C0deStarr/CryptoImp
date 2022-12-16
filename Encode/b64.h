#ifndef B64_H
#define B64_H
class b64
{
public:
	static int b64_encode(char* pChIn, int nLen, char* pChOut);
	static int b64_decode(char* pChIn, int nLen, char* pChOut);
	static void test();
private:
	static const char m_arr_b64_enc_tbl[65];
	//  max([ord(i) for i in m_arr_b64_enc_tbl]) == 122 == 'z'
	static const char m_arr_b64_dec_tbl[123];
};
#endif
