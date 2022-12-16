#ifndef B64_H
#define B64_H
class b64
{
public:
	static int b64_encode(char* pChIn, int nLen, char* pChOut);

private:
    static const char _b64_enc_tbl[];
};
#endif
