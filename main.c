#include <stdio.h>
#include "common/util.h"

//#include <common/b64.h>
//#include "Hash/md/mddriver.h"
//#include "Hash/sha/sha1.h"
//#include "./Hash/sha/sha256.h"
//#include "./Hash/sha/sha224.h"
//#include "./Hash/sha/sha512.h"
//#include "./Hash/sha/sha384.h"
//#include "./Hash/sha/sha512_224.h"
//#include "./Hash/sha/sha512_256.h"
//#include "./Hash/sha/sha3.h"
//#include "./Hash/gm/sm3.h"

//#include "./Cipher/BlockCipher/des.h"
//#include "./Cipher/BlockCipher/des3.h"
//#include "./Cipher/BlockCipher/aes.h"
//#include "./Cipher/BlockCipher/sm4.h"

//
//	pubkey
//
//#include "./pubkey/rsa/rsa.h"
//#include "./pubkey/rsa/pkcs1_oaep.h"
//#include "./pubkey/rsa/pkcs1_pss.h"
//#include "./pubkey/ecc/ecc.h"
#include "./pubkey/ecc/ecdsa.h"

int main()
{
	//test_base64();
	//test_sha256();
	//test_sha224();
	//test_sha512();
	//sha512_t_iv_generator();
	//test_sha384();
	//test_sha512_224();
	//test_sha3();
	//test_sm3();
	//test_sha256_hmac();


	//test_des();
	//test_des3();
	//test_aes_modes();
	//test_sm4();

	//test_mgf();
	//test_rsa();
	//test_rsa_oaep();
	//test_pss();

	//test_ecc_demo();
	//test_ecdsa();
	test_ecc();

	getchar();
	return 0;
}


