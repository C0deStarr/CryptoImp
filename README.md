My Cryptography algorithm implements.

# Algorithms

## Hash

* MD5  [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321.html)
* SHA1 [FIPS-180 ](https://csrc.nist.gov/publications/detail/fips/180/4/final)
* SHA2 [FIPS-180 ](https://csrc.nist.gov/publications/detail/fips/180/4/final)
  * SHA-224
  * SHA-256,  with [HMAC rfc2104]((https://www.rfc-editor.org/rfc/rfc2104))
  * SHA-384
  * SHA-512
  * SHA-512/224
  * SHA-512/256
* SHA3 [FIPS-202](https://csrc.nist.gov/publications/detail/fips/202/final)
  * SHA3_224
  * SHA3_256
  * SHA3_384
  * SHA3_512
  * SHAKE128
  * SHAKE256
* [SM3](http://www.sca.gov.cn/sca/xwdt/2010-12/17/content_1002389.shtml)



## Symmetric cipher

**Block cipher**:

* DES [FIPS 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25)
* DES3
* AES
  * with [modes]((https://csrc.nist.gov/publications/detail/sp/800-38a/final)): CBC
* SM4



**Stream cipher**:

* chacha20 [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
* zuc 
* AES with [modes]((https://csrc.nist.gov/publications/detail/sp/800-38a/final)): CFB, OFB, CTR





## Asymmetric cipher

[RFC 8017: PKCS #1: RSA](https://www.rfc-editor.org/rfc/rfc8017):

* pkcs1 oaep 
* pkcs1 pss

Elliptic Curve Cryptography:

* Encryption & Decryption
* ECDSA, [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final)
* Elliptic Curves
  * Curves in Short-Weierstrass Form
    * P-192/224/256/384/521， W-25519/448
    * [SM2]((http://www.sca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml))

