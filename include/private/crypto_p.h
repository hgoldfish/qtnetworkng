#ifndef QTNG_CRYPTO_P_H
#define QTNG_CRYPTO_P_H

#include "./openssl_symbols.h"
#include "../md.h"
#include "../cipher.h"
#include "../pkey.h"
#include "../certificate.h"

QTNETWORKNG_NAMESPACE_BEGIN

void initOpenSSL();
const openssl::EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo);
const openssl::EVP_CIPHER *getOpenSSL_CIPHER(Cipher::Algorithm algo, Cipher::Mode mode);
openssl::EVP_MD_CTX *EVP_MD_CTX_new();
void EVP_MD_CTX_free(openssl::EVP_MD_CTX *context);
bool openssl_setPkey(PublicKey *key, openssl::EVP_PKEY *pkey, bool hasPrivate);
bool openssl_setCertificate(Certificate *cert, openssl::X509 *x509);


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_CRYPTO_P_H
