#ifndef QTNG_CRYPTO_P_H
#define QTNG_CRYPTO_P_H

extern "C" {
#include <openssl/evp.h>
#include <openssl/x509.h>
}
#include "../md.h"
#include "../cipher.h"
#include "../pkey.h"
#include "../certificate.h"

QTNETWORKNG_NAMESPACE_BEGIN

void initOpenSSL();
const EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo);
const EVP_CIPHER *getOpenSSL_CIPHER(Cipher::Algorithm algo, Cipher::Mode mode);
bool openssl_setPkey(PublicKey *key, EVP_PKEY *pkey, bool hasPrivate);
bool openssl_setCertificate(Certificate *cert, X509 *x509);


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_CRYPTO_P_H
