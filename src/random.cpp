#include "../include/random.h"
#include "../include/openssl_symbols.h"
#include "../include/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

QByteArray randomBytes(int i)
{
    initOpenSSL();
    QByteArray b;
    b.resize(i);
    openssl::q_RAND_bytes((unsigned char*) b.data(), i);
    return b;
}

QTNETWORKNG_NAMESPACE_END
