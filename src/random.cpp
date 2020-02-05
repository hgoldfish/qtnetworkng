#include <openssl/rand.h>
#include "../include/random.h"

#ifndef QTNG_NO_CRYPTO
#include "../include/private/crypto_p.h"
#else
#include <QtCore/qdatetime.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN


#ifndef QTNG_NO_CRYPTO

QByteArray randomBytes(int numBytes)
{
    initOpenSSL();
    QByteArray b;
    b.resize(numBytes);
    RAND_bytes(reinterpret_cast<unsigned char*>(b.data()), numBytes);
    return b;
}

#else

QByteArray randomBytes(int numBytes)
{
    QByteArray b;
    b.reserve(numBytes);
    qsrand(static_cast<uint>(QDateTime::currentMSecsSinceEpoch()));
    for (int i = 0; i < numBytes; ++i) {
        b.append(static_cast<char>(0xff & qrand()));
    }
    return b;
}

#endif


QTNETWORKNG_NAMESPACE_END
