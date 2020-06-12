#include "../include/random.h"

#ifdef QTNG_NO_CRYPTO
#include <QtCore/qdatetime.h>
#else
#include "../include/private/crypto_p.h"
#include <openssl/rand.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN


#ifdef QTNG_NO_CRYPTO

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

#else

QByteArray randomBytes(int numBytes)
{
    initOpenSSL();
    QByteArray b;
    b.resize(numBytes);
    RAND_bytes(reinterpret_cast<unsigned char*>(b.data()), numBytes);
    return b;
}

#endif


QTNETWORKNG_NAMESPACE_END
