#include "../include/random.h"

#ifdef QTNG_NO_CRYPTO
#  if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#    include <QtCore/qrandom.h>
#  else
#    include <QtCore/qdatetime.h>
#  endif
#else
#  include "../include/private/crypto_p.h"
#  include <openssl/rand.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN

#ifdef QTNG_NO_CRYPTO

#  if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)

QByteArray randomBytes(int numBytes)
{
    QByteArray b;
    b.reserve(numBytes);
    QRandomGenerator *generator = QRandomGenerator::global();
    for (int i = 0; i < numBytes; ++i) {
        b.append(static_cast<char>(generator->bounded(0xff)));
    }
    return b;
}

#  else

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

#  endif

#else

QByteArray randomBytes(int numBytes)
{
    initOpenSSL();
    QByteArray b;
    b.resize(numBytes);
    RAND_bytes(reinterpret_cast<unsigned char *>(b.data()), numBytes);
    cleanupOpenSSL();
    return b;
}

#endif

QTNETWORKNG_NAMESPACE_END
