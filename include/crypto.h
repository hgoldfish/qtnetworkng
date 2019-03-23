#ifndef QTNG_CRYPTO_H
#define QTNG_CRYPTO_H

#include "config.h"

QTNETWORKNG_NAMESPACE_BEGIN

namespace Ssl {

enum EncodingFormat {
    Pem = 0,
    Der = 1,
};

enum SslProtocol
{
    UnknownProtocol = -1,
    SslV3 = 0,
    SslV2 = 1,
    TlsV1_0 = 2,
    TlsV1_0OrLater,
    TlsV1 = TlsV1_0,
    TlsV1_1,
    TlsV1_1OrLater,
    TlsV1_2,
    TlsV1_3,
    TlsV1_2OrLater,
    AnyProtocol,
    TlsV1SslV3,
    SecureProtocols,
};

enum SslOption
{
    SslOptionDisableEmptyFragments = 0x01,
    SslOptionDisableSessionTickets = 0x02,
    SslOptionDisableCompression = 0x04,
    SslOptionDisableServerNameIndication = 0x08,
    SslOptionDisableLegacyRenegotiation = 0x10,
    SslOptionDisableSessionSharing = 0x20,
    SslOptionDisableSessionPersistence = 0x40,
    SslOptionDisableServerCipherPreference = 0x80,
};
Q_DECLARE_FLAGS(SslOptions, SslOption);

enum PeerVerifyMode
{
    VerifyNone = 0,
    QueryPeer = 1,
    VerifyPeer = 2,
    AutoVerifyPeer = 3,
};
}

void initOpenSSL();
void cleanupOpenSSL();

QTNETWORKNG_NAMESPACE_END

#endif //QTNG_CRYPTO_H
