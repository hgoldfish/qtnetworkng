#ifndef QTNG_SSL_H
#define QTNG_SSL_H

#include "socket.h"
#include "certificate.h"

QTNETWORKNG_NAMESPACE_BEGIN


class SslConfigurationPrivate;
class SslConfiguration
{
public:
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
    Q_DECLARE_FLAGS(SslOptions, SslOption)

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
        TlsV1_2OrLater,
        AnyProtocol,
        TlsV1SslV3,
        SecureProtocols,
    };

    enum PeerVerifyMode
    {
        VerifyNone = 0,
        QueryPeer = 1,
        VerifyPeer = 2,
        AutoVerifyPeer = 3,
    };
public:
    SslConfiguration();
    ~SslConfiguration();
public:
    QList<QByteArray> allowedNextProtocols() const;
    QList<Certificate> caCertificates() const;
    QList<Cipher> ciphers() const;
    bool isNull() const;
    Certificate localCertificate() const;
    QList<Certificate> localCertificateChain() const;
    void addCaCertificate(const Certificate &certificate);
    void addCaCertificates(const QList<Certificate> &certificates);
    PeerVerifyMode peerVerifyMode() const;
    void setLocalCertificate(const Certificate &certificate);
    void setLocalCertificate(const QString &path, PrivateKey::EncodingFormat format = PrivateKey::Pem);
    void setLocalCertificateChain(const QList<Certificate> &localChain);
    void setPeerVerifyDepth(int depth);
    void setPeerVerifyMode(PeerVerifyMode mode);
    void setPeerVerifyName(const QString &hostName);
    void setPrivateKey(const PrivateKey &key);
    void setPrivateKey(const QString &fileName, PrivateKey::Algorithm algorithm = PrivateKey::Rsa,
                       PrivateKey::EncodingFormat format = PrivateKey::Pem, const QByteArray &passPhrase = QByteArray());
    void setProtocol(SslProtocol protocol);
private:
    SslConfigurationPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(SslConfiguration)
};

class SslErrorPrivate;
class SslError
{

};


class QSocket;
class SslSocketPrivate;
class SslSocket
{
public:
    enum SslMode
    {
        UnencryptedMode = 0,
        SslClientMode = 1,
        SslServerMode = 2,
    };

    enum NextProtocolNegotiationStatus
    {
        NextProtocolNegotiationNone = 0,
        NextProtocolNegotiationNegotiated = 1,
        NextProtocolNegotiationUnsupported = 2,
    };

public:
    SslSocket(QSocket::NetworkLayerProtocol protocol = QSocket::AnyIPProtocol);
    SslSocket(qintptr socketDescriptor);
    SslSocket(QSharedPointer<QSocket> rawSocket);
    virtual ~SslSocket();
public:
    Certificate localCertificate() const;
    QList<Certificate> localCertificateChain() const;
    QByteArray nextNegotiatedProtocol() const;
    NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const;
    SslMode mode() const;
    Certificate peerCertificate() const;
    QList<Certificate> peerCertificateChain() const;
    int peerVerifyDepth() const;
    SslConfiguration::PeerVerifyMode peerVerifyMode() const;
    QString peerVerifyName() const;
    PrivateKey privateKey() const;
    SslConfiguration::SslProtocol sslProtocol() const;
    Cipher sessionCipher() const;
    SslConfiguration::SslProtocol sessionProtocol() const;
    SslConfiguration sslConfiguration() const;
    QList<SslError> sslErrors() const;
    void setSslConfiguration(const SslConfiguration &configuration);
public:
    QSocket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    virtual qintptr	fileno() const;
    QSocket::SocketType type() const;
    QSocket::SocketState state() const;
    QSocket::NetworkLayerProtocol protocol() const;

    QSharedPointer<SslSocket> accept();
    QSocket *acceptRaw();
    bool bind(QHostAddress &address, quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform);
    bool bind(quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform);
    bool connect(const QHostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol = QSocket::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(QSocket::SocketOption option, const QVariant &value);
    QVariant option(QSocket::SocketOption option) const;

    qint64 recv(char *data, qint64 size);
    qint64 recvall(char *data, qint64 size);
    qint64 send(const char *data, qint64 size);
    qint64 sendall(const char *data, qint64 size);
    QByteArray recv(qint64 size);
    QByteArray recvall(qint64 size);
    qint64 send(const QByteArray &data);
    qint64 sendall(const QByteArray &data);
private:
    SslSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(SslSocket)
    Q_DISABLE_COPY(SslSocket)
};


QTNETWORKNG_NAMESPACE_END


#endif //QTNG_SSL_H
