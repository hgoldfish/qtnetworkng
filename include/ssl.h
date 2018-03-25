#ifndef QTNG_SSL_H
#define QTNG_SSL_H

#include "socket.h"
#include "certificate.h"

QTNETWORKNG_NAMESPACE_BEGIN

class SslCipherPrivate;
class SslCipher
{
public:
    SslCipher();
    explicit SslCipher(const QString &name);
    SslCipher(const QString &name, Ssl::SslProtocol protocol);
    SslCipher(const SslCipher &other);
    ~SslCipher();
public:
    QString authenticationMethod() const;
    QString encryptionMethod() const;
    bool isNull() const;
    QString keyExchangeMethod() const;
    QString name() const;
    Ssl::SslProtocol protocol() const;
    QString protocolString() const;
    int supportedBits() const;
    int usedBits() const;
public:
    inline bool operator!=(const SslCipher &other) const { return !operator==(other); }
    SslCipher &operator=(SslCipher &&other) { swap(other); return *this; }
    SslCipher &operator=(const SslCipher &other);
    void swap(SslCipher &other) { qSwap(d, other.d); }
    bool operator==(const SslCipher &other) const;
private:
    friend class SslCipherPrivate;
    QScopedPointer<SslCipherPrivate> d;
};


class SslConfigurationPrivate;
class SslConfiguration
{
public:
    SslConfiguration();
    SslConfiguration(const SslConfiguration &other);
    SslConfiguration(SslConfiguration &&other);
    ~SslConfiguration();
public:
    QList<QByteArray> allowedNextProtocols() const;
    QList<Certificate> caCertificates() const;
    QList<SslCipher> ciphers() const;
    bool isNull() const;
    Certificate localCertificate() const;
    Ssl::PeerVerifyMode peerVerifyMode() const;
    QString peerVerifyName() const;
    int peerVerifyDepth() const;
    PrivateKey privateKey() const;

    void addCaCertificate(const Certificate &certificate);
    void addCaCertificates(const QList<Certificate> &certificates);
    void setLocalCertificate(const Certificate &certificate);
    bool setLocalCertificate(const QString &path, Ssl::EncodingFormat format = Ssl::Pem);
    void setPeerVerifyDepth(int depth);
    void setPeerVerifyMode(Ssl::PeerVerifyMode mode);
    void setPeerVerifyName(const QString &hostName);
    void setPrivateKey(const PrivateKey &key);
    void setPrivateKey(const QString &fileName, PrivateKey::Algorithm algorithm = PrivateKey::Rsa,
                       Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &passPhrase = QByteArray());
    void setSslProtocol(Ssl::SslProtocol protocol);
    void setAllowedNextProtocols(const QList<QByteArray> &protocols);
public:
    static QList<SslCipher> supportedCiphers();
public:
    inline bool operator!=(const SslConfiguration &other) const { return !operator==(other); }
    SslConfiguration &operator=(SslConfiguration &&other) { swap(other); return *this; }
    SslConfiguration &operator=(const SslConfiguration &other);
    void swap(SslConfiguration &other) { qSwap(d, other.d); }
    bool operator==(const SslConfiguration &other) const;
private:
    QSharedDataPointer<SslConfigurationPrivate> d;
    friend class SslConfigurationPrivate;
};

class SslErrorPrivate;
class SslError
{
public:
    enum Error {
        NoError,
        UnableToGetIssuerCertificate,
        UnableToDecryptCertificateSignature,
        UnableToDecodeIssuerPublicKey,
        CertificateSignatureFailed,
        CertificateNotYetValid,
        CertificateExpired,
        InvalidNotBeforeField,
        InvalidNotAfterField,
        SelfSignedCertificate,
        SelfSignedCertificateInChain,
        UnableToGetLocalIssuerCertificate,
        UnableToVerifyFirstCertificate,
        CertificateRevoked,
        InvalidCaCertificate,
        PathLengthExceeded,
        InvalidPurpose,
        CertificateUntrusted,
        CertificateRejected,
        SubjectIssuerMismatch, // hostname mismatch?
        AuthorityIssuerSerialNumberMismatch,
        NoPeerCertificate,
        HostNameMismatch,
        NoSslSupport,
        CertificateBlacklisted,
        UnspecifiedError = -1
    };

    SslError();
    SslError(Error error);
    SslError(Error error, const Certificate &certificate);
    SslError(const SslError &other);
    ~SslError();
public:
    Error error() const;
    QString errorString() const;
    Certificate certificate() const;
public:
    void swap(SslError &other) { qSwap(d, other.d); }
    SslError &operator=(SslError &&other) { swap(other); return *this; }
    SslError &operator=(const SslError &other);
    bool operator==(const SslError &other) const;
    inline bool operator!=(const SslError &other) const { return !(*this == other); }
private:
    QScopedPointer<SslErrorPrivate> d;
};
uint qHash(const SslError &key, uint seed = 0);
QDebug &operator<<(QDebug &debug, const SslError &error);
QDebug &operator<<(QDebug &debug, const SslError::Error &error);


class Socket;
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
    SslSocket(Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol, const SslConfiguration &config = SslConfiguration());
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());
    virtual ~SslSocket();
public:
    bool handshake(bool asServer, const QString &verificationPeerName = QString());
    Certificate localCertificate() const;
    QList<Certificate> localCertificateChain() const;
    QByteArray nextNegotiatedProtocol() const;
    NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const;
    SslMode mode() const;
    Certificate peerCertificate() const;
    QList<Certificate> peerCertificateChain() const;
    int peerVerifyDepth() const;
    Ssl::PeerVerifyMode peerVerifyMode() const;
    QString peerVerifyName() const;
    PrivateKey privateKey() const;
    SslCipher cipher() const;
    Ssl::SslProtocol sslProtocol() const;
    SslConfiguration sslConfiguration() const;
    QList<SslError> sslErrors() const;
    void setSslConfiguration(const SslConfiguration &configuration);
public:
    Socket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    virtual qintptr	fileno() const;
    Socket::SocketType type() const;
    Socket::SocketState state() const;
    Socket::NetworkLayerProtocol protocol() const;

    QSharedPointer<SslSocket> accept();
    Socket *acceptRaw();
    bool bind(QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

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

Q_DECLARE_METATYPE(QList<QTNETWORKNG_NAMESPACE::SslError>)

#endif //QTNG_SSL_H
