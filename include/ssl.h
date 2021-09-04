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


class ChooseTlsExtNameCallback
{
public:
    virtual QString choose(const QString &hostName) = 0;
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
    int peerVerifyDepth() const;
    PrivateKey privateKey() const;
    bool onlySecureProtocol() const;
    bool supportCompression() const;
    bool sendTlsExtHostName() const;
    QSharedPointer<ChooseTlsExtNameCallback> tlsExtHostNameCallback() const;

    void addCaCertificate(const Certificate &certificate);
    void addCaCertificates(const QList<Certificate> &certificates);
    void setLocalCertificate(const Certificate &certificate);
    bool setLocalCertificate(const QString &path, Ssl::EncodingFormat format = Ssl::Pem);
    void setPeerVerifyDepth(int depth);
    void setPeerVerifyMode(Ssl::PeerVerifyMode mode);
    void setPrivateKey(const PrivateKey &key);
    bool setPrivateKey(const QString &fileName, Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &passPhrase = QByteArray());
    void setSslProtocol(Ssl::SslProtocol protocol);
    void setAllowedNextProtocols(const QList<QByteArray> &protocols);
    void setOnlySecureProtocol(bool onlySecureProtocol);
    void setSupportCompression(bool supportCompression);
    void setSendTlsExtHostName(bool sendTlsExtHostName);
    void setTlsExtHostNameCallback(QSharedPointer<ChooseTlsExtNameCallback> callback);
public:
    static QList<SslCipher> supportedCiphers();
    static SslConfiguration testPurpose(const QString &commonName, const QString &countryCode, const QString &organization);
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
class SocketLike;
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
    SslSocket(HostAddress::NetworkLayerProtocol protocol=HostAddress::IPv4Protocol, const SslConfiguration &config = SslConfiguration());
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());
    SslSocket(QSharedPointer<SocketLike> rawSocket, const SslConfiguration &config = SslConfiguration());
    virtual ~SslSocket();
public:
    bool handshake(bool asServer, const QString &hostName);
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
    void setPeerVerifyName(const QString &peerVerifyName);
    void setTlsExtHostName(const QString &tlsExtHostName);
public:
    Socket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    HostAddress localAddress() const;
    quint16 localPort() const;
    HostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    virtual qintptr	fileno() const;
    Socket::SocketType type() const;
    Socket::SocketState state() const;
    HostAddress::NetworkLayerProtocol protocol() const;

    SslSocket *accept();
    Socket *acceptRaw();
    bool bind(const HostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const HostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port,
                 QSharedPointer<SocketDnsCache> dnsCache=QSharedPointer<SocketDnsCache>());
    void close();
    void abort();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    QByteArray recv(qint32 size);
    QByteArray recvall(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);

    static SslSocket *createConnection(const HostAddress &host, quint16 port,
                    const SslConfiguration &config = SslConfiguration(),
                    Socket::SocketError *error = nullptr,
                    int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol);
    static SslSocket *createConnection(const QString &hostName, quint16 port,
                    const SslConfiguration &config = SslConfiguration(),
                    Socket::SocketError *error = nullptr,
                    QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                    int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol);
    static SslSocket *createServer(const HostAddress &host, quint16 port,
                                                  const SslConfiguration &config = SslConfiguration(),
                                                  int backlog = 50);
private:
    SslSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(SslSocket)
    Q_DISABLE_COPY(SslSocket)
};


QSharedPointer<SocketLike> asSocketLike(QSharedPointer<SslSocket> s);


inline QSharedPointer<SocketLike> asSocketLike(SslSocket *s) { return asSocketLike(QSharedPointer<SslSocket>(s)); }


QSharedPointer<SslSocket> convertSocketLikeToSslSocket(QSharedPointer<SocketLike> socket);


// XXX we always assume the cipher is stream cipher
QSharedPointer<SocketLike> encrypted(QSharedPointer<Cipher> cipher, QSharedPointer<SocketLike> socket);


QTNETWORKNG_NAMESPACE_END

Q_DECLARE_METATYPE(QList<QTNETWORKNG_NAMESPACE::SslError>)

#endif //QTNG_SSL_H
