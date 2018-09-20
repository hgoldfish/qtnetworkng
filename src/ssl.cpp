#include <QtCore/qfile.h>
#include "../include/locks.h"
#include "../include/ssl.h"
#include "../include/socket.h"
#include "../include/socket_utils.h"
#include "../include/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN


class SslCipherPrivate
{
public:
    SslCipherPrivate()
        : isNull(true), supportedBits(0), bits(0),
          exportable(false), protocol(Ssl::UnknownProtocol)
    {
    }

    static SslCipher from_SSL_CIPHER(const openssl::SSL_CIPHER *cipher);

    bool isNull;
    QString name;
    int supportedBits;
    int bits;
    QString keyExchangeMethod;
    QString authenticationMethod;
    QString encryptionMethod;
    bool exportable;
    QString protocolString;
    Ssl::SslProtocol protocol;
};

SslCipher SslCipherPrivate::from_SSL_CIPHER(const openssl::SSL_CIPHER *cipher)
{
    SslCipher ciph;
    if(!cipher) {
        return ciph;
    }

    char buf [256];
    char *description = openssl::q_SSL_CIPHER_description(cipher, buf, sizeof(buf));
    if(!description) {
        return ciph;
    }
    QString descriptionOneLine = QString::fromLatin1(description);

    const QVector<QStringRef> &descriptionList = descriptionOneLine.splitRef(QLatin1Char(' '), QString::SkipEmptyParts);
    if (descriptionList.size() > 5) {
        // ### crude code.
        ciph.d->isNull = false;
        ciph.d->name = descriptionList.at(0).toString();

        QString protoString = descriptionList.at(1).toString();
        ciph.d->protocolString = protoString;
        ciph.d->protocol = Ssl::UnknownProtocol;
        if (protoString == QLatin1String("SSLv3")) {
            ciph.d->protocol = Ssl::SslV3;
        } else if (protoString == QLatin1String("SSLv2")) {
            ciph.d->protocol = Ssl::SslV2;
        } else if (protoString == QLatin1String("TLSv1")) {
            ciph.d->protocol = Ssl::TlsV1_0;
        } else if (protoString == QLatin1String("TLSv1.1")) {
            ciph.d->protocol = Ssl::TlsV1_1;
        } else if (protoString == QLatin1String("TLSv1.2")) {
            ciph.d->protocol = Ssl::TlsV1_2;
        } else {
            ciph.d->protocol = Ssl::UnknownProtocol;
        }
        if (descriptionList.at(2).startsWith(QLatin1String("Kx=")))
            ciph.d->keyExchangeMethod = descriptionList.at(2).mid(3).toString();
        if (descriptionList.at(3).startsWith(QLatin1String("Au=")))
            ciph.d->authenticationMethod = descriptionList.at(3).mid(3).toString();
        if (descriptionList.at(4).startsWith(QLatin1String("Enc=")))
            ciph.d->encryptionMethod = descriptionList.at(4).mid(4).toString();
        ciph.d->exportable = (descriptionList.size() > 6 && descriptionList.at(6) == QLatin1String("export"));

        ciph.d->bits = openssl::q_SSL_CIPHER_get_bits(cipher, &ciph.d->supportedBits);
    }
    return ciph;
}

SslCipher::SslCipher()
    : d(new SslCipherPrivate)
{
}

SslCipher::SslCipher(const QString &name)
    : d(new SslCipherPrivate)
{
    const QList<SslCipher> &ciphers = SslConfiguration::supportedCiphers();
    for (const SslCipher &cipher : ciphers) {
        if (cipher.name() == name) {
            *this = cipher;
            return;
        }
    }
}

SslCipher::SslCipher(const QString &name, Ssl::SslProtocol protocol)
    : d(new SslCipherPrivate)
{
    const QList<SslCipher> &ciphers = SslConfiguration::supportedCiphers();
    for (const SslCipher &cipher : ciphers) {
        if (cipher.name() == name && cipher.protocol() == protocol) {
            *this = cipher;
            return;
        }
    }
}

SslCipher::SslCipher(const SslCipher &other)
    : d(new SslCipherPrivate)
{
    *d.data() = *other.d.data();
}

SslCipher::~SslCipher()
{
}

SslCipher &SslCipher::operator=(const SslCipher &other)
{
    *d.data() = *other.d.data();
    return *this;
}

bool SslCipher::operator==(const SslCipher &other) const
{
    return d->name == other.d->name && d->protocol == other.d->protocol;
}

bool SslCipher::isNull() const
{
    return d->isNull;
}

QString SslCipher::name() const
{
    return d->name;
}

int SslCipher::supportedBits()const
{
    return d->supportedBits;
}

int SslCipher::usedBits() const
{
    return d->bits;
}

QString SslCipher::keyExchangeMethod() const
{
    return d->keyExchangeMethod;
}

QString SslCipher::authenticationMethod() const
{
    return d->authenticationMethod;
}

QString SslCipher::encryptionMethod() const
{
    return d->encryptionMethod;
}

QString SslCipher::protocolString() const
{
    return d->protocolString;
}

Ssl::SslProtocol SslCipher::protocol() const
{
    return d->protocol;
}

QDebug operator<<(QDebug debug, const SslCipher &cipher)
{
    QDebugStateSaver saver(debug); Q_UNUSED(saver);
    debug.resetFormat().nospace().noquote();
    debug << "SslCipher(name=" << cipher.name()
          << ", bits=" << cipher.usedBits()
          << ", proto=" << cipher.protocolString()
          << ')';
    return debug;
}

class SslConfigurationPrivate: public QSharedData
{
public:
    SslConfigurationPrivate();
    SslConfigurationPrivate(const SslConfigurationPrivate &) = default;
    bool isNull() const;
    bool operator==(const SslConfigurationPrivate &other) const;
    static QSharedPointer<openssl::SSL_CTX> makeContext(const SslConfiguration &config, bool asServer);

    QList<Certificate> caCertificates;
    Certificate localCertificate;
    PrivateKey privateKey;
    QList<QByteArray> allowedNextProtocols;
    Ssl::PeerVerifyMode peerVerifyMode;
    int peerVerifyDepth;
    QString peerVerifyName;
    QList<SslCipher> ciphers;
    bool onlySecureProtocol;
    bool supportCompression;
};

bool SslConfigurationPrivate::operator==(const SslConfigurationPrivate &other) const
{
    return caCertificates == other.caCertificates &&
            localCertificate == other.localCertificate &&
            privateKey == other.privateKey &&
            allowedNextProtocols == other.allowedNextProtocols &&
            peerVerifyMode == other.peerVerifyMode &&
            peerVerifyDepth == other.peerVerifyDepth &&
            peerVerifyName == other.peerVerifyName &&
            ciphers == other.ciphers &&
            onlySecureProtocol == other.onlySecureProtocol &&
            supportCompression == other.supportCompression;
}

bool SslConfigurationPrivate::isNull() const
{
    return caCertificates.isEmpty() &&
            localCertificate.isNull() &&
            !privateKey.isValid() &&
            allowedNextProtocols.isEmpty() &&
            peerVerifyMode == Ssl::AutoVerifyPeer &&
            peerVerifyDepth == 4 &&
            peerVerifyName.isEmpty() &&
            ciphers.isEmpty() &&
            onlySecureProtocol == true &&
            supportCompression == true;
}

SslConfigurationPrivate::SslConfigurationPrivate()
    :peerVerifyMode(Ssl::AutoVerifyPeer), peerVerifyDepth(4), onlySecureProtocol(true), supportCompression(true)
{

}


QSharedPointer<openssl::SSL_CTX> SslConfigurationPrivate::makeContext(const SslConfiguration &config, bool asServer)
{
    QSharedPointer<openssl::SSL_CTX> ctx;
    const openssl::SSL_METHOD *method = NULL;
    if(asServer) {
        method = openssl::q_SSLv23_server_method();
    } else {
        method = openssl::q_SSLv23_client_method();
    }
    if(!method) {
        return ctx;
    }
    ctx.reset(openssl::q_SSL_CTX_new(method), openssl::q_SSL_CTX_free);
    if(ctx.isNull()) {
        return ctx;
    }
    openssl::q_SSL_CTX_set_verify_depth(ctx.data(), config.peerVerifyDepth());
    long flags = openssl::SSL_OP_NO_SSLv2 | openssl::SSL_OP_NO_SSLv3 | openssl::SSL_OP_NO_TLSv1;
    if (config.onlySecureProtocol()) {
        flags |= openssl::SSL_OP_NO_TLSv1_1;
    }
    if (!config.supportCompression()) {
        flags |= openssl::SSL_OP_NO_COMPRESSION;
    }
    openssl::q_SSL_CTX_set_options(ctx.data(), flags);
    const PrivateKey &privateKey = config.privateKey();
    if(privateKey.isValid()) {
        int r = openssl::q_SSL_CTX_use_PrivateKey(ctx.data(), (openssl::EVP_PKEY *) privateKey.handle());
        if(!r) {
            qDebug() << "can not set ssl private key.";
        }
    }
    const Certificate localCertificate = config.localCertificate();
    if(localCertificate.isValid()) {
        int r = openssl::q_SSL_CTX_use_certificate(ctx.data(), (openssl::X509 *) localCertificate.handle());
        if(!r) {
            qDebug() << "can not set ssl certificate.";
        }
    }
    return ctx;
}


SslConfiguration::SslConfiguration()
    :d(new SslConfigurationPrivate())
{
}

SslConfiguration::SslConfiguration(const SslConfiguration &other)
    :d(other.d)
{
}

SslConfiguration::SslConfiguration(SslConfiguration &&other)
    :d(0)
{
    qSwap(d, other.d);
}

SslConfiguration::~SslConfiguration()
{
}

SslConfiguration &SslConfiguration::operator=(const SslConfiguration &other)
{
    if(this == &other) {
        return *this;
    }
    d = other.d;
    return *this;
}

bool SslConfiguration::operator==(const SslConfiguration &other) const
{
    if(d == other.d) {
        return true;
    }
    return d->operator ==(*other.d);
}

bool SslConfiguration::isNull() const
{
    return d->isNull();
}

QList<QByteArray> SslConfiguration::allowedNextProtocols() const
{
    return d->allowedNextProtocols;
}

QList<Certificate> SslConfiguration::caCertificates() const
{
    return d->caCertificates;
}

QList<SslCipher> SslConfiguration::ciphers() const
{
    return d->ciphers;
}
Certificate SslConfiguration::localCertificate() const
{
    return d->localCertificate;
}

Ssl::PeerVerifyMode SslConfiguration::peerVerifyMode() const
{
    return d->peerVerifyMode;
}

QString SslConfiguration::peerVerifyName() const
{
    return d->peerVerifyName;
}

int SslConfiguration::peerVerifyDepth() const
{
    return d->peerVerifyDepth;
}

PrivateKey SslConfiguration::privateKey() const
{
    return d->privateKey;
}

bool SslConfiguration::onlySecureProtocol() const
{
    return d->onlySecureProtocol;
}

bool SslConfiguration::supportCompression() const
{
    return d->supportCompression;
}

void SslConfiguration::addCaCertificate(const Certificate &certificate)
{
    d->caCertificates.append(certificate);
}

void SslConfiguration::addCaCertificates(const QList<Certificate> &certificates)
{
    d->caCertificates.append(certificates);
}

void SslConfiguration::setAllowedNextProtocols(const QList<QByteArray> &protocols)
{
    d->allowedNextProtocols = protocols;
}

void SslConfiguration::setPeerVerifyDepth(int depth)
{
    d->peerVerifyDepth = depth;
}

void SslConfiguration::setPeerVerifyMode(Ssl::PeerVerifyMode mode)
{
    d->peerVerifyMode = mode;
}

void SslConfiguration::setPeerVerifyName(const QString &hostName)
{
    d->peerVerifyName = hostName;
}

void SslConfiguration::setLocalCertificate(const Certificate &certificate)
{
    d->localCertificate = certificate;
}

bool SslConfiguration::setLocalCertificate(const QString &path, Ssl::EncodingFormat format)
{
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) {
        return false;
    }
    const QByteArray &data = f.readAll();
    const Certificate &cert = Certificate::load(data, format);
    if(cert.isNull() || cert.isBlacklisted()) {
        return false;
    }
    setLocalCertificate(cert);
    return true;
}

void SslConfiguration::setPrivateKey(const PrivateKey &key)
{
    d->privateKey = key;
}

void SslConfiguration::setOnlySecureProtocol(bool onlySecureProtocol)
{
    d->onlySecureProtocol = onlySecureProtocol;
}

void SslConfiguration::setSupportCompression(bool supportCompression)
{
    d->supportCompression = supportCompression;
}

QList<SslCipher> SslConfiguration::supportedCiphers()
{
    return QList<SslCipher>();
}


class SslErrorPrivate
{
public:
    SslError::Error error;
    Certificate certificate;
};

SslError::SslError()
    : d(new SslErrorPrivate)
{
    d->error = SslError::NoError;
    d->certificate = Certificate();
}

SslError::SslError(Error error)
    : d(new SslErrorPrivate)
{
    d->error = error;
    d->certificate = Certificate();
}

SslError::SslError(Error error, const Certificate &certificate)
    : d(new SslErrorPrivate)
{
    d->error = error;
    d->certificate = certificate;
}

SslError::SslError(const SslError &other)
    : d(new SslErrorPrivate)
{
    *d.data() = *other.d.data();
}

SslError::~SslError()
{
}

SslError &SslError::operator=(const SslError &other)
{
    *d.data() = *other.d.data();
    return *this;
}

bool SslError::operator==(const SslError &other) const
{
    return d->error == other.d->error
        && d->certificate == other.d->certificate;
}

SslError::Error SslError::error() const
{
    return d->error;
}

QString SslError::errorString() const
{
    QString errStr;
    switch (d->error) {
    case NoError:
        errStr = QStringLiteral("No error");
        break;
    case UnableToGetIssuerCertificate:
        errStr = QStringLiteral("The issuer certificate could not be found");
        break;
    case UnableToDecryptCertificateSignature:
        errStr = QStringLiteral("The certificate signature could not be decrypted");
        break;
    case UnableToDecodeIssuerPublicKey:
        errStr = QStringLiteral("The public key in the certificate could not be read");
        break;
    case CertificateSignatureFailed:
        errStr = QStringLiteral("The signature of the certificate is invalid");
        break;
    case CertificateNotYetValid:
        errStr = QStringLiteral("The certificate is not yet valid");
        break;
    case CertificateExpired:
        errStr = QStringLiteral("The certificate has expired");
        break;
    case InvalidNotBeforeField:
        errStr = QStringLiteral("The certificate's notBefore field contains an invalid time");
        break;
    case InvalidNotAfterField:
        errStr = QStringLiteral("The certificate's notAfter field contains an invalid time");
        break;
    case SelfSignedCertificate:
        errStr = QStringLiteral("The certificate is self-signed, and untrusted");
        break;
    case SelfSignedCertificateInChain:
        errStr = QStringLiteral("The root certificate of the certificate chain is self-signed, and untrusted");
        break;
    case UnableToGetLocalIssuerCertificate:
        errStr = QStringLiteral("The issuer certificate of a locally looked up certificate could not be found");
        break;
    case UnableToVerifyFirstCertificate:
        errStr = QStringLiteral("No certificates could be verified");
        break;
    case InvalidCaCertificate:
        errStr = QStringLiteral("One of the CA certificates is invalid");
        break;
    case PathLengthExceeded:
        errStr = QStringLiteral("The basicConstraints path length parameter has been exceeded");
        break;
    case InvalidPurpose:
        errStr = QStringLiteral("The supplied certificate is unsuitable for this purpose");
        break;
    case CertificateUntrusted:
        errStr = QStringLiteral("The root CA certificate is not trusted for this purpose");
        break;
    case CertificateRejected:
        errStr = QStringLiteral("The root CA certificate is marked to reject the specified purpose");
        break;
    case SubjectIssuerMismatch: // hostname mismatch
        errStr = QStringLiteral("The current candidate issuer certificate was rejected because its"
                                " subject name did not match the issuer name of the current certificate");
        break;
    case AuthorityIssuerSerialNumberMismatch:
        errStr = QStringLiteral("The current candidate issuer certificate was rejected because"
                             " its issuer name and serial number was present and did not match the"
                             " authority key identifier of the current certificate");
        break;
    case NoPeerCertificate:
        errStr = QStringLiteral("The peer did not present any certificate");
        break;
    case HostNameMismatch:
        errStr = QStringLiteral("The host name did not match any of the valid hosts"
                             " for this certificate");
        break;
    case NoSslSupport:
        errStr = QStringLiteral("SSL is not supported on this pltform.");
        break;
    case CertificateBlacklisted:
        errStr = QStringLiteral("The peer certificate is blacklisted");
        break;
    default:
        errStr = QStringLiteral("Unknown error");
        break;
    }

    return errStr;
}

Certificate SslError::certificate() const
{
    return d->certificate;
}

uint qHash(const SslError &key, uint seed)
{
    // 2x boost::hash_combine inlined:
    seed ^= qHash(key.error())       + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed ^= qHash(key.certificate()) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    return seed;
}

QDebug &operator<<(QDebug &debug, const SslError &error)
{
    debug << error.errorString();
    return debug;
}

QDebug &operator<<(QDebug &debug, const SslError::Error &error)
{
    debug << SslError(error).errorString();
    return debug;
}

static SslError _q_OpenSSL_to_SslError(int errorCode, const Certificate &cert)
{
    SslError error;
    switch (errorCode) {
    case X509_V_OK:
        // X509_V_OK is also reported if the peer had no certificate.
        break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        error = SslError(SslError::UnableToGetIssuerCertificate, cert); break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        error = SslError(SslError::UnableToDecryptCertificateSignature, cert); break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        error = SslError(SslError::UnableToDecodeIssuerPublicKey, cert); break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        error = SslError(SslError::CertificateSignatureFailed, cert); break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
        error = SslError(SslError::CertificateNotYetValid, cert); break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        error = SslError(SslError::CertificateExpired, cert); break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        error = SslError(SslError::InvalidNotBeforeField, cert); break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        error = SslError(SslError::InvalidNotAfterField, cert); break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        error = SslError(SslError::SelfSignedCertificate, cert); break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        error = SslError(SslError::SelfSignedCertificateInChain, cert); break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        error = SslError(SslError::UnableToGetLocalIssuerCertificate, cert); break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        error = SslError(SslError::UnableToVerifyFirstCertificate, cert); break;
    case X509_V_ERR_CERT_REVOKED:
        error = SslError(SslError::CertificateRevoked, cert); break;
    case X509_V_ERR_INVALID_CA:
        error = SslError(SslError::InvalidCaCertificate, cert); break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        error = SslError(SslError::PathLengthExceeded, cert); break;
    case X509_V_ERR_INVALID_PURPOSE:
        error = SslError(SslError::InvalidPurpose, cert); break;
    case X509_V_ERR_CERT_UNTRUSTED:
        error = SslError(SslError::CertificateUntrusted, cert); break;
    case X509_V_ERR_CERT_REJECTED:
        error = SslError(SslError::CertificateRejected, cert); break;
    default:
        error = SslError(SslError::UnspecifiedError, cert); break;
    }
    return error;
}

template<typename Socket>
class SslConnection
{
public:
    SslConnection(const SslConfiguration &config);
    SslConnection();
    ~SslConnection();
    bool handshake(bool asServer, const QString &verificationPeerName);
    bool _handshake();
    bool close();
    qint64 recv(char *data, qint64 size, bool all);
    qint64 send(const char *data, qint64 size, bool all);
    bool pumpOutgoing();
    bool pumpIncoming();
    Certificate localCertificate() const;
    QList<Certificate> localCertificateChain() const;
    Certificate peerCertificate() const;
    QList<Certificate> peerCertificateChain() const;
    Ssl::PeerVerifyMode peerVerifyMode() const;
    SslCipher cipher() const;
    SslSocket::SslMode mode() const;
    Ssl::SslProtocol sslProtocol() const;

    QSharedPointer<Socket> rawSocket;
    bool asServer;
    SslConfiguration config;
    QSharedPointer<openssl::SSL_CTX> ctx;
    QSharedPointer<openssl::SSL> ssl;
    QString verificationPeerName;
    QList<SslError> errors;
};


template<typename Socket>
SslConnection<Socket>::SslConnection(const SslConfiguration &config)
    :config(config)
{
    initOpenSSL();
}


template<typename Socket>
SslConnection<Socket>::SslConnection()
{
    initOpenSSL();
}

template<typename Socket>
SslConnection<Socket>::~SslConnection()
{
    close();
}

template<typename Socket>
bool SslConnection<Socket>::handshake(bool asServer, const QString &verificationPeerName)
{
    if (rawSocket.isNull()) {
        return false;
    }
    this->asServer = asServer;
    this->verificationPeerName = verificationPeerName;
    // TODO set verify name.

    openssl::BIO *incoming = openssl::q_BIO_new(openssl::q_BIO_s_mem());
    if(!incoming) {
        return false;
    }
    openssl::BIO *outgoing = openssl::q_BIO_new(openssl::q_BIO_s_mem());
    if(!outgoing) {
        return false;
    }

    ctx = SslConfigurationPrivate::makeContext(config, asServer);
    if(!ctx.isNull()) {
        ssl.reset(openssl::q_SSL_new(ctx.data()), openssl::q_SSL_free);
        if(!ssl.isNull()) {
            // do not free incoming & outgoing
            openssl::q_SSL_set_bio(ssl.data(), incoming, outgoing);
            return _handshake();
        } else {
            ctx.reset();
        }
    }

    openssl::q_BIO_free(incoming);
    openssl::q_BIO_free(outgoing);
    return false;
}


template<typename Socket>
bool SslConnection<Socket>::close()
{
    if (!ssl.isNull()) {
        while(true) {
            int result = openssl::q_SSL_shutdown(ssl.data());
            bool done = true;
            if (result < 0) {
                int err = openssl::q_SSL_get_error(ssl.data(), result);
                switch(err) {
                case SSL_ERROR_WANT_READ:
                    if (pumpOutgoing()) {
                        if (pumpIncoming()) {
                            done = false;
                        }
                    }
                    break;
                case SSL_ERROR_WANT_WRITE:
                    if (pumpOutgoing()) {
                        done = false;
                    }
                    break;
                case SSL_ERROR_NONE:
                case SSL_ERROR_ZERO_RETURN:
                    break;
                case SSL_ERROR_WANT_CONNECT:
                case SSL_ERROR_WANT_ACCEPT:
                case SSL_ERROR_WANT_X509_LOOKUP:
    //            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                    qDebug() << "what?";
                    break;
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    // qDebug() << "underlying socket is closed.";
                    break;
                default:
                    qDebug() << "unkown returned value of SSL_shutdown().";
                    break;
                }
            } else if (result > 0) {
                // success.
            } else { // result == 0
                done = false;
                // process the second SSL_shutdown();
                // https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html
            }
            if (done) {
                break;
            }
        }
        ssl.reset();
    }
    if (ctx.isNull()) {
        ctx.reset();
    }
    rawSocket->close();
    return true;
}

template<typename Socket>
bool SslConnection<Socket>::_handshake()
{
    while(true) {
        int result = asServer ? openssl::q_SSL_accept(ssl.data()) : openssl::q_SSL_connect(ssl.data());
        if(result <= 0) {
            switch(openssl::q_SSL_get_error(ssl.data(), result)) {
            case SSL_ERROR_WANT_READ:
                if(!pumpOutgoing()) return false;
                if(!pumpIncoming()) return false;
                break;
            case SSL_ERROR_WANT_WRITE:
                if(!pumpOutgoing()) return false;
                break;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
//            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            case SSL_ERROR_SYSCALL:
                qDebug() << "invalid ssl connection state.";
                return false;
            case SSL_ERROR_SSL:
            default:
                qDebug() << "handshake error.";
                return false;
            }
        } else {
            return true;
        }
    }
}


template<typename Socket>
bool SslConnection<Socket>::pumpOutgoing()
{
    if (ssl.isNull()) {
        return false;
    }
    int pendingBytes;
    QVarLengthArray<char, 4096> buf;
    openssl::BIO *outgoing = openssl::q_SSL_get_wbio(ssl.data());
    while(outgoing && rawSocket->isValid() && (pendingBytes = openssl::q_BIO_pending(outgoing)) > 0) {
        buf.resize(pendingBytes);
        int encryptedBytesRead = openssl::q_BIO_read(outgoing, buf.data(), pendingBytes);
        qint64 actualWritten = rawSocket->sendall(buf.constData(), encryptedBytesRead);
        if (actualWritten < 0) {
            qDebug() << "error sending data.";
            return false;
        }
    }
    return true;
}


template<typename Socket>
bool SslConnection<Socket>::pumpIncoming()
{
    if (ssl.isNull()) {
        return false;
    }
    QByteArray buf = rawSocket->recv(1024 * 8);
    if(buf.isEmpty())
        return false;
    int totalWritten = 0;
    openssl::BIO *incoming = openssl::q_SSL_get_rbio(ssl.data());
    while(incoming && totalWritten < buf.size()) {
        int writtenToBio = openssl::q_BIO_write(incoming, buf.constData() + totalWritten, buf.size() - totalWritten);
        if(writtenToBio > 0) {
            totalWritten += writtenToBio;
        } else {
            qDebug() << "Unable to decrypt data";
            return false;
        }
    };
    return true;
}


template<typename Socket>
qint64 SslConnection<Socket>::recv(char *data, qint64 size, bool all)
{
    if (ssl.isNull()) {
        return -1;
    }
    qint64 total = 0;
    while(true) {
        int result = openssl::q_SSL_read(ssl.data(), data + total, size - total);
        if(result < 0) {
            switch(openssl::q_SSL_get_error(ssl.data(), result)) {
            case SSL_ERROR_WANT_READ:
                if(!pumpOutgoing()) {
                    return total == 0 ? -1 : total;
                }
                if(!pumpIncoming()) {
                    return total == 0 ? -1 : total;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if(!pumpOutgoing()) {
                    return total == 0 ? -1 : total;
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
                return total == 0 ? -1 :total;
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
//            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                qDebug() << "recv error.";
                return total == 0 ? -1 : total;
            }
        } else if(result == 0) {
            return total;
        } else {
            total += result;
            if(all && total < size) {
                continue;
            } else {
                return total;
            }
        }
    }
}

template<typename Socket>
qint64 SslConnection<Socket>::send(const char *data, qint64 size, bool all)
{
    if (ssl.isNull()) {
        return -1;
    }
    qint64 total = 0;
    while(true) {
        int result = openssl::q_SSL_write(ssl.data(), data + total, size - total);
        if(result < 0) {
            switch(openssl::q_SSL_get_error(ssl.data(), result)) {
            case SSL_ERROR_WANT_READ:
                if(!pumpOutgoing()) {
                    return total == 0 ? -1 : total;
                }
                if(!pumpIncoming()) {
                    return total == 0 ? -1 : total;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                if(!pumpOutgoing()) {
                    return total == 0 ? -1 : total;
                }
                break;
            case SSL_ERROR_ZERO_RETURN:
                // may the remote peer close the connection.
                return total == 0 ? -1 : total;
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
//            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                qDebug() << "send error.";
                return -1;
            }
        } else {
            total += result;
            if(total > size) {
                qDebug() << "send too many data.";
                pumpOutgoing();
                return size;
            } else if(total == size) {
                pumpOutgoing();
                return total;
            } else {
                if(all) {
                    continue;
                } else {
                    return total;
                }
            }
        }
    }
}

template<typename Socket>
Certificate SslConnection<Socket>::localCertificate() const
{
    Certificate cert;
    if(!ssl.isNull()) {
        openssl::X509 *x = openssl::q_SSL_get_certificate(ssl.data());
        if(x) {
            openssl_setCertificate(&cert, x);
        }
    }
    return cert;
}

template<typename Socket>
Certificate SslConnection<Socket>::peerCertificate() const
{
    Certificate cert;
    if(!ssl.isNull()) {
        openssl::X509 *x = openssl::q_SSL_get_peer_certificate(ssl.data());
        if(x) {
            openssl_setCertificate(&cert, x);
        }
    }
    return cert;
}


QList<Certificate> STACKOFX509_to_Certificates(openssl::stack_st *x509)
{
    QList<Certificate> certificates;
    for (int i = 0; i < openssl::q_sk_num(x509); ++i) {
        if (openssl::X509 *entry = (openssl::X509*) openssl::q_sk_value(x509, i)) {
            Certificate cert;
            openssl_setCertificate(&cert, entry);
            certificates.append(cert);
        }
    }
    return certificates;
}

template<typename Socket>
QList<Certificate> SslConnection<Socket>::localCertificateChain() const
{
    QList<Certificate> certificates;
    if(ssl.isNull())
        return certificates;
    //FIXME store in sslconfig.
    return certificates;
}

template<typename Socket>
QList<Certificate> SslConnection<Socket>::peerCertificateChain() const
{
    QList<Certificate> certificates;
    if(ssl.isNull())
        return certificates;

    openssl::stack_st *x509 = openssl::q_SSL_get_peer_cert_chain(ssl.data());
    if(x509) {
        certificates = STACKOFX509_to_Certificates(x509);
    }
    return certificates;
}

template<typename Socket>
Ssl::PeerVerifyMode SslConnection<Socket>::peerVerifyMode() const
{
    if(ssl.isNull()) {
        return Ssl::AutoVerifyPeer;
    }
    int mode = openssl::q_SSL_get_verify_mode(ssl.data());
    if(mode == SSL_VERIFY_NONE) {
        return Ssl::VerifyNone;
    } else if(mode == SSL_VERIFY_PEER) {
        return Ssl::VerifyPeer;
    } else if(mode == SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
        return Ssl::QueryPeer;
    } else if(mode == SSL_VERIFY_CLIENT_ONCE) {
        return Ssl::AutoVerifyPeer;
    } else {
        return Ssl::AutoVerifyPeer;
    }
}

template<typename Socket>
SslCipher SslConnection<Socket>::cipher() const
{
    if(ssl.isNull()) {
        return SslCipher();
    }
    const openssl::SSL_CIPHER *sessionCipher = openssl::q_SSL_get_current_cipher(ssl.data());
    return SslCipherPrivate::from_SSL_CIPHER(sessionCipher);
}

template<typename Socket>
SslSocket::SslMode SslConnection<Socket>::mode() const
{
    if(asServer) {
        return SslSocket::SslServerMode;
    } else {
        return SslSocket::SslClientMode;
    }
}

template<typename Socket>
Ssl::SslProtocol SslConnection<Socket>::sslProtocol() const
{
    if(ssl.isNull())
        return Ssl::UnknownProtocol;
    int ver = openssl::q_SSL_version(ssl.data());
    switch (ver) {
    case 0x2:
        return Ssl::SslV2;
    case 0x300:
        return Ssl::SslV3;
    case 0x301:
        return Ssl::TlsV1_0;
    case 0x302:
        return Ssl::TlsV1_1;
    case 0x303:
        return Ssl::TlsV1_2;
    }
    return Ssl::UnknownProtocol;
}

class SslSocketPrivate: public SslConnection<Socket>
{
public:
    SslSocketPrivate(const SslConfiguration &config);
    bool isValid() const;

    Socket::SocketError error;
    QString errorString;
};


SslSocketPrivate::SslSocketPrivate(const SslConfiguration &config)
    :SslConnection<Socket>(config), error(Socket::NoError)
{

}

bool SslSocketPrivate::isValid() const
{
    if(error != Socket::NoError) {
        return false;
    } else {
        return rawSocket->isValid();
    }
}


SslSocket::SslSocket(Socket::NetworkLayerProtocol protocol, const SslConfiguration &config)
    :d_ptr(new SslSocketPrivate(config))
{
    Q_D(SslSocket);
    d->rawSocket.reset(new Socket(protocol));
    d->asServer = false;
}

SslSocket::SslSocket(qintptr socketDescriptor, const SslConfiguration &config)
    :d_ptr(new SslSocketPrivate(config))
{
    Q_D(SslSocket);
    d->rawSocket.reset(new Socket(socketDescriptor));
    d->asServer = false;
}

SslSocket::SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config)
    :d_ptr(new SslSocketPrivate(config))
{
    Q_D(SslSocket);
    d->rawSocket = rawSocket;
    d->asServer = false;
}


SslSocket::~SslSocket()
{
    delete d_ptr;
}

bool SslSocket::handshake(bool asServer, const QString &verificationPeerName)
{
    Q_D(SslSocket);
    if(!d->ssl.isNull()) {
        return false;
    }
    return d->handshake(asServer, verificationPeerName);
}

Certificate SslSocket::localCertificate() const
{
    Q_D(const SslSocket);
    return d->localCertificate();
}

QList<Certificate> SslSocket::localCertificateChain() const
{
    Q_D(const SslSocket);
    return d->localCertificateChain();
}

Certificate SslSocket::peerCertificate() const
{
    Q_D(const SslSocket);
    return d->peerCertificate();
}

QList<Certificate> SslSocket::peerCertificateChain() const
{
    Q_D(const SslSocket);
    return d->peerCertificateChain();
}

Ssl::PeerVerifyMode SslSocket::peerVerifyMode() const
{
    Q_D(const SslSocket);
    return d->config.peerVerifyMode();
}

QString SslSocket::peerVerifyName() const
{
    Q_D(const SslSocket);
    return d->config.peerVerifyName();
}


PrivateKey SslSocket::privateKey() const
{
    Q_D(const SslSocket);
    return d->config.privateKey();
}

Ssl::SslProtocol SslSocket::sslProtocol() const
{
    Q_D(const SslSocket);
    return d->sslProtocol();
}

SslCipher SslSocket::cipher() const
{
    Q_D(const SslSocket);
    return d->cipher();
}

SslSocket::SslMode SslSocket::mode() const
{
    Q_D(const SslSocket);
    return d->mode();
}

SslConfiguration SslSocket::sslConfiguration() const
{
    Q_D(const SslSocket);
    return d->config;
}

QList<SslError> SslSocket::sslErrors() const
{
    Q_D(const SslSocket);
    return d->errors;
}

void SslSocket::setSslConfiguration(const SslConfiguration &configuration)
{
    Q_D(SslSocket);
    d->config = configuration;
}


QSharedPointer<SslSocket> SslSocket::accept()
{
    Q_D(SslSocket);
    while(true) {
        Socket *rawSocket = d->rawSocket->accept();
        if(rawSocket) {
            QSharedPointer<SslSocket> s(new SslSocket(QSharedPointer<Socket>(rawSocket), d->config));
            if(s->d_func()->handshake(true, QString())) {
                return s;
            }
        }
    }
}

Socket *SslSocket::acceptRaw()
{
    Q_D(SslSocket);
    return d->rawSocket->accept();
}

bool SslSocket::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    Q_D(SslSocket);
    return d->rawSocket->bind(address, port, mode);
}

bool SslSocket::bind(quint16 port, Socket::BindMode mode)
{
    Q_D(SslSocket);
    return d->rawSocket->bind(port, mode);
}

bool SslSocket::connect(const QHostAddress &addr, quint16 port)
{
    Q_D(SslSocket);
    if(!d->rawSocket->connect(addr, port)) {
        return false;
    }
    return d->handshake(false, QString());
}

bool SslSocket::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    Q_D(SslSocket);
    if(!d->rawSocket->connect(hostName, port, protocol)) {
        return false;
    }
    return d->handshake(false, hostName);
}

bool SslSocket::close()
{
    Q_D(SslSocket);
    return d->close();
}

bool SslSocket::listen(int backlog)
{
    Q_D(SslSocket);
    return d->rawSocket->listen(backlog);
}

bool SslSocket::setOption(Socket::SocketOption option, const QVariant &value)
{
    Q_D(SslSocket);
    return d->rawSocket->setOption(option, value);
}

QVariant SslSocket::option(Socket::SocketOption option) const
{
    Q_D(const SslSocket);
    return d->rawSocket->option(option);
}

Socket::SocketError SslSocket::error() const
{
    Q_D(const SslSocket);
    if(d->error) {
        return d->error;
    } else {
        return d->rawSocket->error();
    }
}

QString SslSocket::errorString() const
{
    Q_D(const SslSocket);
    if(!d->errorString.isEmpty()) {
        return d->errorString;
    } else {
        return d->rawSocket->errorString();
    }
}

bool SslSocket::isValid() const
{
    Q_D(const SslSocket);
    return d->isValid();
}

QHostAddress SslSocket::localAddress() const
{
    Q_D(const SslSocket);
    return d->rawSocket->localAddress();
}

quint16 SslSocket::localPort() const
{
    Q_D(const SslSocket);
    return d->rawSocket->localPort();
}

QHostAddress SslSocket::peerAddress() const
{
    Q_D(const SslSocket);
    return d->rawSocket->peerAddress();
}

QString SslSocket::peerName() const
{
    Q_D(const SslSocket);
    return d->rawSocket->peerName();
}

quint16 SslSocket::peerPort() const
{
    Q_D(const SslSocket);
    return d->rawSocket->peerPort();
}

qintptr	SslSocket::fileno() const
{
    Q_D(const SslSocket);
    return d->rawSocket->fileno();
}

Socket::SocketType SslSocket::type() const
{
    Q_D(const SslSocket);
    return d->rawSocket->type();
}

Socket::SocketState SslSocket::state() const
{
    Q_D(const SslSocket);
    return d->rawSocket->state();
}

Socket::NetworkLayerProtocol SslSocket::protocol() const
{
    Q_D(const SslSocket);
    return d->rawSocket->protocol();
}


qint64 SslSocket::recv(char *data, qint64 size)
{
    Q_D(SslSocket);
    return d->recv(data, size, false);
}

qint64 SslSocket::recvall(char *data, qint64 size)
{
    Q_D(SslSocket);
    return d->recv(data, size, true);
}

qint64 SslSocket::send(const char *data, qint64 size)
{
    Q_D(SslSocket);
    return d->send(data, size, false);
}

qint64 SslSocket::sendall(const char *data, qint64 size)
{
    Q_D(SslSocket);
    return d->send(data, size, true);
}

QByteArray SslSocket::recv(qint64 size)
{
    Q_D(SslSocket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), false);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

QByteArray SslSocket::recvall(qint64 size)
{
    Q_D(SslSocket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), true);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint64 SslSocket::send(const QByteArray &data)
{
    Q_D(SslSocket);
    qint64 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 SslSocket::sendall(const QByteArray &data)
{
    Q_D(SslSocket);
    return d->send(data.data(), data.size(), true);
}


namespace {

class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<SslSocket> s);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual QHostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr	fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) override;
    virtual bool close() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint64 recv(char *data, qint64 size) override;
    virtual qint64 recvall(char *data, qint64 size) override;
    virtual qint64 send(const char *data, qint64 size) override;
    virtual qint64 sendall(const char *data, qint64 size) override;
    virtual QByteArray recv(qint64 size) override;
    virtual QByteArray recvall(qint64 size) override;
    virtual qint64 send(const QByteArray &data) override;
    virtual qint64 sendall(const QByteArray &data) override;
private:
    QSharedPointer<SslSocket> s;
};

SocketLikeImpl::SocketLikeImpl(QSharedPointer<SslSocket> s)
    :s(s) {}

Socket::SocketError SocketLikeImpl::error() const
{
    return s->error();
}

QString SocketLikeImpl::errorString() const
{
    return s->errorString();
}

bool SocketLikeImpl::isValid() const
{
    return s->isValid();
}

QHostAddress SocketLikeImpl::localAddress() const
{
    return s->localAddress();
}

quint16 SocketLikeImpl::localPort() const
{
    return s->localPort();
}

QHostAddress SocketLikeImpl::peerAddress() const
{
    return s->peerAddress();
}

QString SocketLikeImpl::peerName() const
{
    return s->peerName();
}

quint16 SocketLikeImpl::peerPort() const
{
    return s->peerPort();
}

qintptr	SocketLikeImpl::fileno() const
{
    return s->fileno();
}

Socket::SocketType SocketLikeImpl::type() const
{
    return s->type();
}

Socket::SocketState SocketLikeImpl::state() const
{
    return s->state();
}

Socket::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    return s->protocol();
}

Socket *SocketLikeImpl::acceptRaw()
{
    return s->acceptRaw();
}

QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    return SocketLike::sslSocket(s->accept());
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform)
{
    return s->bind(address, port, mode);
}

bool SocketLikeImpl::bind(quint16 port, Socket::BindMode mode)
{
    return s->bind(port, mode);
}

bool SocketLikeImpl::connect(const QHostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}

bool SocketLikeImpl::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    return s->connect(hostName, port, protocol);
}

bool SocketLikeImpl::close()
{
    return s->close();
}

bool SocketLikeImpl::listen(int backlog)
{
    return s->listen(backlog);
}

bool SocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}

QVariant SocketLikeImpl::option(Socket::SocketOption option) const
{
    return s->option(option);
}

qint64 SocketLikeImpl::recv(char *data, qint64 size)
{
    return s->recv(data, size);
}

qint64 SocketLikeImpl::recvall(char *data, qint64 size)
{
    return s->recvall(data, size);
}

qint64 SocketLikeImpl::send(const char *data, qint64 size)
{
    return s->send(data, size);
}

qint64 SocketLikeImpl::sendall(const char *data, qint64 size)
{
    return s->sendall(data, size);
}

QByteArray SocketLikeImpl::recv(qint64 size)
{
    return s->recv(size);
}

QByteArray SocketLikeImpl::recvall(qint64 size)
{
    return s->recvall(size);
}

qint64 SocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}

qint64 SocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}

} //anonymous namespace

QSharedPointer<SocketLike> SocketLike::sslSocket(QSharedPointer<SslSocket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QSharedPointer<SocketLike> SocketLike::sslSocket(SslSocket *s)
{
    return QSharedPointer<SocketLikeImpl>::create(QSharedPointer<SslSocket>(s)).dynamicCast<SocketLike>();
}

QTNETWORKNG_NAMESPACE_END
