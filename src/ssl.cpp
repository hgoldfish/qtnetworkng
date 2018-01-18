#include "../include/locks.h"
#include "../include/ssl.h"
#include "../include/socket.h"
#include "../include/openssl_symbols.h"
#include "../include/socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

void initOpenSSL(); // defined in crypto.cpp

template<typename Socket>
struct SslConnection
{
//    SslConnection(const SslConfiguration &config);
    SslConnection();
    ~SslConnection();
    bool wrap(bool asServer);
    bool handshake();
    qint64 recv(char *data, qint64 size, bool all);
    qint64 send(const char *data, qint64 size, bool all);
    bool pumpOutgoing();
    bool pumpIncoming();

    QSharedPointer<Socket> rawSocket;
    bool asServer;
//    SslConfiguration config;
    QSharedPointer<openssl::SSL_CTX> ctx;
    QSharedPointer<openssl::SSL> ssl;
};


//template<typename Socket>
//SslConnection<Socket>::SslConnection(const SslConfiguration &config)
//    :config(config)
//{
//}


template<typename Socket>
SslConnection<Socket>::SslConnection()
{
    initOpenSSL();
}

template<typename Socket>
SslConnection<Socket>::~SslConnection()
{

}

template<typename Socket>
bool SslConnection<Socket>::wrap(bool asServer)
{
    this->asServer = asServer;

    openssl::BIO *incoming = openssl::q_BIO_new(openssl::q_BIO_s_mem());
    if(!incoming) {
        return false;
    }
    openssl::BIO *outgoing = openssl::q_BIO_new(openssl::q_BIO_s_mem());
    if(!outgoing) {
        return false;
    }
    const openssl::SSL_METHOD *method = NULL;
    if(asServer) {
        method = openssl::q_SSLv3_server_method();
    } else {
        method = openssl::q_SSLv3_client_method();
    }
    if(method) {
        ctx.reset(openssl::q_SSL_CTX_new(method), openssl::q_SSL_CTX_free);
        if(!ctx.isNull()) {
            ssl.reset(openssl::q_SSL_new(ctx.data()), openssl::q_SSL_free);
            if(!ssl.isNull()) {
                openssl::q_SSL_set_bio(ssl.data(), incoming, outgoing);
                return handshake();
            }
        }
    }

    openssl::q_BIO_free(incoming);
    openssl::q_BIO_free(outgoing);
    return false;
}


template<typename Socket>
bool SslConnection<Socket>::handshake()
{
    while(true) {
        int result = asServer ? openssl::q_SSL_accept(ssl.data()) : openssl::q_SSL_connect(ssl.data());
        if(result <= 0) {
            QByteArray buf;
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
            case SSL_ERROR_SSL:
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
    int pendingBytes;
    QVarLengthArray<char, 4096> buf;
    openssl::BIO *outgoing = openssl::q_SSL_get_wbio(ssl.data());
    while(outgoing && rawSocket->isValid() && (pendingBytes = openssl::q_BIO_pending(outgoing)) > 0) {
        buf.resize(pendingBytes);
        int encryptedBytesRead = openssl::q_BIO_read(outgoing, buf.data(), pendingBytes);
        qint64 actualWritten = rawSocket->send(buf.constData(), encryptedBytesRead);
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
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
//            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
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
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
//            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                qDebug() << "recv error.";
                return false;
            }
        } else {
            total += result;
            if(total > size) {
                qDebug() << "send too many data.";
                return size;
            } else if(total == size) {
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

struct SslSocketPrivate: public SslConnection<QSocket>
{
    SslSocketPrivate();
    bool isValid() const;
    QSocket::SocketError error;
    QString errorString;
};


SslSocketPrivate::SslSocketPrivate()
    :SslConnection<QSocket>()
{

}

bool SslSocketPrivate::isValid() const
{
    if(error != QSocket::NoError) {
        return false;
    } else {
        return rawSocket->isValid();
    }
}


SslSocket::SslSocket(QSocket::NetworkLayerProtocol protocol)
    :d_ptr(new SslSocketPrivate)
{
    Q_D(SslSocket);
    d->rawSocket.reset(new QSocket(protocol));
    d->asServer = false;
}

SslSocket::SslSocket(qintptr socketDescriptor)
    :d_ptr(new SslSocketPrivate)
{
    Q_D(SslSocket);
    d->rawSocket.reset(new QSocket(socketDescriptor));
    d->asServer = false;
}

SslSocket::SslSocket(QSharedPointer<QSocket> rawSocket)
    :d_ptr(new SslSocketPrivate)
{
    Q_D(SslSocket);
    d->rawSocket = rawSocket;
}

SslSocket::~SslSocket()
{
    delete d_ptr;
}


QSharedPointer<SslSocket> SslSocket::accept()
{
    Q_D(SslSocket);
    QSocket *rawSocket = d->rawSocket->accept();
    if(rawSocket) {
        QSharedPointer<SslSocket> s(new SslSocket(QSharedPointer<QSocket>(rawSocket)));
        if(s->d_func()->wrap(true)) {
            return s;
        }
    }
    return QSharedPointer<SslSocket>();
}

QSocket *SslSocket::acceptRaw()
{
    Q_D(SslSocket);
    return d->rawSocket->accept();
}

bool SslSocket::bind(QHostAddress &address, quint16 port, QSocket::BindMode mode)
{
    Q_D(SslSocket);
    return d->rawSocket->bind(address, port, mode);
}

bool SslSocket::bind(quint16 port, QSocket::BindMode mode)
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
    return d->wrap(false);
}

bool SslSocket::connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol)
{
    Q_D(SslSocket);
    if(!d->rawSocket->connect(hostName, port, protocol)) {
        return false;
    }
    return d->wrap(false);
}

bool SslSocket::close()
{
    Q_D(SslSocket);
    return d->rawSocket->close();
}

bool SslSocket::listen(int backlog)
{
    Q_D(SslSocket);
    return d->rawSocket->listen(backlog);
}

bool SslSocket::setOption(QSocket::SocketOption option, const QVariant &value)
{
    Q_D(SslSocket);
    return d->rawSocket->setOption(option, value);
}

QVariant SslSocket::option(QSocket::SocketOption option) const
{
    Q_D(const SslSocket);
    return d->rawSocket->option(option);
}

QSocket::SocketError SslSocket::error() const
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

QSocket::SocketType SslSocket::type() const
{
    Q_D(const SslSocket);
    return d->rawSocket->type();
}

QSocket::SocketState SslSocket::state() const
{
    Q_D(const SslSocket);
    return d->rawSocket->state();
}

QSocket::NetworkLayerProtocol SslSocket::protocol() const
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
    virtual QSocket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual QHostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr	fileno() const override;
    virtual QSocket::SocketType type() const override;
    virtual QSocket::SocketState state() const override;
    virtual QSocket::NetworkLayerProtocol protocol() const override;

    virtual QSocket *accept() override;
    virtual bool bind(QHostAddress &address, quint16 port, QSocket::BindMode mode) override;
    virtual bool bind(quint16 port, QSocket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol) override;
    virtual bool close() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(QSocket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(QSocket::SocketOption option) const override;

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

QSocket::SocketError SocketLikeImpl::error() const
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

QSocket::SocketType SocketLikeImpl::type() const
{
    return s->type();
}

QSocket::SocketState SocketLikeImpl::state() const
{
    return s->state();
}

QSocket::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    return s->protocol();
}

QSocket *SocketLikeImpl::accept()
{
    return s->acceptRaw();
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform)
{
    return s->bind(address, port, mode);
}

bool SocketLikeImpl::bind(quint16 port, QSocket::BindMode mode)
{
    return s->bind(port, mode);
}

bool SocketLikeImpl::connect(const QHostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}

bool SocketLikeImpl::connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol)
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

bool SocketLikeImpl::setOption(QSocket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}

QVariant SocketLikeImpl::option(QSocket::SocketOption option) const
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

QTNETWORKNG_NAMESPACE_END



