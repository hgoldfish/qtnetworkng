#include <string.h>
#include "../include/coroutine_utils.h"
#include "../include/socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

SocketLike::SocketLike() { }

SocketLike::~SocketLike() { }

qint32 SocketLike::read(char *data, qint32 size)
{
    return recv(data, size);
}

qint32 SocketLike::write(const char *data, qint32 size)
{
    return sendall(data, size);
}

qint64 SocketLike::size()
{
    return -1;
}

namespace {
class SocketLikeImpl : public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<Socket> s);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
    virtual QString localAddressURI() const override;
    virtual QString peerAddressURI() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port,
                         QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>()) override;
    virtual void close() override;
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint32 peek(char *data, qint32 size) override;
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
public:
    QSharedPointer<Socket> s;
};

SocketLikeImpl::SocketLikeImpl(QSharedPointer<Socket> s)
    : s(s)
{
}

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

HostAddress SocketLikeImpl::localAddress() const
{
    return s->localAddress();
}

quint16 SocketLikeImpl::localPort() const
{
    return s->localPort();
}

HostAddress SocketLikeImpl::peerAddress() const
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

qintptr SocketLikeImpl::fileno() const
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

HostAddress::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    return s->protocol();
}

QString SocketLikeImpl::localAddressURI() const
{
    return s->localAddressURI();
}

QString SocketLikeImpl::peerAddressURI() const
{
    return s->peerAddressURI();
}

Socket *SocketLikeImpl::acceptRaw()
{
    return s->accept();
}

QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    Socket *r = s->accept();
    if (r) {
        return asSocketLike(r);
    } else {
        return QSharedPointer<SocketLike>();
    }
}

bool SocketLikeImpl::bind(const HostAddress &address, quint16 port, Socket::BindMode mode)
{
    return s->bind(address, port, mode);
}

bool SocketLikeImpl::bind(quint16 port, Socket::BindMode mode)
{
    return s->bind(port, mode);
}

bool SocketLikeImpl::connect(const HostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}

bool SocketLikeImpl::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    return s->connect(hostName, port, dnsCache);
}

void SocketLikeImpl::close()
{
    s->close();
}

void SocketLikeImpl::abort()
{
    s->abort();
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

qint32 SocketLikeImpl::peek(char *data, qint32 size) 
{
    return s->peek(data, size);
}

qint32 SocketLikeImpl::peekRaw(char *data, qint32 size)
{
    return s->peek(data, size);
}

qint32 SocketLikeImpl::recv(char *data, qint32 size)
{
    return s->recv(data, size);
}

qint32 SocketLikeImpl::recvall(char *data, qint32 size)
{
    return s->recvall(data, size);
}

qint32 SocketLikeImpl::send(const char *data, qint32 size)
{
    return s->send(data, size);
}

qint32 SocketLikeImpl::sendall(const char *data, qint32 size)
{
    return s->sendall(data, size);
}

QByteArray SocketLikeImpl::recv(qint32 size)
{
    return s->recv(size);
}

QByteArray SocketLikeImpl::recvall(qint32 size)
{
    return s->recvall(size);
}

qint32 SocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}

qint32 SocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}

}  // anonymous namespace

QSharedPointer<SocketLike> asSocketLike(QSharedPointer<Socket> s)
{
    if (!s) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QSharedPointer<Socket> convertSocketLikeToSocket(QSharedPointer<SocketLike> socket)
{
    QSharedPointer<SocketLikeImpl> impl = socket.dynamicCast<SocketLikeImpl>();
    if (impl.isNull()) {
        return QSharedPointer<Socket>();
    } else {
        return impl->s;
    }
}

class ExchangerPrivate
{
public:
    ExchangerPrivate(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward, quint32 maxBufferSize,
                     float timeout);
    ~ExchangerPrivate();
public:
    void in2out();
    void out2in();
public:
    QSharedPointer<SocketLike> request;
    QSharedPointer<SocketLike> forward;
    CoroutineGroup *operations;
    quint32 maxBufferSize;
    float timeout;
};

ExchangerPrivate::ExchangerPrivate(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward,
                                   quint32 maxBufferSize, float timeout)
    : request(request)
    , forward(forward)
    , operations(new CoroutineGroup)
    , maxBufferSize(maxBufferSize)
    , timeout(timeout)
{
}

ExchangerPrivate::~ExchangerPrivate()
{
    delete operations;
}

void ExchangerPrivate::in2out()
{
    QByteArray buf(maxBufferSize, Qt::Uninitialized);
    while (true) {
        qint32 len = request->recv(buf.data(), buf.size());
        if (len <= 0) {
            forward->abort();
            operations->kill(QString::fromLatin1("out2in"));
            return;
        }
        qint32 sentBytes;
        try {
            Timeout timeout(this->timeout);
            Q_UNUSED(timeout);
            sentBytes = forward->sendall(buf.data(), len);
        } catch (TimeoutException &) {
            sentBytes = -1;
        }
        if (sentBytes != len) {
            forward->abort();
            operations->kill(QString::fromLatin1("out2in"));
            return;
        }
    }
}

void ExchangerPrivate::out2in()
{
    QByteArray buf(maxBufferSize, Qt::Uninitialized);
    while (true) {
        qint32 len = forward->recv(buf.data(), buf.size());
        if (len <= 0) {
            request->abort();
            operations->kill(QString::fromLatin1("in2out"));
            return;
        }
        qint32 sentBytes;
        try {
            Timeout timeout(this->timeout);
            Q_UNUSED(timeout);
            sentBytes = request->sendall(buf.data(), len);
        } catch (TimeoutException &) {
            sentBytes = -1;
        }
        if (sentBytes != len) {
            request->abort();
            operations->kill(QString::fromLatin1("in2out"));
            return;
        }
    }
}

Exchanger::Exchanger(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward, quint32 maxBufferSize,
                     float timeout)
    : d_ptr(new ExchangerPrivate(request, forward, maxBufferSize, timeout))
{
}

Exchanger::~Exchanger()
{
    delete d_ptr;
}

void Exchanger::exchange()
{
    Q_D(Exchanger);
    d->operations->spawnWithName(QString::fromLatin1("in2out"), [d] { d->in2out(); });
    d->operations->spawnWithName(QString::fromLatin1("out2in"), [d] { d->out2in(); });
    d->operations->joinall();
}

QTNETWORKNG_NAMESPACE_END
