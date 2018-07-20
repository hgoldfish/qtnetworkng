#include "../include/socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

SocketLike::~SocketLike()
{
}

namespace {
class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<Socket> s);
    virtual ~SocketLikeImpl();
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
    QSharedPointer<Socket> s;
};

SocketLikeImpl::SocketLikeImpl(QSharedPointer<Socket> s)
    :s(s) {}


SocketLikeImpl::~SocketLikeImpl()
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
    return s->accept();
}


QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    return SocketLike::rawSocket(s->accept());
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
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

QSharedPointer<SocketLike> SocketLike::rawSocket(QSharedPointer<Socket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QTNETWORKNG_NAMESPACE_END
