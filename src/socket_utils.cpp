#include "../include/socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

namespace {
class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<QSocket> s);
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
    QSharedPointer<QSocket> s;
};

SocketLikeImpl::SocketLikeImpl(QSharedPointer<QSocket> s)
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
    return s->accept();
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port, QSocket::BindMode mode)
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

QSharedPointer<SocketLike> SocketLike::rawSocket(QSharedPointer<QSocket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QTNETWORKNG_NAMESPACE_END
