#ifndef QTNG_SOCKET_UTILS_H
#define QTNG_SOCKET_UTILS_H

#include <QtCore/qsharedpointer.h>
#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN


class SslSocket;
class SocketLike
{
public:
    virtual QSocket::SocketError error() const = 0;
    virtual QString errorString() const = 0;
    virtual bool isValid() const = 0;
    virtual QHostAddress localAddress() const = 0;
    virtual quint16 localPort() const = 0;
    virtual QHostAddress peerAddress() const = 0;
    virtual QString peerName() const = 0;
    virtual quint16 peerPort() const = 0;
    virtual qintptr	fileno() const = 0;
    virtual QSocket::SocketType type() const = 0;
    virtual QSocket::SocketState state() const = 0;
    virtual QSocket::NetworkLayerProtocol protocol() const = 0;

    virtual QSocket *accept() = 0;
    virtual bool bind(QHostAddress &address, quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform) = 0;
    virtual bool bind(quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform) = 0;
    virtual bool connect(const QHostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol = QSocket::AnyIPProtocol) = 0;
    virtual bool close() = 0;
    virtual bool listen(int backlog) = 0;
    virtual bool setOption(QSocket::SocketOption option, const QVariant &value) = 0;
    virtual QVariant option(QSocket::SocketOption option) const = 0;

    virtual qint64 recv(char *data, qint64 size) = 0;
    virtual qint64 recvall(char *data, qint64 size) = 0;
    virtual qint64 send(const char *data, qint64 size) = 0;
    virtual qint64 sendall(const char *data, qint64 size) = 0;
    virtual QByteArray recv(qint64 size) = 0;
    virtual QByteArray recvall(qint64 size) = 0;
    virtual qint64 send(const QByteArray &data) = 0;
    virtual qint64 sendall(const QByteArray &data) = 0;
public:
    static QSharedPointer<SocketLike> rawSocket(QSharedPointer<QSocket> s);
    static QSharedPointer<SocketLike> rawSocket(QSocket *s) { return rawSocket(QSharedPointer<QSocket>(s)); }
    static QSharedPointer<SocketLike> sslSocket(QSharedPointer<SslSocket> s);
    static QSharedPointer<SocketLike> sslSocket(SslSocket *s);
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_UTILS_H
