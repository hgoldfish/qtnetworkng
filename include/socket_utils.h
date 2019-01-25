#ifndef QTNG_SOCKET_UTILS_H
#define QTNG_SOCKET_UTILS_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qfile.h>
#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN

#ifndef QTNG_NO_CRYPTO
class SslSocket;
#endif
class SocketLike
{
public:
    virtual ~SocketLike();
    virtual Socket::SocketError error() const = 0;
    virtual QString errorString() const = 0;
    virtual bool isValid() const = 0;
    virtual QHostAddress localAddress() const = 0;
    virtual quint16 localPort() const = 0;
    virtual QHostAddress peerAddress() const = 0;
    virtual QString peerName() const = 0;
    virtual quint16 peerPort() const = 0;
    virtual qintptr	fileno() const = 0;
    virtual Socket::SocketType type() const = 0;
    virtual Socket::SocketState state() const = 0;
    virtual Socket::NetworkLayerProtocol protocol() const = 0;

    virtual QSharedPointer<SocketLike> accept() = 0;
    virtual Socket *acceptRaw() = 0;
    virtual bool bind(QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform) = 0;
    virtual bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform) = 0;
    virtual bool connect(const QHostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol) = 0;
    virtual bool close() = 0;
    virtual bool listen(int backlog) = 0;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) = 0;
    virtual QVariant option(Socket::SocketOption option) const = 0;

    virtual qint32 recv(char *data, qint32 size) = 0;
    virtual qint32 recvall(char *data, qint32 size) = 0;
    virtual qint32 send(const char *data, qint32 size) = 0;
    virtual qint32 sendall(const char *data, qint32 size) = 0;
    virtual QByteArray recv(qint32 size) = 0;
    virtual QByteArray recvall(qint32 size) = 0;
    virtual qint32 send(const QByteArray &data) = 0;
    virtual qint32 sendall(const QByteArray &data) = 0;
public:
    static QSharedPointer<SocketLike> rawSocket(QSharedPointer<Socket> s);
    static QSharedPointer<SocketLike> rawSocket(Socket *s) { return rawSocket(QSharedPointer<Socket>(s)); }
#ifndef QTNG_NO_CRYPTO
    static QSharedPointer<SocketLike> sslSocket(QSharedPointer<SslSocket> s);
    static QSharedPointer<SocketLike> sslSocket(SslSocket *s);
#endif
};


class FileLike
{
public:
    virtual ~FileLike();
    virtual qint32 read(char *data, qint32 size) = 0;
    virtual qint32 readall(char *data, qint32 size) = 0;
    virtual qint32 write(char *data, qint32 size) = 0;
    virtual qint32 writeall(char *data, qint32 size) = 0;
    virtual bool atEnd() = 0;
    virtual void close() = 0;
public:
    static QSharedPointer<FileLike> rawFile(QSharedPointer<QFile> f);
    static QSharedPointer<FileLike> rawFile(QFile *f) { return rawFile(QSharedPointer<QFile>(f)); }
    static QSharedPointer<FileLike> bytes(const QByteArray &data);
};
QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_UTILS_H
