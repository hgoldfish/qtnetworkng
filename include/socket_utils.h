#ifndef QTNG_SOCKET_UTILS_H
#define QTNG_SOCKET_UTILS_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qfile.h>
#include "socket.h"
#include "io_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

#ifndef QTNG_NO_CRYPTO
class SslSocket;
#endif
class KcpSocket;
class SocketLike : public FileLike
{
public:
    SocketLike();
    virtual ~SocketLike() override;
public:
    virtual Socket::SocketError error() const = 0;
    virtual QString errorString() const = 0;
    virtual bool isValid() const = 0;
    virtual HostAddress localAddress() const = 0;
    virtual quint16 localPort() const = 0;
    virtual HostAddress peerAddress() const = 0;
    virtual QString peerName() const = 0;
    virtual quint16 peerPort() const = 0;
    virtual qintptr fileno() const = 0;
    virtual Socket::SocketType type() const = 0;
    virtual Socket::SocketState state() const = 0;
    virtual HostAddress::NetworkLayerProtocol protocol() const = 0;
    virtual QString localAddressURI() const = 0;
    virtual QString peerAddressURI() const = 0;

    virtual QSharedPointer<SocketLike> accept() = 0;
    virtual Socket *acceptRaw() = 0;
    virtual bool bind(const HostAddress &address, quint16 port = 0,
                      Socket::BindMode mode = Socket::DefaultForPlatform) = 0;
    virtual bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform) = 0;
    virtual bool connect(const HostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port,
                         QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>()) = 0;
    //    virtual void close() override = 0;  // from FileLike
    virtual void abort() = 0;
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
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *data, qint32 size) override;
    virtual qint64 size() override;
};

class ExchangerPrivate;
class Exchanger
{
public:
    Exchanger(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward, quint32 maxBufferSize = 1024 * 64,
              float timeout = 30.0);
    ~Exchanger();
public:
    void exchange();
private:
    ExchangerPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Exchanger)
};

class SocketProxy
{
public:
    virtual QSharedPointer<SocketLike> connect(const HostAddress &addr, quint16 port) = 0;
    virtual QSharedPointer<SocketLike> connect(const QString &addr, quint16 port) = 0;
};

QSharedPointer<SocketLike> asSocketLike(QSharedPointer<Socket> s);

inline QSharedPointer<SocketLike> asSocketLike(Socket *s)
{
    return asSocketLike(QSharedPointer<Socket>(s));
}

QSharedPointer<Socket> convertSocketLikeToSocket(QSharedPointer<SocketLike> socket);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_SOCKET_UTILS_H
