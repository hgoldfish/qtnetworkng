#ifndef QTNG_LOCAL_SOCKET_H
#define QTNG_LOCAL_SOCKET_H

#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN

class LocalSocketPrivate;
class LocalSocket
{
public:
    LocalSocket();
    explicit LocalSocket(qintptr socketDescriptor);
    virtual ~LocalSocket();
public:
    Socket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    HostAddress localAddress() const;
    quint16 localPort() const;
    HostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    qintptr fileno() const;
    Socket::SocketType type() const;
    Socket::SocketState state() const;
    HostAddress::NetworkLayerProtocol protocol() const;
    QString localAddressURI() const;
    QString peerAddressURI() const;

    QString serverName() const;
    QString fullServerName() const;

    LocalSocket *accept();
    // By default a socket file that nothing serves anymore - the leftover of a
    // crashed server - is reclaimed, so restarting a server on the same name
    // just works. DontShareAddress opts out: the leftover is left alone and
    // bind() fails with AddressInUseError. Windows has nothing to reclaim, and
    // a named pipe never shares its name in the first place, so mode is
    // ignored there.
    bool bind(const QString &name, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QString &name);
    void close();
    void abort();
    // backlog reaches ::listen() on Unix. Windows named pipes have no accept
    // queue, so the value has no effect there.
    bool listen(int backlog = 50);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

    qint32 peek(char *data, qint32 size);
    qint32 peekRaw(char *data, qint32 size);
    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    QByteArray recv(qint32 size);
    QByteArray recvall(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);

    static LocalSocket *createConnection(const QString &name, Socket::SocketError *error = nullptr);
    // if backlog == 0, only create and bind (do not listen).
    static LocalSocket *createServer(const QString &name, int backlog = 50);
private:
    LocalSocket(LocalSocketPrivate *d);
    friend class LocalSocketPrivate;
private:
    LocalSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(LocalSocket)
    Q_DISABLE_COPY(LocalSocket)
};

QSharedPointer<class SocketLike> asSocketLike(QSharedPointer<LocalSocket> s);

inline QSharedPointer<class SocketLike> asSocketLike(LocalSocket *s)
{
    return asSocketLike(QSharedPointer<LocalSocket>(s));
}

QSharedPointer<LocalSocket> convertSocketLikeToLocalSocket(QSharedPointer<class SocketLike> socket);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_LOCAL_SOCKET_H
