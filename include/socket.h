#ifndef QTNG_SOCKET_H
#define QTNG_SOCKET_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qobject.h>
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qhostinfo.h>

#include "eventloop.h"
#include "locks.h"

// #include <qplatformdefs.h>
#ifdef Q_OS_WIN
    #define QT_SOCKLEN_T int
    #define QT_SOCKOPTLEN_T int
#endif

#ifdef Q_OS_UNIX
    #include <unistd.h>
    #if defined(__GLIBC__) && (__GLIBC__ < 2)
        #define QT_SOCKLEN_T            int
    #else
        #ifdef Q_OS_ANDROID
            #define QT_SOCKLEN_T int
        #elif defined(Q_OS_OPENBSD)
            #define QT_SOCKLEN_T __socklen_t
        #else
            #define QT_SOCKLEN_T socklen_t
        #endif
    #endif
#endif

#ifdef fileno // android define fileno() function as macro
#undef fileno
#endif
QTNETWORKNG_NAMESPACE_BEGIN

class QSocketPrivate;
class QTcpSocketPrivate;
class QTcpServerPrivate;
class QSocketDnsCache;

class QSocket: public QObject
{
public:
    enum SocketType {
        TcpSocket,
        UdpSocket,
        UnknownSocketType = -1
    };
    Q_ENUMS(SocketType)
    enum NetworkLayerProtocol {
        IPv4Protocol,
        IPv6Protocol,
        AnyIPProtocol,
        UnknownNetworkLayerProtocol = -1
    };
    Q_ENUMS(NetworkLayerProtocol)
    enum SocketError {
        ConnectionRefusedError,
        RemoteHostClosedError,
        HostNotFoundError,
        SocketAccessError,
        SocketResourceError,
        SocketTimeoutError,                     /* 5 */
        DatagramTooLargeError,
        NetworkError,
        AddressInUseError,
        SocketAddressNotAvailableError,
        UnsupportedSocketOperationError,        /* 10 */
        UnfinishedSocketOperationError,
        ProxyAuthenticationRequiredError,
        SslHandshakeFailedError,
        ProxyConnectionRefusedError,
        ProxyConnectionClosedError,             /* 15 */
        ProxyConnectionTimeoutError,
        ProxyNotFoundError,
        ProxyProtocolError,
        OperationError,
        SslInternalError,                       /* 20 */
        SslInvalidUserDataError,
        TemporaryError,

        UnknownSocketError = -1,
        NoError = -2,
    };
    Q_ENUMS(SocketError)
    enum SocketState {
        UnconnectedState,
        HostLookupState,
        ConnectingState,
        ConnectedState,
        BoundState,
        ListeningState,
        ClosingState
    };
    Q_ENUMS(SocketState)
    enum SocketOption {
        BroadcastSocketOption, // SO_BROADCAST
        AddressReusable,  // SO_REUSEADDR
        ReceiveOutOfBandData, // SO_OOBINLINE
        ReceivePacketInformation, // IP_PKTINFO
        ReceiveHopLimit, // IP_RECVTTL
        LowDelayOption, // TCP_NODELAY
        KeepAliveOption, // SO_KEEPALIVE
        MulticastTtlOption, // IP_MULTICAST_TTL
        MulticastLoopbackOption, // IP_MULTICAST_LOOPBACK
        TypeOfServiceOption, //IP_TOS
        SendBufferSizeSocketOption,    //SO_SNDBUF
        ReceiveBufferSizeSocketOption,  //SO_RCVBUF
        MaxStreamsSocketOption, // for sctp
        NonBlockingSocketOption,
        BindExclusively
    };
    Q_ENUMS(SocketOption)
    enum BindFlag {
        DefaultForPlatform = 0x0,
        ShareAddress = 0x1,
        DontShareAddress = 0x2,
        ReuseAddressHint = 0x4
    };
    Q_DECLARE_FLAGS(BindMode, BindFlag)
public:
    QSocket(NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    QSocket(qintptr socketDescriptor);
    virtual ~QSocket();
public:
    SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    qintptr	fileno() const;
    SocketType type() const;
    SocketState state() const;
    NetworkLayerProtocol protocol() const;

    QSocket *accept();
    bool bind(QHostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, NetworkLayerProtocol protocol = AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(SocketOption option, const QVariant &value);
    QVariant option(SocketOption option) const;

    qint64 recv(char *data, qint64 size);
    qint64 recvall(char *data, qint64 size);
    qint64 send(const char *data, qint64 size);
    qint64 sendall(const char *data, qint64 size);
    qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port);

    QByteArray recvall(qint64 size);
    QByteArray recv(qint64 size);
    qint64 send(const QByteArray &data);
    qint64 sendall(const QByteArray &data);
    QByteArray recvfrom(qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const QByteArray &data, const QHostAddress &addr, quint16 port);

    static QList<QHostAddress> resolve(const QString &hostName);
    void setDnsCache(QSharedPointer<QSocketDnsCache> dnsCache);
protected:
    QSocketPrivate * const d_ptr;
private:
    Q_DECLARE_PRIVATE(QSocket)
    Q_DISABLE_COPY(QSocket)
};

Q_DECLARE_OPERATORS_FOR_FLAGS(QSocket::BindMode)

class PollPrivate;
class Poll
{
public:
    Poll();
    virtual ~Poll();
public:
    void add(QSocket *socket, EventLoopCoroutine::EventType event);
    void remove(QSocket *socket);
    QSocket *wait(qint64 msecs = 0);
private:
    PollPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Poll)
};

class QSocketDnsCachePrivate;
class QSocketDnsCache
{
public:
    QSocketDnsCache();
    virtual ~QSocketDnsCache();
public:
    QList<QHostAddress> resolve(const QString &hostName);
private:
    QSocketDnsCachePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(QSocketDnsCache)
};


QTNETWORKNG_NAMESPACE_END

Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::QSocket::SocketState)
Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::QSocket::SocketError)


#endif // QTNG_SOCKET_H
