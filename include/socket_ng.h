#ifndef QTNG_SOCKET_NG_H
#define QTNG_SOCKET_NG_H

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>

#include "eventloop.h"
#include "locks.h"

// #include <qplatformdefs.h>
#ifdef Q_OS_WIN
    #define QT_SOCKLEN_T int
    //#define QT_SOCKOPTLEN_T int
#endif

#ifdef Q_OS_UNIX
    #include <unistd.h>
    #if defined(__GLIBC__) && (__GLIBC__ < 2)
        #define QT_SOCKLEN_T            int
    #else
        #define QT_SOCKLEN_T            socklen_t
    #endif
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class QSocketNgPrivate;
class QTcpSocketNgPrivate;
class QTcpServerNgPrivate;
class QSocketNgDnsCache;

class QSocketNg: public QObject
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
    QSocketNg(NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    QSocketNg(qintptr socketDescriptor);
    virtual ~QSocketNg();
public:
    SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    virtual qintptr	fileno() const;
    SocketType type() const;
    SocketState state() const;
    NetworkLayerProtocol protocol() const;

    QSocketNg *accept();
    bool bind(QHostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, NetworkLayerProtocol protocol = AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(SocketOption option, const QVariant &value);
    QVariant option(SocketOption option) const;

    qint64 recv(char *data, qint64 size);
    qint64 send(const char *data, qint64 size);
    qint64 sendall(const char *data, qint64 size);
    qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port);

    QByteArray recv(qint64 size);
    qint64 send(const QByteArray &data);
    qint64 sendall(const QByteArray &data);
    QByteArray recvfrom(qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const QByteArray &data, const QHostAddress &addr, quint16 port);

    static QList<QHostAddress> resolve(const QString &hostName);
    void setDnsCache(QSharedPointer<QSocketNgDnsCache> dnsCache);
protected:
    QSocketNgPrivate * const d_ptr;
private:
    Q_DECLARE_PRIVATE(QSocketNg)
    Q_DISABLE_COPY(QSocketNg)
};

Q_DECLARE_OPERATORS_FOR_FLAGS(QSocketNg::BindMode)

class PollPrivate;
class Poll
{
public:
    Poll();
    virtual ~Poll();
public:
    void add(QSocketNg *socket, EventLoopCoroutine::EventType event);
    void remove(QSocketNg *socket);
    QSocketNg *wait(qint64 msecs = 0);
private:
    PollPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Poll)
};

class QSocketNgDnsCachePrivate;
class QSocketNgDnsCache
{
public:
    QSocketNgDnsCache();
    virtual ~QSocketNgDnsCache();
public:
    QList<QHostAddress> resolve(const QString &hostName);
private:
    QSocketNgDnsCachePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(QSocketNgDnsCache)
};


QTNETWORKNG_NAMESPACE_END

Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::QSocketNg::SocketState)
Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::QSocketNg::SocketError)


#endif // QTNG_SOCKET_NG_H
