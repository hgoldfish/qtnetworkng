#ifndef QTNG_SOCKET_H
#define QTNG_SOCKET_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qobject.h>
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qhostinfo.h>

#include "private/eventloop_p.h"
#include "locks.h"

#ifdef fileno // android define fileno() function as macro
#undef fileno
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class SocketPrivate;
class SocketDnsCache;

class Socket: public QObject
{
public:
    enum SocketType {
        TcpSocket = QAbstractSocket::TcpSocket,
        UdpSocket = QAbstractSocket::UdpSocket,
        // SctpSocket = QAbstractSocket::SctpSocket,
        // define for other XXXSocket types. not used here.
        KcpSocket,
        LocalSocket,
        UnknownSocketType = -1
    };
    Q_ENUMS(SocketType)
    enum NetworkLayerProtocol {
        IPv4Protocol = QAbstractSocket::IPv4Protocol,
        IPv6Protocol = QAbstractSocket::IPv6Protocol,
        AnyIPProtocol = QAbstractSocket::AnyIPProtocol,
        UnknownNetworkLayerProtocol = -1
    };
    Q_ENUMS(NetworkLayerProtocol)
    enum SocketError {
        ConnectionRefusedError,
        RemoteHostClosedError,
        HostNotFoundError,
        SocketAccessError,
        SocketResourceError,
        SocketTimeoutError,
        DatagramTooLargeError,
        NetworkError,
        AddressInUseError,
        SocketAddressNotAvailableError,
        UnsupportedSocketOperationError,
        UnfinishedSocketOperationError,

        // define for proxy and ssl, not used here.
        ProxyAuthenticationRequiredError,
        SslHandshakeFailedError,
        ProxyConnectionRefusedError,
        ProxyConnectionClosedError,
        ProxyConnectionTimeoutError,
        ProxyNotFoundError,
        ProxyProtocolError,
        OperationError,
        SslInternalError,
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
        BroadcastSocketOption,             // SO_BROADCAST
        AddressReusable,                   // SO_REUSEADDR
        ReceiveOutOfBandData,              // SO_OOBINLINE
        ReceivePacketInformation,          // IP_PKTINFO
        ReceiveHopLimit,                   // IP_RECVTTL
        LowDelayOption,                    // TCP_NODELAY
        KeepAliveOption,                   // SO_KEEPALIVE
        MulticastTtlOption,                // IP_MULTICAST_TTL
        MulticastLoopbackOption,           // IP_MULTICAST_LOOPBACK
        TypeOfServiceOption,               // IP_TOS
        SendBufferSizeSocketOption,        // SO_SNDBUF
        ReceiveBufferSizeSocketOption,     // SO_RCVBUF
        MaxStreamsSocketOption,            // for sctp
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
    explicit Socket(NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    explicit Socket(qintptr socketDescriptor);
    virtual ~Socket();
public:
    SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    qintptr fileno() const;
    SocketType type() const;
    SocketState state() const;
    NetworkLayerProtocol protocol() const;

    Socket *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, NetworkLayerProtocol protocol = AnyIPProtocol);
    void close();
    void abort();
    bool listen(int backlog);
    bool setOption(SocketOption option, const QVariant &value);
    QVariant option(SocketOption option) const;

    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    qint32 recvfrom(char *data, qint32 size, QHostAddress *addr, quint16 *port);
    qint32 sendto(const char *data, qint32 size, const QHostAddress &addr, quint16 port);

    QByteArray recvall(qint32 size);
    QByteArray recv(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);
    QByteArray recvfrom(qint32 size, QHostAddress *addr, quint16 *port);
    qint32 sendto(const QByteArray &data, const QHostAddress &addr, quint16 port);

    static QList<QHostAddress> resolve(const QString &hostName);
    void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache);
private:
    SocketPrivate * const dd_ptr;
    Q_DECLARE_PRIVATE_D(dd_ptr, Socket)
    Q_DISABLE_COPY(Socket)
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Socket::BindMode)

class PollPrivate;
class Poll
{
public:
    enum EventType
    {
        Read = EventLoopCoroutine::Read,
        ReadWrite = EventLoopCoroutine::ReadWrite,
        Write = EventLoopCoroutine::Write,
    };
public:
    Poll();
    virtual ~Poll();
public:
    void add(QSharedPointer<Socket> socket, EventType event);
    void remove(QSharedPointer<Socket> socket);
    QSharedPointer<Socket> wait(float msecs = 0.0);
private:
    PollPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Poll)
};

class SocketDnsCachePrivate;
class SocketDnsCache
{
public:
    SocketDnsCache();
    virtual ~SocketDnsCache();
public:
    QList<QHostAddress> resolve(const QString &hostName);
private:
    SocketDnsCachePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(SocketDnsCache)
};


QTNETWORKNG_NAMESPACE_END

Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::Socket::SocketState)
Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::Socket::SocketError)


#endif // QTNG_SOCKET_H
