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
        TcpSocket = 1,
        UdpSocket = 2,
        // SctpSocket = QAbstractSocket::SctpSocket,
        // define for other XXXSocket types. not used here.
        KcpSocket = 3,
        LocalSocket = 4,
        UnknownSocketType = -1
    };
    Q_ENUMS(SocketType)
    enum NetworkLayerProtocol {
        IPv4Protocol = 1,
        IPv6Protocol = 2,
        UnknownNetworkLayerProtocol = -1
    };
    Q_ENUMS(NetworkLayerProtocol)
    enum SocketError {
        ConnectionRefusedError = 1,
        RemoteHostClosedError = 2,
        HostNotFoundError = 3,
        SocketAccessError = 4,
        SocketResourceError = 5,
        SocketTimeoutError = 6,
        DatagramTooLargeError = 7,
        NetworkError = 8,
        AddressInUseError = 9,
        SocketAddressNotAvailableError = 10,
        UnsupportedSocketOperationError = 11,
        UnfinishedSocketOperationError = 12,

        // define for proxy and ssl, not used here.
        ProxyAuthenticationRequiredError = 101,
        SslHandshakeFailedError = 102,
        ProxyConnectionRefusedError = 103,
        ProxyConnectionClosedError = 104,
        ProxyConnectionTimeoutError = 105,
        ProxyNotFoundError = 106,
        ProxyProtocolError = 107,
        OperationError = 108,
        SslInternalError = 109,
        SslInvalidUserDataError = 110,
        TemporaryError = 111,

        UnknownSocketError = -1,
        NoError = -2,
    };
    Q_ENUMS(SocketError)
    enum SocketState {
        UnconnectedState = 1,
        HostLookupState = 2,
        ConnectingState = 3,
        ConnectedState = 4,
        BoundState = 5,
        ListeningState = 6,
        ClosingState = 7
    };
    Q_ENUMS(SocketState)
    enum SocketOption {
        BroadcastSocketOption = 1,              // SO_BROADCAST
        AddressReusable = 2,                    // SO_REUSEADDR
        ReceiveOutOfBandData = 3,               // SO_OOBINLINE
        ReceivePacketInformation = 4,           // IP_PKTINFO
        ReceiveHopLimit = 5,                    // IP_RECVTTL
        LowDelayOption = 6,                     // TCP_NODELAY
        KeepAliveOption = 7,                    // SO_KEEPALIVE
        MulticastTtlOption = 8,                 // IP_MULTICAST_TTL
        MulticastLoopbackOption = 9,            // IP_MULTICAST_LOOPBACK
        TypeOfServiceOption = 10,               // IP_TOS
        SendBufferSizeSocketOption = 11,        // SO_SNDBUF
        ReceiveBufferSizeSocketOption = 12,     // SO_RCVBUF
        MaxStreamsSocketOption = 13,            // for sctp
        NonBlockingSocketOption = 14,
        BindExclusively = 15
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
    explicit Socket(NetworkLayerProtocol protocol = IPv4Protocol, SocketType type = TcpSocket);
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
    bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>());
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
    static Socket *createConnection(const QHostAddress &host, quint16 port, Socket::SocketError *error = nullptr,
                                  int allowProtocol = IPv4Protocol | IPv6Protocol);
    static Socket *createConnection(const QString &hostName, quint16 port, Socket::SocketError *error = nullptr,
                                  QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                                  int allowProtocol = IPv4Protocol | IPv6Protocol);
    static Socket *createServer(const QHostAddress &host, quint16 port, int backlog = 50);
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
