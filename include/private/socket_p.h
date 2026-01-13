#ifndef QTNG_SOCKET_P_H
#define QTNG_SOCKET_P_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qstring.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qbytearray.h>
#include "../socket.h"

QTNETWORKNG_NAMESPACE_BEGIN

union qt_sockaddr;

class EventLoopCoroutine;
class HostAddress;

class SocketPrivate
{
public:
    enum ErrorString {
        NonBlockingInitFailedErrorString,
        BroadcastingInitFailedErrorString,
        NoIpV6ErrorString,
        RemoteHostClosedErrorString,
        TimeOutErrorString,
        ResourceErrorString,
        OperationUnsupportedErrorString,
        ProtocolUnsupportedErrorString,
        InvalidSocketErrorString,
        HostUnreachableErrorString,
        NetworkUnreachableErrorString,
        AccessErrorString,
        ConnectionTimeOutErrorString,
        ConnectionRefusedErrorString,
        AddressInuseErrorString,
        AddressNotAvailableErrorString,
        AddressProtectedErrorString,
        DatagramTooLargeErrorString,
        SendDatagramErrorString,
        ReceiveDatagramErrorString,
        WriteErrorString,
        ReadErrorString,
        PortInuseErrorString,
        NotSocketErrorString,
        InvalidProxyTypeString,
        TemporaryErrorString,
        NetworkDroppedConnectionErrorString,
        ConnectionResetErrorString,
        OutOfMemoryErrorString,

        UnknownSocketErrorString = -1
    };
public:
    SocketPrivate(HostAddress::NetworkLayerProtocol protocol, Socket::SocketType type, Socket *parent);
    SocketPrivate(qintptr socketDescriptor, Socket *parent);
    virtual ~SocketPrivate();
public:
    QString getErrorString() const;
    void setError(Socket::SocketError error, const QString &errorString);
    void setError(Socket::SocketError error, ErrorString errorString);
    bool checkState() const
    {
        return fd > 0 && (error == Socket::NoError || type != Socket::TcpSocket || error == Socket::RemoteHostClosedError);
    }  // not very accurate
    bool isValid() const;

    Socket *accept();
    bool bind(const HostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const HostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache);
    void close();
    void abort();
    bool listen(int backlog);
    bool setTcpKeepalive(bool keepalve, int keepaliveTimeoutSesc, int keepaliveIntervalSesc);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    bool setNonblocking();
    QVariant option(Socket::SocketOption option) const;

    bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface);
    bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface);
    NetworkInterface multicastInterface() const;
    bool setMulticastInterface(const NetworkInterface &iface);
    qint32 peek(char *data, qint32 size);
    qint32 recv(char *data, qint32 size, bool all);
    qint32 send(const char *data, qint32 size, bool all);
    qint32 recvfrom(char *data, qint32 size, HostAddress *addr, quint16 *port);
    qint32 sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port);
    bool fetchConnectionParameters();
public:
    bool setPortAndAddress(quint16 port, const HostAddress &address, qt_sockaddr *aa, int *sockAddrSize);
    bool createSocket();
public:
    Socket *q_ptr;
public:
    HostAddress::NetworkLayerProtocol protocol;
    Socket::SocketType type;
    Socket::SocketError error;
    QString errorString;
    Socket::SocketState state;
    HostAddress localAddress;
    quint16 localPort;
    HostAddress peerAddress;
    quint16 peerPort;
#ifdef Q_OS_WIN
    qintptr fd;
#else
    int fd;
#endif
    Lock readLock;
    Lock writeLock;

    Q_DECLARE_PUBLIC(Socket)
};

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_SOCKET_P_H
