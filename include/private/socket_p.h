#ifndef QTNG_SOCKET_P_H
#define QTNG_SOCKET_P_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qstring.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qbytearray.h>
#include <QtNetwork/qhostaddress.h>
#include "../socket.h"

QTNETWORKNG_NAMESPACE_BEGIN

union qt_sockaddr;

class EventLoopCoroutine;

class SocketPrivate
{
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

        UnknownSocketErrorString = -1
    };
public:
    SocketPrivate(Socket::NetworkLayerProtocol protocol, Socket::SocketType type, Socket *parent);
    SocketPrivate(qintptr socketDescriptor, Socket *parent);
    virtual ~SocketPrivate();
public:
    QString getErrorString() const;
    void setError(Socket::SocketError error, const QString &errorString);
    void setError(Socket::SocketError error, ErrorString errorString);
    bool checkState() const { return fd > 0 && (error == Socket::NoError || type != Socket::TcpSocket); } // not very accurate
    bool isValid() const;

    Socket *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache);
    void close();
    void abort();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    bool setNonblocking();
    QVariant option(Socket::SocketOption option) const;
    qint32 recv(char *data, qint32 size, bool all);
    qint32 send(const char *data, qint32 size, bool all = true);
    qint32 recvfrom(char *data, qint32 size, QHostAddress *addr, quint16 *port);
    qint32 sendto(const char *data, qint32 size, const QHostAddress &addr, quint16 port);
    bool fetchConnectionParameters();
private:
    bool setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, int *sockAddrSize);
    bool createSocket();
protected:
    Socket *q_ptr;
private:
    Socket::NetworkLayerProtocol protocol;
    Socket::SocketType type;
    Socket::SocketError error;
    QString errorString;
    Socket::SocketState state;
    QHostAddress localAddress;
    quint16 localPort;
    QHostAddress peerAddress;
    quint16 peerPort;
#ifdef Q_OS_WIN
    qintptr fd;
#else
    int fd;
#endif
    QSharedPointer<Lock> readLock;
    QSharedPointer<Lock> writeLock;

    Q_DECLARE_PUBLIC(Socket)
};

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif


template<typename SocketType>
SocketType *createConnection(const QHostAddress &addr, quint16 port, Socket::SocketError *error,
                             int allowProtocol, std::function<SocketType*(Socket::NetworkLayerProtocol)> func)
{
    SocketType *socket = nullptr;
    if (addr.isNull() || port == 0) {
        return socket;
    }
    bool isIPv4Address;
    addr.toIPv4Address(&isIPv4Address);
    if (isIPv4Address && (allowProtocol & Socket::IPv4Protocol)) {
        socket = func(Socket::IPv4Protocol);
    } else if (!isIPv4Address && (allowProtocol & Socket::IPv6Protocol)) {
        socket = func(Socket::IPv6Protocol);
    }
    if (socket) {
        bool done = socket->connect(addr, port);
        if (done) {
            if (error) {
                *error = Socket::NoError;
            }
            return socket;
        } else {
            if (error) {
                *error = socket->error();
            }
            delete socket;
        }
    }
    return nullptr;
}


template<typename SocketType>
SocketType *createConnection(const QString &hostName, quint16 port, Socket::SocketError *error,
                           QSharedPointer<SocketDnsCache> dnsCache, int allowProtocol,
                           std::function<SocketType*(Socket::NetworkLayerProtocol)> func)
{
    QList<QHostAddress> addresses;
    QHostAddress t;
    if (t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if (dnsCache.isNull()) {
            addresses = Socket::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }

    if (addresses.isEmpty()) {
        if (error) {
            *error = Socket::HostNotFoundError;
        }
        return nullptr;
    }
    for (int i = 0; i < addresses.size(); ++i) {
        const QHostAddress &addr = addresses.at(i);
        SocketType *socket = createConnection<SocketType>(addr, port, error, allowProtocol, func);
        if (socket) {
            return socket;
        }
    }
    if (error && *error == Socket::NoError) {
        *error = Socket::HostNotFoundError;
    }
    return nullptr;
}


template<typename SocketType>
SocketType *createServer(const QHostAddress &host, quint16 port, int backlog,
                         std::function<SocketType*(Socket::NetworkLayerProtocol)> func)
{
    SocketType *socket;
    if (host == QHostAddress(QHostAddress::AnyIPv4) || host == QHostAddress(QHostAddress::Any)) {
        socket = func(Socket::IPv4Protocol);
    } else if (host == QHostAddress(QHostAddress::AnyIPv6)) {
        socket = func(Socket::IPv6Protocol);
    } else {
        bool isIPv4Address;
        host.toIPv4Address(&isIPv4Address);
        if (isIPv4Address) {
            socket = func(Socket::IPv4Protocol);
        } else {
            socket = func(Socket::IPv6Protocol);
        }
    }
    if (backlog > 0) {
        socket->setOption(Socket::AddressReusable, true);
        if (!socket->bind(host, port)) {
            delete socket;
            return nullptr;
        }
        if (!socket->listen(backlog)) {
            delete socket;
            return nullptr;
        }
    }
    return socket;
}

template<typename SocketType>
SocketType *MakeSocketType(Socket::NetworkLayerProtocol protocol)
{
    return new SocketType(protocol);
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_P_H
