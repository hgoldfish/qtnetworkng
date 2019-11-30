#ifndef QTNG_SOCKET_P_H
#define QTNG_SOCKET_P_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qstring.h>
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
    bool isValid() const {return fd > 0 && (error == Socket::NoError || type != Socket::TcpSocket);}

    Socket *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol);
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
    void setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, int *sockAddrSize);
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
    QSharedPointer<SocketDnsCache> dnsCache;
    QSharedPointer<Lock> readLock;
    QSharedPointer<Lock> writeLock;

    Q_DECLARE_PUBLIC(Socket)
};

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_P_H
