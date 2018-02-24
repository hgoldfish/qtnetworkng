#ifndef QTNG_SOCKET_P_H
#define QTNG_SOCKET_P_H

#include <QtCore/QSharedPointer>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtNetwork/QHostAddress>
#include "socket.h"

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
    bool isValid() const {return fd > 0 && error == Socket::NoError;}

    Socket *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    bool setNonblocking();
    QVariant option(Socket::SocketOption option) const;
    qint64 recv(char *data, qint64 size, bool all);
    qint64 send(const char *data, qint64 size, bool all = true);
    qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port);
private:
    bool fetchConnectionParameters();
    void setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, QT_SOCKLEN_T *sockAddrSize);
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
    qintptr fd;
    QSharedPointer<SocketDnsCache> dnsCache;

    Q_DECLARE_PUBLIC(Socket)
};

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_P_H
