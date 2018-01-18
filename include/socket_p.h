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

class QSocketPrivate
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
    QSocketPrivate(QSocket::NetworkLayerProtocol protocol, QSocket::SocketType type, QSocket *parent);
    QSocketPrivate(qintptr socketDescriptor, QSocket *parent);
    virtual ~QSocketPrivate();
public:
    QString getErrorString() const;
    void setError(QSocket::SocketError error, const QString &errorString);
    void setError(QSocket::SocketError error, ErrorString errorString);
    bool isValid() const {return fd > 0 && error == QSocket::NoError;}

    QSocket *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform);
    bool bind(quint16 port = 0, QSocket::BindMode mode = QSocket::DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol = QSocket::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(QSocket::SocketOption option, const QVariant &value);
    bool setNonblocking();
    QVariant option(QSocket::SocketOption option) const;
    qint64 recv(char *data, qint64 size, bool all);
    qint64 send(const char *data, qint64 size, bool all = true);
    qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port);
private:
    bool fetchConnectionParameters();
    void setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, QT_SOCKLEN_T *sockAddrSize);
    bool createSocket();
protected:
    QSocket *q_ptr;
private:
    QSocket::NetworkLayerProtocol protocol;
    QSocket::SocketType type;
    QSocket::SocketError error;
    QString errorString;
    QSocket::SocketState state;
    QHostAddress localAddress;
    quint16 localPort;
    QHostAddress peerAddress;
    quint16 peerPort;
    qintptr fd;
    QSharedPointer<QSocketDnsCache> dnsCache;

    Q_DECLARE_PUBLIC(QSocket)
};

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_P_H
