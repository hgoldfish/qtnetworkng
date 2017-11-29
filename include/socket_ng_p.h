#ifndef QTNG_SOCKET_NG_P_H
#define QTNG_SOCKET_NG_P_H

#include <QtCore/QSharedPointer>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtNetwork/QHostAddress>
#include "socket_ng.h"

QTNETWORKNG_NAMESPACE_BEGIN

union qt_sockaddr;

class EventLoopCoroutine;

class QSocketNgPrivate
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
    QSocketNgPrivate(QSocketNg::NetworkLayerProtocol protocol, QSocketNg::SocketType type, QSocketNg *parent);
    QSocketNgPrivate(qintptr socketDescriptor, QSocketNg *parent);
    virtual ~QSocketNgPrivate();
public:
    QString getErrorString() const;
    void setError(QSocketNg::SocketError error, const QString &errorString);
    void setError(QSocketNg::SocketError error, ErrorString errorString);
    bool isValid() const {return fd > 0 && error == QSocketNg::NoError;}

    QSocketNg *accept();
    bool bind(const QHostAddress &address, quint16 port = 0, QSocketNg::BindMode mode = QSocketNg::DefaultForPlatform);
    bool bind(quint16 port = 0, QSocketNg::BindMode mode = QSocketNg::DefaultForPlatform);
    bool connect(const QHostAddress &host, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSocketNg::NetworkLayerProtocol protocol = QSocketNg::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(QSocketNg::SocketOption option, const QVariant &value);
    bool setNonblocking();
    QVariant option(QSocketNg::SocketOption option) const;
    qint64 recv(char *data, qint64 size);
    qint64 send(const char *data, qint64 size, bool all = true);
    qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port);
    qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port);
private:
    bool fetchConnectionParameters();
    void setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, QT_SOCKLEN_T *sockAddrSize);
    bool createSocket();
protected:
    QSocketNg *q_ptr;
private:
    QSocketNg::NetworkLayerProtocol protocol;
    QSocketNg::SocketType type;
    QSocketNg::SocketError error;
    QString errorString;
    QSocketNg::SocketState state;
    QHostAddress localAddress;
    quint16 localPort;
    QHostAddress peerAddress;
    quint16 peerPort;
    qintptr fd;
    QSharedPointer<QSocketNgDnsCache> dnsCache;

    Q_DECLARE_PUBLIC(QSocketNg)
};

#ifdef Q_OS_WIN
void initWinSock();
void freeWinSock();
#endif

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_SOCKET_NG_P_H
