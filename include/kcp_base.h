#ifndef QTNG_KCP_BASE_H
#define QTNG_KCP_BASE_H

#include "socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

enum KcpMode {
    LargeDelayInternet,
    Internet,
    FastInternet,
    Ethernet,
    Loopback,
};

class KcpSocketLikeHelper
{
public:
    explicit KcpSocketLikeHelper(QSharedPointer<SocketLike> socket);
public:
    void setMode(KcpMode mode);
    void setSendQueueSize(quint32 sendQueueSize);
    void setUdpPacketSize(quint32 udpPacketSize);
    void setTearDownTime(float secs);
protected:
    QSharedPointer<SocketLike> socket;
};

QSharedPointer<SocketLike> createKcpConnection(const HostAddress &host, quint16 port, Socket::SocketError *error = nullptr,
                                            int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol, KcpMode mode = Internet);
QSharedPointer<SocketLike> createKcpConnection(const QString &hostName, quint16 port, Socket::SocketError *error = nullptr,
                                   QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                    int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol, KcpMode mode = Internet);
// if backlog == 0, do not bind and listen.
QSharedPointer<SocketLike> createKcpServer(const HostAddress &host, quint16 port, int backlog = 50,
                                           KcpMode mode = Internet);

QTNETWORKNG_NAMESPACE_END
#endif // QTNG_KCP_BASE_H
