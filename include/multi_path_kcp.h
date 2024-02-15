#ifndef QTNG_MULTI_PATH_KCP_H
#define QTNG_MULTI_PATH_KCP_H

#include "kcp_base.h"

QTNETWORKNG_NAMESPACE_BEGIN

QSharedPointer<SocketLike> createMultiPathKcpConnection(const QList<QPair<HostAddress, quint16>> &remoteHosts,
                                                        Socket::SocketError *error = nullptr,
                    int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol, KcpMode mode = Internet);
QSharedPointer<SocketLike>
createMultiPathKcpConnection(const QString &hostName, quint16 port, Socket::SocketError *error = nullptr,
                    QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                    int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol, KcpMode mode = Internet);
// if backlog == 0, do not bind and listen.
QSharedPointer<SocketLike> createMultiKcpServer(const QList<QPair<HostAddress, quint16>> &localHosts, int backlog = 50,
                                           KcpMode mode = Internet);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_MULTI_PATH_KCP_H
