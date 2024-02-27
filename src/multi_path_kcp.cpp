#include <QtCore/qobject.h>
#include <QtCore/qscopeguard.h>
#include "kcp_base_p.h"
#include "../include/multi_path_kcp.h"
#include "../include/private/socket_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

const char PACKET_TYPE_UNCOMPRESSED_DATA_WITH_TOKEN = 0x05;

// #define DEBUG_PROTOCOL 1
#define TOKEN_SIZE 256
#define INVALIDE_SINCE_TIME 15  // 15s
#define ReceiveQueueSize 10

int multi_path_kcp_client_callback(const char *buf, int len, ikcpcb *kcp, void *user);

class MultiPathUdpLinkClient
{
public:
    typedef QByteArray PathID;

    MultiPathUdpLinkClient();
    ~MultiPathUdpLinkClient();
public:
    bool connect(const QList<QPair<HostAddress, quint16>> &remoteHosts, int allowProtocol);
    // template
    qint32 recvfrom(char *data, qint32 size, QByteArray &who);
    qint32 sendto(const char *data, qint32 size, const QByteArray &who);
    bool filter(char *data, qint32 *size, QByteArray *who);
    void close();
    void abort();
    void closeSlave(const QByteArray &){};
    void abortSlave(const QByteArray &){};
    bool addSlave(const QByteArray &, quint32) { return false; };
public:
    void doReceive(QSharedPointer<Socket> rawSocket);
    void startReceive(CoroutineGroup *operations);
public:
    struct RemoteHost
    {
        HostAddress addr;
        quint16 port;
        QSharedPointer<Socket> rawSocket;

        bool operator==(const RemoteHost &other) { return addr == other.addr && port == other.port; }

        QString toString() const { return QString("%1:%2").arg(addr.toString(), QString::number(port)); }
    };
    QList<RemoteHost> remoteHosts;
    QList<QSharedPointer<Socket>> rawSockets;
    QByteArray token;  // size == TOKEN_SIZE

    QByteArray unhandleData;
    qint32 unhandleDataSize;
    Event unhandleDataNotEmpty;
    Condition unhandleDataEmpty;

    int receiver;

    // todo:
    // at first n*remoteHostPorts.size() packet priority sent to unsent address.
    // after that, priority sent to remote that can receive data
    int lastSend;
    int nextSend();  // make sure choose one remote to sent
};
typedef KcpBase<MultiPathUdpLinkClient> MultiPathKcpClient;

class MultiPathUdpLinkSlaveInfo
{
public:
    explicit MultiPathUdpLinkSlaveInfo(quint32 connectionId);
public:
    struct RemoteHost
    {
        HostAddress addr;
        quint16 port;
        QSharedPointer<Socket> rawSocket;

        quint64 lastActiveTimestamp;
        QString toString() const { return QString("%1:%2").arg(addr.toString(), QString::number(port)); }
    };
    QList<QSharedPointer<RemoteHost>> remoteHosts;

    int lastSend;
    quint32 connectionId;
    quint64 connectedTime;
    int nextSend();  // average sent to slave. if is not active, choose next
    qint32 send(const char *data, qint32 len);

    QSharedPointer<RemoteHost> append(const HostAddress &addr, quint16 port, QSharedPointer<Socket> rawSocket);
};
typedef MultiPathUdpLinkSlaveInfo::RemoteHost MultiPathUdpLinkSlaveOnePath;

class MultiPathUdpLinkServer
{
public:
    typedef QByteArray PathID;
    MultiPathUdpLinkServer();
    ~MultiPathUdpLinkServer();
public:
    bool bind(const QList<QPair<HostAddress, quint16>> &localHosts, Socket::BindMode mode = Socket::DefaultForPlatform);
public:
    // template
    qint32 recvfrom(char *data, qint32 size, QByteArray &who);
    qint32 sendto(const char *data, qint32 size, const QByteArray &who);
    bool filter(char *data, qint32 *size, QByteArray *who);
    void close();
    void abort();
    void closeSlave(const QByteArray &who);
    void abortSlave(const QByteArray &who);
    bool addSlave(const QByteArray &who, quint32 connectionId);
public:
    bool accpetConnection(QMap<QByteArray, QSharedPointer<MultiPathUdpLinkSlaveOnePath>> &tokenToOnePath,
                          QSharedPointer<Socket> rawSocket, const QByteArray &token, const HostAddress &addr,
                          quint16 port);
public:
    struct Path
    {
        QMap<QByteArray, QSharedPointer<MultiPathUdpLinkSlaveOnePath>> tokenToOnePath;
        QSharedPointer<Socket> rawSocket;
        HostAddress localAddress;
        quint16 localPort;
    };
    void doReceive(QSharedPointer<Path> rawPath);
    void startReceive(CoroutineGroup *operations);

    QList<QSharedPointer<Path>> rawPaths;

    QMap<QByteArray, QSharedPointer<MultiPathUdpLinkSlaveInfo>> tokenToSlave;
    QMap<quint32, QByteArray> connectionIdToToken;


    Queue<QByteArray> buffers; // pool for doReceive

    struct UnhandleData {
        QByteArray who;
        QByteArray buf;
        qint32 size = 0;
    };
    Queue<UnhandleData> unhandleDatas;

    int receiver;
};

QByteArray makeMultiPathDataPacket(const QByteArray &token, const char *data, qint32 size)
{
    QByteArray packet(size + 1 + token.size(), Qt::Uninitialized);
    packet.data()[0] = PACKET_TYPE_UNCOMPRESSED_DATA_WITH_TOKEN;
    memcpy(packet.data() + 1, token.data(), token.size());
    memcpy(packet.data() + 1 + token.size(), data, static_cast<size_t>(size));
    return packet;
}

int multi_path_kcp_client_callback(const char *buf, int len, ikcpcb *kcp, void *user)
{
    MasterKcpBase<MultiPathUdpLinkClient> *p = static_cast<MasterKcpBase<MultiPathUdpLinkClient> *>(user);
    if (!p || !buf) {
        qtng_warning << "kcp_callback got invalid data.";
        return -1;
    }
    QByteArray packet;
    if (p->connectionId == 0) {
        if (len + TOKEN_SIZE > 65535) {
            qtng_warning << "kcp_callback got invalid multi data. len:" << len;
            return -1;
        }
        packet = makeMultiPathDataPacket(p->link->token, buf, len);
    } else {
        if (len > 65535) {
            qtng_warning << "kcp_callback got invalid data. len:" << len;
            return -1;
        }
        packet = MultiPathKcpClient::makeDataPacket(p->connectionId, buf, len);
    }
    qint32 sentBytes = p->sendRaw(packet.data(), packet.size());
    if (sentBytes != packet.size()) {  // but why this happens?
        if (p->error == Socket::NoError) {
            p->error = Socket::SocketAccessError;
            p->errorString = QString::fromLatin1("can not send udp packet");
        }
#ifdef DEBUG_PROTOCOL
        qtng_warning << "can not send packet to connection:" << p->connectionId;
#endif
        p->abort();
        return -1;
    }
    return sentBytes;
}

MultiPathUdpLinkClient::MultiPathUdpLinkClient()
    : token(randomBytes(TOKEN_SIZE))
    , unhandleDataSize(0)
    , lastSend(-1)
    , receiver(0)
{
}

MultiPathUdpLinkClient::~MultiPathUdpLinkClient() { }

bool MultiPathUdpLinkClient::connect(const QList<QPair<HostAddress, quint16>> &remoteHosts, int allowProtocol)
{
    QSharedPointer<Socket> ipv4, ipv6;
    for (QPair<HostAddress, quint16> _ : remoteHosts) {
        RemoteHost remote;
        remote.addr = _.first;
        remote.port = _.second;
        if (remote.addr.isIPv4() == HostAddress::IPv4Protocol) {
            if (!(allowProtocol & HostAddress::IPv4Protocol)) {
                continue;
            }
            if (ipv4.isNull()) {
                ipv4.reset(new Socket(HostAddress::IPv4Protocol, Socket::UdpSocket));
                if (!ipv4->bind()) {
                    ipv4.clear();
                    continue;
                }
                this->rawSockets.append(ipv4);
            }
            remote.rawSocket = ipv4;
        } else {
            if (!(allowProtocol & HostAddress::IPv6Protocol)) {
                continue;
            }
            if (ipv6.isNull()) {
                ipv6.reset(new Socket(HostAddress::IPv6Protocol, Socket::UdpSocket));
                if (!ipv6->bind()) {
                    ipv6.clear();
                    continue;
                }
                this->rawSockets.append(ipv6);
            }
            remote.rawSocket = ipv6;
        }
        this->remoteHosts.append(remote);
    }
    return !this->remoteHosts.isEmpty();
}

qint32 MultiPathUdpLinkClient::recvfrom(char *data, qint32 size, QByteArray &)
{
    if (rawSockets.size() == 0) {
        return -1;
    }
    if (rawSockets.size() == 1) {
        return rawSockets.at(0)->recvfrom(data, size, nullptr, nullptr);
    }
    if (!unhandleDataNotEmpty.tryWait()) {
        return -1;
    }
    if (unhandleData.isEmpty()) {
        return 0;
    }
    qint32 result = unhandleDataSize;
    Q_ASSERT(size >= result);
    memcpy(data, unhandleData.data(), result);
    unhandleDataSize = 0;
    unhandleDataNotEmpty.clear();
    unhandleDataEmpty.notify();
    return result;
}

qint32 MultiPathUdpLinkClient::sendto(const char *data, qint32 size, const QByteArray &)
{
    const RemoteHost &remote = remoteHosts.at(nextSend());
    QSharedPointer<Socket> rawSocket = remote.rawSocket;
#ifdef DEBUG_PROTOCOL
    qtng_debug << "send udp packet" << size << "to:" << remote.toString() << (int) (data[0]);
#endif
    return rawSocket->sendto(data, size, remote.addr, remote.port);
}

bool MultiPathUdpLinkClient::filter(char *data, qint32 *size, QByteArray *who)
{
    return false;
}

void MultiPathUdpLinkClient::close()
{
    for (QSharedPointer<Socket> rawSocket : rawSockets) {
        rawSocket->close();
    }
    unhandleDataNotEmpty.clear();
    unhandleData.clear();
    unhandleDataSize = 0;
    unhandleDataEmpty.notifyAll();
}

void MultiPathUdpLinkClient::abort()
{
    for (QSharedPointer<Socket> rawSocket : rawSockets) {
        rawSocket->abort();
    }
    unhandleDataNotEmpty.clear();
    unhandleData.clear();
    unhandleDataSize = 0;
    unhandleDataEmpty.notifyAll();
}

void MultiPathUdpLinkClient::doReceive(QSharedPointer<Socket> rawSocket)
{
    auto cleanup = qScopeGuard([this] {
        if ((--receiver) > 0) {
            return;
        }
        unhandleData.clear();
        unhandleDataNotEmpty.set();
        unhandleDataEmpty.notifyAll();
    });
    ++receiver;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), nullptr, nullptr);
        if (len <= 0) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "multi path client can not receive udp packet. remote:" << rawSocket->localAddressURI()
                       << "error:" << rawSocket->errorString();
#endif
            return;
        }
        while (true) {
            if (unhandleDataSize == 0) {
                break;
            }
            if (!unhandleDataEmpty.wait()) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "wait unhandle data empty error:" << rawSocket->localAddressURI();
#endif
                return;
            }
            if (!rawSocket->isValid()) {
                return;
            }
        }
        unhandleData = buf;
        unhandleDataSize = len;
        unhandleDataNotEmpty.set();
#ifdef DEBUG_PROTOCOL
        qtng_debug << "recv from udp packet" << len << rawSocket->localAddressURI();
#endif
    }
}

void MultiPathUdpLinkClient::startReceive(CoroutineGroup *operations)
{
    for (int i = 0; i < rawSockets.size(); i++) {
        QSharedPointer<Socket> rawSocket = rawSockets.at(i);
        operations->spawnWithName("do_receive_" + QString::number(i), [this, rawSocket] { doReceive(rawSocket); });
    }
}

int MultiPathUdpLinkClient::nextSend()
{
    if ((++lastSend) < remoteHosts.size()) {
        return lastSend;
    }
    lastSend = 0;
    return lastSend;
}

int MultiPathUdpLinkSlaveInfo::nextSend()
{
    quint64 now = QDateTime::currentSecsSinceEpoch();
    int last = lastSend++;
    for (; lastSend < remoteHosts.size(); ++lastSend) {
        QSharedPointer<RemoteHost> remoteHost = remoteHosts.at(lastSend);
        if (!remoteHost->rawSocket->isValid()) {
            continue;
        }
        if (now <= remoteHost->lastActiveTimestamp + 30) {
            return lastSend;
        }
    }
    for (lastSend = 0; lastSend < last; ++lastSend) {
        QSharedPointer<RemoteHost> remoteHost = remoteHosts.at(lastSend);
        if (!remoteHost->rawSocket->isValid()) {
            continue;
        }
        if (now <= remoteHost->lastActiveTimestamp + 30) {
            return lastSend;
        }
    }
    return 0;
}

qint32 MultiPathUdpLinkSlaveInfo::send(const char *data, qint32 len)
{
    QSharedPointer<RemoteHost> remote = remoteHosts.at(nextSend());
    return remote->rawSocket->sendto(data, len, remote->addr, remote->port);
}

QSharedPointer<MultiPathUdpLinkSlaveOnePath> MultiPathUdpLinkSlaveInfo::append(const HostAddress &addr, quint16 port,
                                                                               QSharedPointer<Socket> rawSocket)
{
    QSharedPointer<RemoteHost> remote(new RemoteHost());
    remote->addr = addr;
    remote->port = port;
    remote->rawSocket = rawSocket;
    remote->lastActiveTimestamp = QDateTime::currentSecsSinceEpoch();
    remoteHosts.append(remote);
    return remote;
}

MultiPathUdpLinkSlaveInfo::MultiPathUdpLinkSlaveInfo(quint32 connectionId)
    : lastSend(-1)
    , connectionId(connectionId)
    , connectedTime(QDateTime::currentSecsSinceEpoch())
{
}

MultiPathUdpLinkServer::MultiPathUdpLinkServer()
    : receiver(0)
    , buffers(0)
{
}

MultiPathUdpLinkServer::~MultiPathUdpLinkServer() { }

bool MultiPathUdpLinkServer::bind(const QList<QPair<HostAddress, quint16>> &localHosts,
                                  Socket::BindMode mode /*= Socket::DefaultForPlatform*/)
{
    for (const QPair<HostAddress, quint16> &_ : localHosts) {
        const HostAddress &addr = _.first;
        quint16 port = _.second;
        QSharedPointer<Socket> rawSocket;
        if (addr.isIPv4()) {
            rawSocket.reset(new Socket(HostAddress::IPv4Protocol, Socket::UdpSocket));
        } else {
            rawSocket.reset(new Socket(HostAddress::IPv6Protocol, Socket::UdpSocket));
        }
        if (mode & Socket::ReuseAddressHint) {
            rawSocket->setOption(Socket::AddressReusable, true);
        }
        if (!rawSocket->bind(addr, port)) {
            qtng_warning << "multi path bind addr:" << addr << "port:" << port << "error";
            continue;
        }
        QSharedPointer<Path> path(new Path());
        path->rawSocket = rawSocket;
        path->localAddress = addr;
        if (port == 0) {
            path->localPort = rawSocket->localPort();
        } else {
            path->localPort = port;
        }
        rawPaths.append(path);
    }
    return !rawPaths.isEmpty();
}

qint32 MultiPathUdpLinkServer::recvfrom(char *data, qint32 size, QByteArray &who)
{
    UnhandleData unhandle = unhandleDatas.get();
    if (unhandle.size <= 0) {
        return unhandle.size;
    }
    who = unhandle.who;
    Q_ASSERT(size >= unhandle.size);
    memcpy(data, unhandle.buf.data(), unhandle.size);
    buffers.put(unhandle.buf);
#ifdef DEBUG_PROTOCOL
    qtng_debug << "recv from udp packet" << unhandle.size;
#endif
    return unhandle.size;
}

qint32 MultiPathUdpLinkServer::sendto(const char *data, qint32 size, const QByteArray &who)
{
    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave = tokenToSlave.value(who);
    if (slave.isNull()) {
        return -1;
    }
#ifdef DEBUG_PROTOCOL
    qtng_debug << "send udp packet" << size;
#endif
    return slave->send(data, size);
}

bool MultiPathUdpLinkServer::filter(char *data, qint32 *size, QByteArray *who)
{
    return false;
}

void MultiPathUdpLinkServer::close()
{
    for (QSharedPointer<Path> rawPath : rawPaths) {
        rawPath->rawSocket->close();
    }
    UnhandleData unhandle;
    unhandle.size = 0;
    unhandleDatas.put(unhandle);
}

void MultiPathUdpLinkServer::abort()
{
    for (QSharedPointer<Path> rawPath : rawPaths) {
        rawPath->rawSocket->abort();
    }
    UnhandleData unhandle;
    unhandle.size = 0;
    unhandleDatas.put(unhandle);
}

void MultiPathUdpLinkServer::doReceive(QSharedPointer<Path> rawPath)
{
    auto cleanup = qScopeGuard([this] {
        if ((--receiver) > 0) {
            return;
        }
        UnhandleData unhandle;
        unhandle.size = 0;
        unhandleDatas.put(unhandle);
    });
    ++receiver;

    QSharedPointer<Socket> rawSocket = rawPath->rawSocket;
    QMap<QByteArray, QSharedPointer<MultiPathUdpLinkSlaveOnePath>> &tokenToOnePath = rawPath->tokenToOnePath;

    QByteArray token;
    HostAddress addr;
    quint16 port;
    qint32 len;

    while (true) {
        QByteArray buf = buffers.get(); // 64K
        if (buf.isEmpty()) {
            return;
        }
        char *data = buf.data();
        len = rawSocket->recvfrom(data, buf.size(), &addr, &port);
        if (len <= 0) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "multi path server can not receive udp packet.";
#endif
            return;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "got invalid kcp packet smaller than 5 bytes." << QByteArray(buf.data(), len);
#endif
            continue;
        }
        const char packType = data[0];
        if (packType == PACKET_TYPE_UNCOMPRESSED_DATA_WITH_TOKEN) {
            if (len < TOKEN_SIZE + 1) {
                continue;
            }
            token = buf.mid(1, TOKEN_SIZE);
#ifdef DEBUG_PROTOCOL
            token = token.toHex();
#endif
            if (!accpetConnection(tokenToOnePath, rawSocket, token, addr, port)) {
                continue;
            }
            // trans data to PACKET_TYPE_UNCOMPRESSED_DATA
            data[0] = PACKET_TYPE_UNCOMPRESSED_DATA;
            memmove(data + 1, data + 1 + TOKEN_SIZE, len - 1 - TOKEN_SIZE);
            len -= TOKEN_SIZE;
        } else {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
            quint32 connectionId = qFromBigEndian<quint32>(data + 1);
#else
            quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar *>(data + 1));
#endif
            if (connectionId == 0) {
                // compatible single path
                token = QString("%1:%2").arg(addr.toString(), QString::number(port)).toLatin1();
                if (!accpetConnection(tokenToOnePath, rawSocket, token, addr, port)) {
                    continue;
                }
            } else {
                token = connectionIdToToken.value(connectionId);
                if (token.isEmpty()) {
#ifdef DEBUG_PROTOCOL
                    qtng_warning << "reject data because can not find connection(1): " << connectionId;
#endif
                    continue;
                }
                QSharedPointer<MultiPathUdpLinkSlaveOnePath> onePath = tokenToOnePath.value(token);
                if (onePath.isNull()) {
                    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave = tokenToSlave.value(token);
                    if (slave.isNull()) {
#ifdef DEBUG_PROTOCOL
                        qtng_debug << "reject data because can not find connection(2): " << connectionId;
#endif
                        continue;
                    }

                    onePath = slave->append(addr, port, rawSocket);
                    tokenToOnePath.insert(token, onePath);
                } else {
                    onePath->lastActiveTimestamp = QDateTime::currentSecsSinceEpoch();
                }
            }
        }

        UnhandleData unhandle;
        unhandle.who = token;
        unhandle.buf = buf;
        unhandle.size = len;
        unhandleDatas.put(unhandle);
#ifdef DEBUG_PROTOCOL
        qtng_debug << "recv from udp packet" << len << addr << port;
#endif
    }
}

void MultiPathUdpLinkServer::startReceive(CoroutineGroup *operations)
{
    int capacity = ReceiveQueueSize * rawPaths.size();
    int oldCapacity = buffers.capacity();
    // only grows
    if (oldCapacity < capacity) {
        buffers.setCapacity(capacity);
        int diff = capacity - oldCapacity;
        for (int i = 0; i < diff; i++) {
            buffers.putForcedly(QByteArray(1024 * 64, Qt::Uninitialized));
        }
    }

    for (int i = 0; i < rawPaths.size(); ++i) {
        QSharedPointer<Path> rawPath = rawPaths.at(i);
        QString localUri;
        if (rawPath->localAddress.protocol() == HostAddress::IPv6Protocol) {
            localUri = QString("[%1]:%2").arg(rawPath->localAddress.toString(), QString::number(rawPath->localPort));
        } else {
            localUri = QString("%1:%2").arg(rawPath->localAddress.toString(), QString::number(rawPath->localPort));
        }
        operations->spawnWithName("do_accept_" + localUri, [rawPath, this] { doReceive(rawPath); });
    }
}

void MultiPathUdpLinkServer::closeSlave(const QByteArray &who)
{
    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave = tokenToSlave.take(who);
    if (!slave) {
        return;
    }
    connectionIdToToken.remove(slave->connectionId);

    for (QSharedPointer<Path> rawPath : rawPaths) {
        rawPath->tokenToOnePath.remove(who);
    }
}

void MultiPathUdpLinkServer::abortSlave(const QByteArray &who)
{
    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave = tokenToSlave.take(who);
    if (!slave) {
        return;
    }
    connectionIdToToken.remove(slave->connectionId);

    for (QSharedPointer<Path> rawPath : rawPaths) {
        rawPath->tokenToOnePath.remove(who);
    }
}

bool MultiPathUdpLinkServer::addSlave(const QByteArray &who, quint32 connectionId)
{
    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave = tokenToSlave.value(who);
    if (!slave) {
        return false;
    }
    slave->connectionId = connectionId;
    connectionIdToToken.insert(connectionId, who);
    return true;
}

bool MultiPathUdpLinkServer::accpetConnection(
        QMap<QByteArray, QSharedPointer<MultiPathUdpLinkSlaveOnePath>> &tokenToOnePath,
        QSharedPointer<Socket> rawSocket, const QByteArray &token, const HostAddress &addr, quint16 port)
{
    QSharedPointer<MultiPathUdpLinkSlaveOnePath> onePath = tokenToOnePath.value(token);
    QSharedPointer<MultiPathUdpLinkSlaveInfo> slave;
    if (!onePath.isNull()) {
        if (onePath->addr != addr || onePath->port != port) {
            return false;
        }
        // in this case we must find slave
        slave = tokenToSlave.value(token);
        if (slave.isNull()) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "can not find slave:" << token << "addr:" << addr << "port:" << port;
#endif
            return false;
        }
        // if pass 15s since last connected time, we reject the connection
        quint64 now = QDateTime::currentSecsSinceEpoch();
        if (now > INVALIDE_SINCE_TIME + slave->connectedTime) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "reject data since pass " << (now - slave->connectedTime)
                       << "secs. connectionId:" << slave->connectionId;
#endif
            return false;
        }
        onePath->lastActiveTimestamp = QDateTime::currentSecsSinceEpoch();
    } else {
        slave = tokenToSlave.value(token);
        if (!slave.isNull()) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "why this happened ?";
#endif
            return false;
        }
        slave.reset(new MultiPathUdpLinkSlaveInfo(0));
        tokenToSlave.insert(token, slave);

        onePath = slave->append(addr, port, rawSocket);
        tokenToOnePath.insert(token, onePath);
    }
    Q_ASSERT(!onePath.isNull());
    return true;
}

class MultiPathKcpClientSocketLike : public KcpBaseSocketLike<MultiPathUdpLinkClient>
{
public:
    MultiPathKcpClientSocketLike();
public:
    bool connect(const QList<QPair<HostAddress, quint16>> &remoteHosts, int allowProtocol);
};

class MultiPathKcpServerSocketLike : public KcpBaseSocketLike<MultiPathUdpLinkServer>
{
public:
    MultiPathKcpServerSocketLike();
protected:
    // interval
    MultiPathKcpServerSocketLike(KcpBase<MultiPathUdpLinkServer> *slave);
public:
    virtual bool bind(const HostAddress &address, quint16 port = 0,
                      Socket::BindMode mode = Socket::DefaultForPlatform) override
    {
        return true;
    }
    virtual bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform) override { return true; }
    bool bind(const QList<QPair<HostAddress, quint16>> &localHosts, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool rebind(const QList<QPair<HostAddress, quint16>> &localHosts, Socket::BindMode mode = Socket::DefaultForPlatform);

    virtual QSharedPointer<SocketLike> accept() override;
};

MultiPathKcpClientSocketLike::MultiPathKcpClientSocketLike()
    : KcpBaseSocketLike<MultiPathUdpLinkClient>(new MasterKcpBase<MultiPathUdpLinkClient>(
            QSharedPointer<MultiPathUdpLinkClient>(new MultiPathUdpLinkClient())))
{
}

bool MultiPathKcpClientSocketLike::connect(const QList<QPair<HostAddress, quint16>> &remoteHosts, int allowProtocol)
{
    if (!kcpBase->canConnect()) {
        return false;
    }
    MasterKcpBase<MultiPathUdpLinkClient> *master = dynamic_cast<MasterKcpBase<MultiPathUdpLinkClient> *>(kcpBase);
    if (!master) {
        return false;
    }
    QSharedPointer<MultiPathUdpLinkClient> link(master->link);
    if (!link->connect(remoteHosts, allowProtocol)) {
        return false;
    }
    if (link->rawSockets.isEmpty()) {
        return false;
    }
    kcpBase->setState(Socket::ConnectedState);
    if (link->rawSockets.size() > 1) {
        // ipv4 + ipv6
        link->startReceive(master->operations);
    }
    return true;
}

MultiPathKcpServerSocketLike::MultiPathKcpServerSocketLike()
    : KcpBaseSocketLike<MultiPathUdpLinkServer>(new MasterKcpBase<MultiPathUdpLinkServer>(
            QSharedPointer<MultiPathUdpLinkServer>(new MultiPathUdpLinkServer())))
{
}

MultiPathKcpServerSocketLike::MultiPathKcpServerSocketLike(KcpBase<MultiPathUdpLinkServer> *slave)
    : KcpBaseSocketLike<MultiPathUdpLinkServer>(slave)
{
}

bool MultiPathKcpServerSocketLike::bind(const QList<QPair<HostAddress, quint16>> &localHosts,
                                        Socket::BindMode mode /*= Socket::DefaultForPlatform*/)
{
    if (!kcpBase->canBind()) {
        return false;
    }
    MasterKcpBase<MultiPathUdpLinkServer> *master = dynamic_cast<MasterKcpBase<MultiPathUdpLinkServer> *>(kcpBase);
    if (!master) {
        return false;
    }
    QSharedPointer<MultiPathUdpLinkServer> link(master->link);
    if (!link->bind(localHosts)) {
        return false;
    }
    kcpBase->setState(Socket::BoundState);
    link->startReceive(master->operations);
    return true;
}

bool MultiPathKcpServerSocketLike::rebind(const QList<QPair<HostAddress, quint16>> &localHosts, Socket::BindMode mode)
{
    MasterKcpBase<MultiPathUdpLinkServer> *master = dynamic_cast<MasterKcpBase<MultiPathUdpLinkServer> *>(kcpBase);
    if (!master) {
        return false;
    }
    QSharedPointer<MultiPathUdpLinkServer> link(master->link);

    QList<QPair<HostAddress, quint16>> newLocalHosts;
    QList<QPair<HostAddress, quint16>> toRemoveLocalHosts;
    for (QSharedPointer<MultiPathUdpLinkServer::Path> path : link->rawPaths) {
        toRemoveLocalHosts.append(qMakePair(path->localAddress, path->localPort));
    }
    for (const QPair<HostAddress, quint16> &localHost : localHosts) {
        bool find = false;
        for (int i = 0; i < toRemoveLocalHosts.size(); i++) {
            if (toRemoveLocalHosts.at(i).first == localHost.first
                && toRemoveLocalHosts.at(i).second == localHost.second) {
                find = true;
                toRemoveLocalHosts.removeAt(i);
                break;
            }
        }
        if (!find) {
            newLocalHosts.append(localHost);
        }
    }
    // nothing changed
    if (toRemoveLocalHosts.isEmpty() && newLocalHosts.isEmpty()) {
        return true;
    }

    // remove old
    for (const QPair<HostAddress, quint16> toRemove : toRemoveLocalHosts) {
        for (int i = 0; i < link->rawPaths.size(); i++) {
            if (link->rawPaths.at(i)->localAddress == toRemove.first && link->rawPaths.at(i)->localPort == toRemove.second) {
                QSharedPointer<MultiPathUdpLinkServer::Path> path = link->rawPaths.at(i);
                link->rawPaths.removeAt(i);
                path->rawSocket->abort();
                break;
            }
        }
    }

    // bind new
    if (!newLocalHosts.isEmpty()) {
        if (!link->bind(newLocalHosts)) {
            return false;
        }
    }
    link->startReceive(master->operations);
    return true;
}

QSharedPointer<SocketLike> MultiPathKcpServerSocketLike::accept()
{
    KcpBase<MultiPathUdpLinkServer> *slave = kcpBase->accept();
    if (!slave) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<MultiPathKcpServerSocketLike>(new MultiPathKcpServerSocketLike(slave));
}

 MultiPathKcpServerSocketLikeHelper::MultiPathKcpServerSocketLikeHelper(QSharedPointer<SocketLike> socket /*= nullptr*/)
    : socket(socket)
{
}

bool MultiPathKcpServerSocketLikeHelper::isValid() const
{
    MultiPathKcpServerSocketLike *kcp = dynamic_cast<MultiPathKcpServerSocketLike *>(socket.data());
    return !!kcp;
}

void MultiPathKcpServerSocketLikeHelper::setSocket(QSharedPointer<SocketLike> socket)
{
    this->socket = socket;
}

bool MultiPathKcpServerSocketLikeHelper::rebind(const QList<QPair<HostAddress, quint16>> &localHosts)
{
    MultiPathKcpServerSocketLike *kcp = dynamic_cast<MultiPathKcpServerSocketLike *>(socket.data());
    if (kcp) {
        return kcp->rebind(localHosts);
    }
    return false;
}

QSharedPointer<SocketLike> createMultiPathKcpConnection(const QList<QPair<HostAddress, quint16>> &remoteHosts,
                                                        Socket::SocketError *error, int allowProtocol, KcpMode mode)
{
    QSharedPointer<MultiPathKcpClientSocketLike> socket(new MultiPathKcpClientSocketLike());
    if (!socket->connect(remoteHosts, allowProtocol)) {
        if (error) {
            *error = Socket::UnknownSocketError;
        }
        return nullptr;
    }
    socket->kcpBase->setMode(mode);
    socket->kcpBase->kcp->output = multi_path_kcp_client_callback;  // reset callback
    if (error) {
        *error = Socket::NoError;
    }
    return socket;
}

QSharedPointer<SocketLike>
createMultiPathKcpConnection(const QString &hostName, quint16 port, Socket::SocketError *error /*= nullptr*/,
                             QSharedPointer<SocketDnsCache> dnsCache /*= QSharedPointer<SocketDnsCache>()*/,
                             int allowProtocol /*= HostAddress::IPv4Protocol | HostAddress::IPv6Protocol*/,
                             KcpMode mode /*= Internet*/)
{
    QList<HostAddress> addresses;
    HostAddress t;
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
    QList<QPair<HostAddress, quint16>> remoteHosts;
    for (const HostAddress &host : addresses) {
        remoteHosts.append(qMakePair(host, port));
    }
    return createMultiPathKcpConnection(remoteHosts, error, allowProtocol, mode);
}

QSharedPointer<SocketLike> createMultiKcpServer(const QList<QPair<HostAddress, quint16>> &localHosts,
                                                int backlog /*= 50*/, KcpMode mode /*= Internet*/)
{
    QSharedPointer<MultiPathKcpServerSocketLike> socket(new MultiPathKcpServerSocketLike());
    if (!socket->bind(localHosts)) {
        return nullptr;
    }
    if (backlog > 0 && !socket->listen(backlog)) {
        return nullptr;
    }
    socket->kcpBase->setMode(mode);
    return socket;
}

QTNETWORKNG_NAMESPACE_END
