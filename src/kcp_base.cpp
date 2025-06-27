#include "kcp_base_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

class SinglePathUdpLinkId
{
public:
    SinglePathUdpLinkId();

    bool operator==(const SinglePathUdpLinkId &other) const;
    bool operator<(const SinglePathUdpLinkId &other) const;
    bool isNull() const;
    QString toString() const;
public:
    HostAddress addr;
    quint16 port;
};

QDebug operator<<(QDebug out, const SinglePathUdpLinkId &t)
{
    return out << t.toString();
}

class SinglePathUdpLinkManager
{
public:
    typedef SinglePathUdpLinkId PathID;
    SinglePathUdpLinkManager(HostAddress::NetworkLayerProtocol protocol);
    SinglePathUdpLinkManager(qintptr socketDescriptor);
    SinglePathUdpLinkManager(QSharedPointer<Socket> rawSocket);
    ~SinglePathUdpLinkManager();
public:
    // template
    qint32 recvfrom(char *data, qint32 size, SinglePathUdpLinkId &who);
    qint32 sendto(const char *data, qint32 size, const SinglePathUdpLinkId &who);
    bool filter(char *data, qint32 *size, SinglePathUdpLinkId *who);
    void close();
    void abort();
    void closeSlave(const SinglePathUdpLinkId &who);
    void abortSlave(const SinglePathUdpLinkId &who);
    bool addSlave(const SinglePathUdpLinkId &who, quint32 connectionId) { return true; };
public:
    QSharedPointer<Socket> rawSocket;
    std::function<bool(char *data, qint32 *size, HostAddress *add, quint16 *port)> filterCallback;
};

SinglePathUdpLinkId::SinglePathUdpLinkId()
    : port(0)
{
}

bool SinglePathUdpLinkId::operator==(const SinglePathUdpLinkId &other) const
{
    return addr == other.addr && port == other.port;
}

bool SinglePathUdpLinkId::operator<(const SinglePathUdpLinkId &other) const
{
    HostAddress::NetworkLayerProtocol a = addr.protocol();
    HostAddress::NetworkLayerProtocol b = other.addr.protocol();
    if (a != b) {
        return a < b;
    }
    switch (a) {
    case qtng::HostAddress::IPv4Protocol: {
        IPv4Address A = addr.toIPv4Address();
        IPv4Address B = other.addr.toIPv4Address();
        if (A != B) {
            return A < B;
        }
        break;
    }
    case qtng::HostAddress::IPv6Protocol: {
        IPv6Address A = addr.toIPv6Address();
        IPv6Address B = other.addr.toIPv6Address();
        int result = memcmp(A.c, B.c, sizeof(IPv6Address));
        if (result != 0) {
            return result < 0;
        }
        break;
    }
    default:
        break;
    }
    return port < other.port;
}

bool SinglePathUdpLinkId::isNull() const
{
    return port == 0 || addr.isNull();
}

QString SinglePathUdpLinkId::toString() const
{
    return addr.toString() + QLatin1String(":") + QString::number(port);
}

SinglePathUdpLinkManager::SinglePathUdpLinkManager(HostAddress::NetworkLayerProtocol protocol)
    : rawSocket(new Socket(protocol, Socket::UdpSocket))
{
}

SinglePathUdpLinkManager::SinglePathUdpLinkManager(QSharedPointer<Socket> rawSocket)
    : rawSocket(rawSocket)
{
}

SinglePathUdpLinkManager::SinglePathUdpLinkManager(qintptr socketDescriptor)
    : rawSocket(new Socket(socketDescriptor))
{
}

SinglePathUdpLinkManager::~SinglePathUdpLinkManager() { }

qint32 SinglePathUdpLinkManager::recvfrom(char *data, qint32 size, SinglePathUdpLinkId &who)
{
    return rawSocket->recvfrom(data, size, &who.addr, &who.port);
}

qint32 SinglePathUdpLinkManager::sendto(const char *data, qint32 size, const SinglePathUdpLinkId &who)
{
    return rawSocket->sendto(data, size, who.addr, who.port);
}

bool SinglePathUdpLinkManager::filter(char *data, qint32 *size, SinglePathUdpLinkId *who)
{
    if (filterCallback) {
        return filterCallback(data, size, &(who->addr), &(who->port));
    }
    return false;
}

void SinglePathUdpLinkManager::close()
{
    rawSocket->close();
}

void SinglePathUdpLinkManager::abort()
{
    rawSocket->abort();
}

void SinglePathUdpLinkManager::closeSlave(const SinglePathUdpLinkId &who) { }

void SinglePathUdpLinkManager::abortSlave(const SinglePathUdpLinkId &who) { }

class SinglePathUdpLinkSocketLike : public KcpBaseSocketLike<SinglePathUdpLinkManager>
{
public:
    SinglePathUdpLinkSocketLike(HostAddress::NetworkLayerProtocol protocol);
    SinglePathUdpLinkSocketLike(qintptr socketDescriptor);
    SinglePathUdpLinkSocketLike(QSharedPointer<Socket> rawSocket);
    ~SinglePathUdpLinkSocketLike();
protected:
    // interval
    SinglePathUdpLinkSocketLike(QSharedPointer<KcpBase<SinglePathUdpLinkManager>> slave);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress peerAddress() const override;
    virtual quint16 peerPort() const override;
    virtual QString peerName() const override;
    virtual qintptr fileno() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
    virtual QString localAddressURI() const override;
    virtual QString peerAddressURI() const override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const HostAddress &address, quint16 port,
                      Socket::BindMode mode = Socket::DefaultForPlatform) override;
    virtual bool bind(quint16 port, Socket::BindMode mode = Socket::DefaultForPlatform) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;

    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface = NetworkInterface());
    bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface = NetworkInterface());
    NetworkInterface multicastInterface() const;
    bool setMulticastInterface(const NetworkInterface &iface);
    bool setFilter(std::function<bool(char *, qint32 *, HostAddress *, quint16 *)> callback);
    qint32 udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port);
    QSharedPointer<SocketLike> accept(const HostAddress &addr, quint16 port);
protected:
    QSharedPointer<Socket> socket() const;
};

SinglePathUdpLinkSocketLike::SinglePathUdpLinkSocketLike(HostAddress::NetworkLayerProtocol protocol)
    : KcpBaseSocketLike<SinglePathUdpLinkManager>(QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>>(new MasterKcpBase<SinglePathUdpLinkManager>(
            QSharedPointer<SinglePathUdpLinkManager>(new SinglePathUdpLinkManager(protocol)))))
{
}

SinglePathUdpLinkSocketLike::SinglePathUdpLinkSocketLike(qintptr socketDescriptor)
    : KcpBaseSocketLike<SinglePathUdpLinkManager>(QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>>(new MasterKcpBase<SinglePathUdpLinkManager>(
            QSharedPointer<SinglePathUdpLinkManager>(new SinglePathUdpLinkManager(socketDescriptor)))))
{
}

SinglePathUdpLinkSocketLike::SinglePathUdpLinkSocketLike(QSharedPointer<Socket> rawSocket)
    : KcpBaseSocketLike<SinglePathUdpLinkManager>(QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>>(new MasterKcpBase<SinglePathUdpLinkManager>(
            QSharedPointer<SinglePathUdpLinkManager>(new SinglePathUdpLinkManager(rawSocket)))))
{
}

SinglePathUdpLinkSocketLike::SinglePathUdpLinkSocketLike(QSharedPointer<KcpBase<SinglePathUdpLinkManager>> slave)
    : KcpBaseSocketLike<SinglePathUdpLinkManager>(slave)
{
}

SinglePathUdpLinkSocketLike::~SinglePathUdpLinkSocketLike() { }

Socket::SocketError SinglePathUdpLinkSocketLike::error() const
{
    if (kcpBase->error != Socket::NoError) {
        return kcpBase->error;
    }
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->error();
    }
    return Socket::NoError;
}

QString SinglePathUdpLinkSocketLike::errorString() const
{
    if (!kcpBase->errorString.isEmpty()) {
        return kcpBase->errorString;
    }
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->errorString();
    }
    return QString();
}

bool SinglePathUdpLinkSocketLike::isValid() const
{
    if (!kcpBase->isValid()) {
        return false;
    }
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->isValid();
    }
    return false;
}

HostAddress SinglePathUdpLinkSocketLike::localAddress() const
{
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->localAddress();
    }
    return HostAddress();
}

quint16 SinglePathUdpLinkSocketLike::localPort() const
{
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->localPort();
    }
    return 0;
}

HostAddress SinglePathUdpLinkSocketLike::peerAddress() const
{
    return kcpBase->remoteId.addr;
}

quint16 SinglePathUdpLinkSocketLike::peerPort() const
{
    return kcpBase->remoteId.port;
}

QString SinglePathUdpLinkSocketLike::peerName() const
{
    return kcpBase->remoteId.addr.toString();
}

qintptr SinglePathUdpLinkSocketLike::fileno() const
{
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->fileno();
    }
    return -1;
}

HostAddress::NetworkLayerProtocol SinglePathUdpLinkSocketLike::protocol() const
{
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->protocol();
    }
    return HostAddress::UnknownNetworkLayerProtocol;
}

QString SinglePathUdpLinkSocketLike::localAddressURI() const
{
    const HostAddress &addr = localAddress();
    quint16 port = localPort();
    if (addr.protocol() == HostAddress::IPv6Protocol) {
        return QString::fromLatin1("kcp://[%1]:%2").arg(addr.toString()).arg(port);
    }
    return QString::fromLatin1("kcp://%1:%2").arg(addr.toString()).arg(port);
}

QString SinglePathUdpLinkSocketLike::peerAddressURI() const
{
    const HostAddress &addr = peerAddress();
    quint16 port = peerPort();
    if (addr.protocol() == HostAddress::IPv6Protocol) {
        return QString::fromLatin1("kcp://[%1]:%2").arg(addr.toString()).arg(port);
    }
    return QString::fromLatin1("kcp://%1:%2").arg(addr.toString()).arg(port);
}

QSharedPointer<SocketLike> SinglePathUdpLinkSocketLike::accept()
{
    QSharedPointer<KcpBase<SinglePathUdpLinkManager>> slave = kcpBase->accept();
    if (!slave) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<SinglePathUdpLinkSocketLike>(new SinglePathUdpLinkSocketLike(slave));
}

bool SinglePathUdpLinkSocketLike::bind(const HostAddress &address, quint16 port,
                                       Socket::BindMode mode /*= Socket::DefaultForPlatform*/)
{
    if (!kcpBase->canBind()) {
        return false;
    }
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (!master) {
        return false;
    }
    QSharedPointer<Socket> rawSocket = master->link->rawSocket;
    if (mode & Socket::ReuseAddressHint) {
        rawSocket->setOption(Socket::AddressReusable, true);
    }
    if (!rawSocket->bind(address, port, mode)) {
        return false;
    }
    kcpBase->setState(Socket::BoundState);
    return true;
}

bool SinglePathUdpLinkSocketLike::bind(quint16 port, Socket::BindMode mode /*= Socket::DefaultForPlatform*/)
{
    if (!kcpBase->canBind()) {
        return false;
    }
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (!master) {
        return false;
    }
    QSharedPointer<Socket> rawSocket = master->link->rawSocket;
    if (mode & Socket::ReuseAddressHint) {
        rawSocket->setOption(Socket::AddressReusable, true);
    }
    if (!rawSocket->bind(port, mode)) {
        return false;
    }
    kcpBase->setState(Socket::BoundState);
    return true;
}

bool SinglePathUdpLinkSocketLike::connect(const HostAddress &addr, quint16 port)
{
    if (addr.isNull() || port == 0) {
        return false;
    }
    if (!kcpBase->canConnect()) {
        return false;
    }
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (!master) {
        return false;
    }
    QSharedPointer<Socket> rawSocket = master->link->rawSocket;
    if (rawSocket && rawSocket->protocol() == addr.protocol()) {
        kcpBase->remoteId.addr = addr;
        kcpBase->remoteId.port = port;
        kcpBase->setState(Socket::ConnectedState);
        return true;
    }
    return false;
}

bool SinglePathUdpLinkSocketLike::connect(const QString &hostName, quint16 port,
                                          QSharedPointer<SocketDnsCache> dnsCache)
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
    for (int i = 0; i < addresses.size(); ++i) {
        const HostAddress &addr = addresses.at(i);
        if (connect(addr, port)) {
            return true;
        }
    }
    return false;
}

bool SinglePathUdpLinkSocketLike::setOption(Socket::SocketOption option, const QVariant &value)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->setOption(option, value);
    }
    return false;
}

QVariant SinglePathUdpLinkSocketLike::option(Socket::SocketOption option) const
{
    QSharedPointer<Socket> rawSocket = socket();
    if (rawSocket) {
        return rawSocket->option(option);
    }
    return QVariant();
}

bool SinglePathUdpLinkSocketLike::joinMulticastGroup(const HostAddress &groupAddress,
                                                     const NetworkInterface &iface /*= NetworkInterface()*/)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->joinMulticastGroup(groupAddress, iface);
    }
    return false;
}

bool SinglePathUdpLinkSocketLike::leaveMulticastGroup(const HostAddress &groupAddress,
                                                      const NetworkInterface &iface /*= NetworkInterface()*/)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->leaveMulticastGroup(groupAddress, iface);
    }
    return false;
}

NetworkInterface SinglePathUdpLinkSocketLike::multicastInterface() const
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->multicastInterface();
    }
    return NetworkInterface();
}

bool SinglePathUdpLinkSocketLike::setMulticastInterface(const NetworkInterface &iface)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->setMulticastInterface(iface);
    }
    return false;
}

bool SinglePathUdpLinkSocketLike::setFilter(std::function<bool(char *, qint32 *, HostAddress *, quint16 *)> callback)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        master->link->filterCallback = callback;
        return true;
    }
    return false;
}

qint32 SinglePathUdpLinkSocketLike::udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket->sendto(data, size, addr, port);
    }
    return -1;
}

QSharedPointer<SocketLike> SinglePathUdpLinkSocketLike::accept(const HostAddress &addr, quint16 port)
{
    SinglePathUdpLinkId remote;
    remote.addr = addr;
    remote.port = port;
    QSharedPointer<KcpBase<SinglePathUdpLinkManager>> slave = kcpBase->accept(remote);
    if (!slave) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<SinglePathUdpLinkSocketLike>(new SinglePathUdpLinkSocketLike(slave));
}

QSharedPointer<Socket> SinglePathUdpLinkSocketLike::socket() const
{
    QSharedPointer<MasterKcpBase<SinglePathUdpLinkManager>> master = kcpBase.dynamicCast<MasterKcpBase<SinglePathUdpLinkManager>>();
    if (master) {
        return master->link->rawSocket;
    }
    QSharedPointer<SlaveKcpBase<SinglePathUdpLinkManager>> slave = kcpBase.dynamicCast<SlaveKcpBase<SinglePathUdpLinkManager>>();
    if (slave && slave->parent) {
        return slave->parent->link->rawSocket;
    }
    return QSharedPointer<Socket>();
}

QSharedPointer<SocketLike>
createKcpConnection(const HostAddress &host, quint16 port, Socket::SocketError *error /*= nullptr*/,
                    int allowProtocol /*= HostAddress::IPv4Protocol | HostAddress::IPv6Protocol*/,
                    KcpMode mode /*= Internet*/)
{
    SinglePathUdpLinkSocketLike *socket = createConnection<SinglePathUdpLinkSocketLike>(
            host, port, error, allowProtocol, MakeSocketType<SinglePathUdpLinkSocketLike>);
    if (socket) {
        socket->kcpBase->setMode(mode);
    }
    return QSharedPointer<SocketLike>(socket);
}

QSharedPointer<SocketLike>
createKcpConnection(const QString &hostName, quint16 port, Socket::SocketError *error /*= nullptr*/,
                    QSharedPointer<SocketDnsCache> dnsCache /*= QSharedPointer<SocketDnsCache>()*/,
                    int allowProtocol /*= HostAddress::IPv4Protocol | HostAddress::IPv6Protocol*/,
                    KcpMode mode /*= Internet*/)
{
    SinglePathUdpLinkSocketLike *socket = createConnection<SinglePathUdpLinkSocketLike>(
            hostName, port, error, dnsCache, allowProtocol, MakeSocketType<SinglePathUdpLinkSocketLike>);
    if (socket) {
        socket->kcpBase->setMode(mode);
    }
    return QSharedPointer<SocketLike>(socket);
}

QSharedPointer<SocketLike> createKcpServer(const HostAddress &host, quint16 port, int backlog,
                                           KcpMode mode /*= Internet*/)
{
    SinglePathUdpLinkSocketLike *socket =
            createServer<SinglePathUdpLinkSocketLike>(host, port, backlog, MakeSocketType<SinglePathUdpLinkSocketLike>);
    if (socket) {
        socket->kcpBase->setMode(mode);
    }
    return QSharedPointer<SocketLike>(socket);
}

KcpSocketLikeHelper::KcpSocketLikeHelper(QSharedPointer<SocketLike> socket)
    : socket(socket)
{
}

bool KcpSocketLikeHelper::isValid() const
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    return !!kcp;
}

void KcpSocketLikeHelper::setSocket(QSharedPointer<SocketLike> socket)
{
    this->socket = socket;
}

quint32 KcpSocketLikeHelper::payloadSizeHint() const
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    return kcp->kcpBase->payloadSizeHint();
}

void KcpSocketLikeHelper::setDebugLevel(int level)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        kcp->kcpBase->setDebugLevel(level);
    }
}

void KcpSocketLikeHelper::setMode(KcpMode mode)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        kcp->kcpBase->setMode(mode);
    }
}

void KcpSocketLikeHelper::setSendQueueSize(quint32 sendQueueSize)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        kcp->kcpBase->setSendQueueSize(sendQueueSize);
    }
}

void KcpSocketLikeHelper::setUdpPacketSize(quint32 udpPacketSize)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        kcp->kcpBase->setUdpPacketSize(udpPacketSize);
    }
}

void KcpSocketLikeHelper::setTearDownTime(float secs)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        kcp->kcpBase->setTearDownTime(secs);
    }
}

bool KcpSocketLikeHelper::setFilter(std::function<bool(char *, qint32 *, HostAddress *, quint16 *)> callback)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->setFilter(callback);
    }
    return false;
}

qint32 KcpSocketLikeHelper::udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->udpSend(data, size, addr, port);
    }
    return -1;
}

QSharedPointer<SocketLike> KcpSocketLikeHelper::accept(const HostAddress &addr, quint16 port)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->accept(addr, port);
    }
    return QSharedPointer<SocketLike>();
}

bool KcpSocketLikeHelper::joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface /*= NetworkInterface()*/)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->joinMulticastGroup(groupAddress, iface);
    }
    return false;
}

bool KcpSocketLikeHelper::leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface /*= NetworkInterface()*/)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->leaveMulticastGroup(groupAddress, iface);
    }
    return false;
}

bool KcpSocketLikeHelper::setOption(Socket::SocketOption option, const QVariant &value)
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->setOption(option, value);
    }
    return false;
}

QVariant KcpSocketLikeHelper::option(Socket::SocketOption option) const
{
    QSharedPointer<SinglePathUdpLinkSocketLike> kcp = socket.dynamicCast<SinglePathUdpLinkSocketLike>();
    if (kcp) {
        return kcp->option(option);
    }
    return QVariant();
}

QTNETWORKNG_NAMESPACE_END
