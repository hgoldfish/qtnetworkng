#include <QtCore/qthread.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qmap.h>
#include <QtCore/qset.h>
#include <QtCore/qcache.h>
#include <QtCore/qdatetime.h>
#include "../include/private/socket_p.h"
#include "../include/coroutine_utils.h"
#include "debugger.h"

QTNG_LOGGER("qtng.socket");

QTNETWORKNG_NAMESPACE_BEGIN

SocketPrivate::SocketPrivate(HostAddress::NetworkLayerProtocol protocol, Socket::SocketType type, Socket *parent)
    : q_ptr(parent)
    , protocol(protocol)
    , type(type)
    , error(Socket::NoError)
    , state(Socket::UnconnectedState)
    , localPort(0)
    , peerPort(0)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    if (!createSocket())
        return;
    if (type == Socket::UdpSocket) {
        setOption(Socket::BroadcastSocketOption, 1);
        setOption(Socket::ReceivePacketInformation, 1);
        setOption(Socket::ReceiveHopLimit, 1);
    } else if (type == Socket::TcpSocket) {
        setTcpKeepalive(true, 10, 2);
    }
}

SocketPrivate::SocketPrivate(qintptr socketDescriptor, Socket *parent)
    : q_ptr(parent)
    , error(Socket::NoError)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    fd = static_cast<int>(socketDescriptor);
    setNonblocking();
    if (!checkState())
        return;
    // FIXME determine the type and state of socket
    protocol = HostAddress::IPv4Protocol;
    type = Socket::TcpSocket;
    state = Socket::ConnectedState;
    fetchConnectionParameters();
    if (type == Socket::UdpSocket) {
        state = Socket::UnconnectedState;
    } else if (type == Socket::TcpSocket) {
        setTcpKeepalive(true, 10, 2);
    }
}

SocketPrivate::~SocketPrivate()
{
#ifdef Q_OS_WIN
    freeWinSock();
#endif
}

bool SocketPrivate::bind(quint16 port, Socket::BindMode mode)
{
    return bind(HostAddress(HostAddress::Any), port, mode);
}

void SocketPrivate::setError(Socket::SocketError error, const QString &errorString)
{
    this->error = error;
    this->errorString = errorString;
}

void SocketPrivate::setError(Socket::SocketError error, ErrorString errorString)
{
    this->error = error;
    QString socketErrorString;
    switch (errorString) {
    case NonBlockingInitFailedErrorString:
        socketErrorString = QString::fromLatin1("Unable to initialize non-blocking socket");
        break;
    case BroadcastingInitFailedErrorString:
        socketErrorString = QString::fromLatin1("Unable to initialize broadcast socket");
        break;
    // should not happen anymore
    case NoIpV6ErrorString:
        socketErrorString = QString::fromLatin1("Attempt to use IPv6 socket on a platform with no IPv6 support");
        break;
    case RemoteHostClosedErrorString:
        socketErrorString = QString::fromLatin1("The remote host closed the connection");
        break;
    case TimeOutErrorString:
        socketErrorString = QString::fromLatin1("Network operation timed out");
        break;
    case ResourceErrorString:
        socketErrorString = QString::fromLatin1("Out of resources");
        break;
    case OperationUnsupportedErrorString:
        socketErrorString = QString::fromLatin1("Unsupported socket operation");
        break;
    case ProtocolUnsupportedErrorString:
        socketErrorString = QString::fromLatin1("Protocol type not supported");
        break;
    case InvalidSocketErrorString:
        socketErrorString = QString::fromLatin1("Invalid socket descriptor");
        break;
    case HostUnreachableErrorString:
        socketErrorString = QString::fromLatin1("Host unreachable");
        break;
    case NetworkUnreachableErrorString:
        socketErrorString = QString::fromLatin1("Network unreachable");
        break;
    case AccessErrorString:
        socketErrorString = QString::fromLatin1("Permission denied");
        break;
    case ConnectionTimeOutErrorString:
        socketErrorString = QString::fromLatin1("Connection timed out");
        break;
    case ConnectionRefusedErrorString:
        socketErrorString = QString::fromLatin1("Connection refused");
        break;
    case AddressInuseErrorString:
        socketErrorString = QString::fromLatin1("The bound address is already in use");
        break;
    case AddressNotAvailableErrorString:
        socketErrorString = QString::fromLatin1("The address is not available");
        break;
    case AddressProtectedErrorString:
        socketErrorString = QString::fromLatin1("The address is protected");
        break;
    case DatagramTooLargeErrorString:
        socketErrorString = QString::fromLatin1("Datagram was too large to send");
        break;
    case SendDatagramErrorString:
        socketErrorString = QString::fromLatin1("Unable to send a message");
        break;
    case ReceiveDatagramErrorString:
        socketErrorString = QString::fromLatin1("Unable to receive a message");
        break;
    case WriteErrorString:
        socketErrorString = QString::fromLatin1("Unable to write");
        break;
    case ReadErrorString:
        socketErrorString = QString::fromLatin1("Network error");
        break;
    case PortInuseErrorString:
        socketErrorString = QString::fromLatin1("Another socket is already listening on the same port");
        break;
    case NotSocketErrorString:
        socketErrorString = QString::fromLatin1("Operation on non-socket");
        break;
    case InvalidProxyTypeString:
        socketErrorString = QString::fromLatin1("The proxy type is invalid for this operation");
        break;
    case TemporaryErrorString:
        socketErrorString = QString::fromLatin1("Temporary error");
        break;
    case NetworkDroppedConnectionErrorString:
        socketErrorString = QString::fromLatin1("Network dropped connection on reset");
        break;
    case ConnectionResetErrorString:
        socketErrorString = QString::fromLatin1("Connection reset by peer");
        break;
    case UnknownSocketErrorString:
        socketErrorString = QString::fromLatin1("Unknown error");
        break;
    case OutOfMemoryErrorString:
        socketErrorString = QString::fromLatin1("Out of memeory.");
        break;
    }
    this->errorString = socketErrorString;
}

QString SocketPrivate::getErrorString() const
{
    return errorString;
}

bool SocketPrivate::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    if (state != Socket::UnconnectedState && state != Socket::BoundState) {
        return false;
    }
    Socket::SocketState oldState = state;
    state = Socket::HostLookupState;
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
        state = oldState;
        setError(Socket::HostNotFoundError, QString::fromLatin1("Host not found."));
        return false;
    }
    bool done = false;
    for (int i = 0; i < addresses.size(); ++i) {
        const HostAddress &addr = addresses.at(i);
        if (protocol == HostAddress::IPv4Protocol && addr.protocol() == HostAddress::IPv6Protocol) {
            continue;
        }
        if (protocol == HostAddress::IPv6Protocol && addr.protocol() == HostAddress::IPv4Protocol) {
            continue;
        }
        state = oldState;
        done = connect(addr, port);
        if (done)
            return true;
    }
    if (error == Socket::NoError) {  // and done must be false!
        setError(Socket::UnsupportedSocketOperationError,
                 QString::fromLatin1("No host with protocol(%1) not found.").arg(static_cast<int>(protocol)));
    }
    state = oldState;
    return false;
}

Socket::Socket(HostAddress::NetworkLayerProtocol protocol, SocketType type)
    : d_ptr(new SocketPrivate(protocol, type, this))
{
}

Socket::Socket(qintptr socketDescriptor)
    : d_ptr(new SocketPrivate(socketDescriptor, this))
{
}

Socket::~Socket()
{
    Q_D(Socket);
    d->abort();
    if (d->readLock.isLocked() || d->writeLock.isLocked()) {
        qtng_warning << "socket is deleted while receiving or sending.";
    }
    delete d_ptr;
}

Socket::SocketError Socket::error() const
{
    Q_D(const Socket);
    return d->error;
}

QString Socket::errorString() const
{
    Q_D(const Socket);
    return d->getErrorString();
}

bool Socket::isValid() const
{
    Q_D(const Socket);
    return d->isValid();
}

HostAddress Socket::localAddress() const
{
    Q_D(const Socket);
    return d->localAddress;
}

quint16 Socket::localPort() const
{
    Q_D(const Socket);
    return d->localPort;
}

HostAddress Socket::peerAddress() const
{
    Q_D(const Socket);
    return d->peerAddress;
}

QString Socket::peerName() const
{
    return QString();
}

quint16 Socket::peerPort() const
{
    Q_D(const Socket);
    return d->peerPort;
}

qintptr Socket::fileno() const
{
    Q_D(const Socket);
    return d->fd;
}

Socket::SocketType Socket::type() const
{
    Q_D(const Socket);
    return d->type;
}

Socket::SocketState Socket::state() const
{
    Q_D(const Socket);
    return d->state;
}

HostAddress::NetworkLayerProtocol Socket::protocol() const
{
    Q_D(const Socket);
    return d->protocol;
}

QString Socket::localAddressURI() const
{
    Q_D(const Socket);
    QString address;
    if (d->type == Socket::TcpSocket) {
        address = QLatin1String("tcp://%1:%2");
    } else {
        address = QLatin1String("udp://%1:%2");
    }
    if (d->localAddress.protocol() == HostAddress::IPv6Protocol) {
        address = address.arg(QString::fromLatin1("[%1]").arg(d->localAddress.toString()));
    } else {
        address = address.arg(d->localAddress.toString());
    }
    address = address.arg(d->localPort);
    return address;
}

QString Socket::peerAddressURI() const
{
    Q_D(const Socket);
    QString address;
    if (d->type == Socket::TcpSocket) {
        address = QLatin1String("tcp://%1:%2");
    } else {
        address = QLatin1String("udp://%1:%2");
    }
    if (d->peerAddress.protocol() == HostAddress::IPv6Protocol) {
        address = address.arg(QString::fromLatin1("[%1]").arg(d->peerAddress.toString()));
    } else {
        address = address.arg(d->peerAddress.toString());
    }
    address = address.arg(d->peerPort);
    return address;
}

Socket *Socket::accept()
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return nullptr;
    }
    return d->accept();
}

bool Socket::bind(const HostAddress &address, quint16 port, Socket::BindMode mode)
{
    Q_D(Socket);
    return d->bind(address, port, mode);
}

bool Socket::bind(quint16 port, Socket::BindMode mode)
{
    Q_D(Socket);
    return d->bind(port, mode);
}

bool Socket::connect(const HostAddress &host, quint16 port)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return false;
    }
    return d->connect(host, port);
}

bool Socket::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return false;
    }
    return d->connect(hostName, port, dnsCache);
}

void Socket::close()
{
    Q_D(Socket);
    d->close();
    if (d->readLock.isLocked()) {
        d->readLock.tryAcquire();
        d->readLock.release();
    }
    if (d->writeLock.isLocked()) {
        d->writeLock.tryAcquire();
        d->writeLock.release();
    }
}

void Socket::abort()
{
    Q_D(Socket);
    d->abort();
    if (d->readLock.isLocked()) {
        d->readLock.release();
    }
    if (d->writeLock.isLocked()) {
        d->writeLock.release();
    }
}

bool Socket::listen(int backlog)
{
    Q_D(Socket);
    return d->listen(backlog);
}

bool Socket::setTcpKeepalive(bool keepalve, int keepaliveTimeoutSesc, int keepaliveIntervalSesc)
{
    Q_D(Socket);
    return d->setTcpKeepalive(keepalve, keepaliveTimeoutSesc, keepaliveIntervalSesc);
}

bool Socket::setOption(Socket::SocketOption option, const QVariant &value)
{
    Q_D(Socket);
    return d->setOption(option, value);
}

QVariant Socket::option(Socket::SocketOption option) const
{
    Q_D(const Socket);
    return d->option(option);
}

bool Socket::joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    Q_D(Socket);
    return d->joinMulticastGroup(groupAddress, iface);
}

bool Socket::leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    Q_D(Socket);
    return d->leaveMulticastGroup(groupAddress, iface);
}

NetworkInterface Socket::multicastInterface() const
{
    Q_D(const Socket);
    return d->multicastInterface();
}

bool Socket::setMulticastInterface(const NetworkInterface &iface)
{
    Q_D(Socket);
    return d->setMulticastInterface(iface);
}

qint32 Socket::peek(char *data, qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->peek(data, size);
}

qint32 Socket::recv(char *data, qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, false);
}

qint32 Socket::recvall(char *data, qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, true);
}

qint32 Socket::send(const char *data, qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    qint32 bytesSent = d->send(data, size, false);
    if (bytesSent == 0 && !d->checkState()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint32 Socket::sendall(const char *data, qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->send(data, size, true);
}

qint32 Socket::recvfrom(char *data, qint32 size, HostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->recvfrom(data, size, addr, port);
}

qint32 Socket::sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->sendto(data, size, addr, port);
}

QByteArray Socket::recv(qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recv(bs.data(), bs.size(), false);
    if (bytes > 0) {
        bs.resize(static_cast<int>(bytes));
        return bs;
    }
    return QByteArray();
}

QByteArray Socket::recvall(qint32 size)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recv(bs.data(), bs.size(), true);
    if (bytes > 0) {
        bs.resize(static_cast<int>(bytes));
        return bs;
    }
    return QByteArray();
}

qint32 Socket::send(const QByteArray &data)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    qint32 bytesSent = d->send(data.data(), data.size(), false);
    if (bytesSent == 0 && !d->checkState()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint32 Socket::sendall(const QByteArray &data)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->send(data.data(), data.size(), true);
}

QByteArray Socket::recvfrom(qint32 size, HostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recvfrom(bs.data(), size, addr, port);
    if (bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint32 Socket::sendto(const QByteArray &data, const HostAddress &addr, quint16 port)
{
    Q_D(Socket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->sendto(data.data(), data.size(), addr, port);
}

QList<HostAddress> Socket::resolve(const QString &hostName)
{
    HostAddress tmp;
    if (tmp.setAddress(hostName)) {
        QList<HostAddress> result;
        result.append(tmp);
        return result;
    }

    std::function<QList<HostAddress>()> task = [hostName]() {
        QList<HostAddress> addr = HostAddress::getHostAddressByName(hostName);
        return addr;
    };

    QList<HostAddress> addr = callInThread<QList<HostAddress>>(task);
    return addr;
}

Socket *Socket::createConnection(const HostAddress &host, quint16 port, Socket::SocketError *error, int allowProtocol)
{
    return QTNETWORKNG_NAMESPACE::createConnection<Socket>(host, port, error, allowProtocol, MakeSocketType<Socket>);
}

Socket *Socket::createConnection(const QString &hostName, quint16 port, Socket::SocketError *error,
                                 QSharedPointer<SocketDnsCache> dnsCache, int allowProtocol)
{
    return QTNETWORKNG_NAMESPACE::createConnection<Socket>(hostName, port, error, dnsCache, allowProtocol,
                                                           MakeSocketType<Socket>);
}

Socket *Socket::createServer(const HostAddress &host, quint16 port, int backlog)
{
    return QTNETWORKNG_NAMESPACE::createServer<Socket>(host, port, backlog, MakeSocketType<Socket>);
}

class PollPrivate
{
public:
    PollPrivate();
    ~PollPrivate();
public:
    void add(QSharedPointer<Socket> socket, EventLoopCoroutine::EventType event);
    void remove(QSharedPointer<Socket> socket);
    QSharedPointer<Socket> wait(float secs = 0);
private:
    QMap<QSharedPointer<Socket>, int> watchers;
    QSharedPointer<QSet<QSharedPointer<Socket>>> events;
    QSharedPointer<Event> done;
};

class PollFunctor : public Functor
{
public:
    PollFunctor(QSharedPointer<QSet<QSharedPointer<Socket>>> events, QSharedPointer<Event> done,
                QSharedPointer<Socket> socket);
    virtual bool operator()();
    QSharedPointer<QSet<QSharedPointer<Socket>>> events;
    QSharedPointer<Event> done;
    QWeakPointer<Socket> socket;
};

PollFunctor::PollFunctor(QSharedPointer<QSet<QSharedPointer<Socket>>> events, QSharedPointer<Event> done,
                         QSharedPointer<Socket> socket)
    : events(events)
    , done(done)
    , socket(socket)
{
}

bool PollFunctor::operator()()
{
    if (!socket.isNull()) {
        events->insert(socket.toStrongRef());
        done->set();
    }
    return true;
}

PollPrivate::PollPrivate()
    : events(new QSet<QSharedPointer<Socket>>())
    , done(new Event())
{
}

PollPrivate::~PollPrivate()
{
    QMapIterator<QSharedPointer<Socket>, int> itor(watchers);
    while (itor.hasNext()) {
        EventLoopCoroutine::get()->removeWatcher(itor.value());
    }
}

void PollPrivate::add(QSharedPointer<Socket> socket, EventLoopCoroutine::EventType event)
{
    if (watchers.contains(socket)) {
        remove(socket);
    }
    PollFunctor *callback = new PollFunctor(events, done, socket);
    int watcherId = EventLoopCoroutine::get()->createWatcher(event, socket->fileno(), callback);
    EventLoopCoroutine::get()->startWatcher(watcherId);
    watchers.insert(socket, watcherId);
}

void PollPrivate::remove(QSharedPointer<Socket> socket)
{
    int watcherId = watchers.value(socket, 0);
    if (!watcherId)
        return;
    EventLoopCoroutine::get()->removeWatcher(watcherId);
    watchers.remove(socket);
}

QSharedPointer<Socket> PollPrivate::wait(float secs)
{
    if (!events->isEmpty()) {
        QMutableSetIterator<QSharedPointer<Socket>> itor(*events);
        QSharedPointer<Socket> socket = itor.next();
        itor.remove();
        return socket;
    }
    done->clear();
    if (!qFuzzyIsNull(secs)) {
        try {
            Timeout timeout(secs);
            Q_UNUSED(timeout);
            done->tryWait();
        } catch (TimeoutException &) {
            return QSharedPointer<Socket>();
        }
    } else {
        done->tryWait();
    }

    if (!events->isEmpty()) {
        // is there some one hungry?
        QMutableSetIterator<QSharedPointer<Socket>> itor(*events);
        QSharedPointer<Socket> socket = itor.next();
        itor.remove();
        return socket;
    } else {
        return QSharedPointer<Socket>();
    }
}

Poll::Poll()
    : d_ptr(new PollPrivate())
{
}

Poll::~Poll()
{
    delete d_ptr;
}

void Poll::add(QSharedPointer<Socket> socket, Poll::EventType event)
{
    Q_D(Poll);
    d->add(socket, static_cast<EventLoopCoroutine::EventType>(event));
}

void Poll::remove(QSharedPointer<Socket> socket)
{
    Q_D(Poll);
    d->remove(socket);
}

QSharedPointer<Socket> Poll::wait(float secs)
{
    Q_D(Poll);
    return d->wait(secs);
}

struct SocketDnsCacheCacheItem
{
    QList<HostAddress> addresses;
    quint64 firstSeen;
};

class SocketDnsCachePrivate
{
public:
    SocketDnsCachePrivate()
        : timeToLive(1000 * 60 * 5)
        , cache(1024)
    {
    }
    quint64 timeToLive;  // in msecs
    QCache<QString, SocketDnsCacheCacheItem> cache;
};

SocketDnsCache::SocketDnsCache()
    : d_ptr(new SocketDnsCachePrivate())
{
}

SocketDnsCache::~SocketDnsCache()
{
    delete d_ptr;
}

QList<HostAddress> SocketDnsCache::resolve(const QString &hostName)
{
    Q_D(SocketDnsCache);
    quint64 now = QDateTime::currentMSecsSinceEpoch();
    if (d->cache.contains(hostName)) {
        SocketDnsCacheCacheItem *item = d->cache.object(hostName);
        if (now > item->firstSeen && (now - item->firstSeen < d->timeToLive)) {
            return item->addresses;
        }
    }
    const QList<HostAddress> &addresses = Socket::resolve(hostName);
    if (addresses.isEmpty()) {
        return QList<HostAddress>();
    } else {
        SocketDnsCacheCacheItem *item = new SocketDnsCacheCacheItem();
        item->firstSeen = now;
        item->addresses = addresses;
        d->cache.insert(hostName, item);
        return addresses;
    }
}

bool SocketDnsCache::hasHost(const QString &hostName) const
{
    Q_D(const SocketDnsCache);
    return d->cache.contains(hostName);
}

void SocketDnsCache::addHost(const QString &hostName, const QList<HostAddress> &addresses)
{
    Q_D(SocketDnsCache);
    SocketDnsCacheCacheItem *item = new SocketDnsCacheCacheItem();
    item->firstSeen = QDateTime::currentMSecsSinceEpoch();
    item->addresses = addresses;
    d->cache.insert(hostName, item);
}

void SocketDnsCache::addHost(const QString &hostName, const HostAddress &addr)
{
    Q_D(SocketDnsCache);
    SocketDnsCacheCacheItem *item = new SocketDnsCacheCacheItem();
    item->firstSeen = QDateTime::currentMSecsSinceEpoch();
    QList<HostAddress> addresses;
    addresses.append(addr);
    item->addresses = addresses;
    d->cache.insert(hostName, item);
}

quint64 SocketDnsCache::timeToLive() const
{
    Q_D(const SocketDnsCache);
    return d->timeToLive;
}

void SocketDnsCache::setTimeToLive(quint64 msecs)
{
    Q_D(SocketDnsCache);
    d->timeToLive = msecs;
}

QTNETWORKNG_NAMESPACE_END
