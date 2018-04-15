#include <QtCore/qthread.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qmap.h>
#include <QtCore/qcache.h>
#include "../include/socket_p.h"
#include "../include/coroutine_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

SocketPrivate::SocketPrivate(Socket::NetworkLayerProtocol protocol,
        Socket::SocketType type, Socket *parent)
    :q_ptr(parent), protocol(protocol), type(type), error(Socket::NoError),
      state(Socket::UnconnectedState)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    if(!createSocket())
        return;
    if(type == Socket::UdpSocket)
    {
        if(!setOption(Socket::BroadcastSocketOption, 1))
        {
//            setError(Socket::UnsupportedSocketOperationError);
//            close();
//            return;
        }
        setOption(Socket::ReceivePacketInformation, 1);
        setOption(Socket::ReceiveHopLimit, 1);
    }
}

SocketPrivate::SocketPrivate(qintptr socketDescriptor, Socket *parent)
    :q_ptr(parent), error(Socket::NoError)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    fd = socketDescriptor;
    setNonblocking();
    if(!isValid())
        return;
    // FIXME determine the type and state of socket
    protocol = Socket::AnyIPProtocol;
    type = Socket::TcpSocket;
    state = Socket::ConnectedState;
    fetchConnectionParameters();
}

SocketPrivate::~SocketPrivate()
{
    close();
#ifdef Q_OS_WIN
    freeWinSock();
#endif
}

bool SocketPrivate::bind(quint16 port, Socket::BindMode mode)
{
    return bind(QHostAddress(QHostAddress::Any), port, mode);
}

bool SocketPrivate::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    state = Socket::HostLookupState;
    QList<QHostAddress> addresses;
    QHostAddress t;
    if(t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if(dnsCache.isNull()) {
            addresses = Socket::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }

    if(addresses.isEmpty()) {
        state = Socket::UnconnectedState;
        setError(Socket::HostNotFoundError, QStringLiteral("Host not found."));
        return false;
    }
    bool done = true;
    state = Socket::UnconnectedState;
    for(int i = 0; i < addresses.size(); ++i) {
        QHostAddress addr = addresses.at(i);
        if(protocol == Socket::IPv4Protocol && addr.protocol() != QAbstractSocket::IPv4Protocol) {
            continue;
        }
        if(protocol == Socket::IPv6Protocol && addr.protocol() != QAbstractSocket::IPv6Protocol) {
            continue;
        }
        done = connect(addr, port);
        if(done)
            return true;
    }
    if(error == Socket::NoError) {
        setError(Socket::HostNotFoundError, QStringLiteral("Host not found."));
    }
    return false;
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
    switch (errorString)
    {
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
    default:
        socketErrorString = QString();
    }
    this->errorString = socketErrorString;
}

QString SocketPrivate::getErrorString() const
{
    return errorString;
}

Socket::Socket(NetworkLayerProtocol protocol, SocketType type)
    :d_ptr(new SocketPrivate(protocol, type, this))
{

}

Socket::Socket(qintptr socketDescriptor)
    :d_ptr(new SocketPrivate(socketDescriptor, this))
{
}

Socket::~Socket()
{
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

QHostAddress Socket::localAddress() const
{
    Q_D(const Socket);
    return d->localAddress;
}

quint16 Socket::localPort() const
{
    Q_D(const Socket);
    return d->localPort;
}

QHostAddress Socket::peerAddress() const
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

qintptr	Socket::fileno() const
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

Socket::NetworkLayerProtocol Socket::protocol() const
{
    Q_D(const Socket);
    return d->protocol;
}


Socket *Socket::accept()
{
    Q_D(Socket);
    return d->accept();
}

bool Socket::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    Q_D(Socket);
    return d->bind(address, port, mode);
}

bool Socket::bind(quint16 port, Socket::BindMode mode)
{
    Q_D(Socket);
    return d->bind(port, mode);
}

bool Socket::connect(const QHostAddress &host, quint16 port)
{
    Q_D(Socket);
    return d->connect(host, port);
}

bool Socket::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    Q_D(Socket);
    return d->connect(hostName, port, protocol);
}

bool Socket::close()
{
    Q_D(Socket);
    return d->close();
}

bool Socket::listen(int backlog)
{
    Q_D(Socket);
    return d->listen(backlog);
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

qint64 Socket::recv(char *data, qint64 size)
{
    Q_D(Socket);
    return d->recv(data, size, false);
}

qint64 Socket::recvall(char *data, qint64 size)
{
    Q_D(Socket);
    return d->recv(data, size, true);
}

qint64 Socket::send(const char *data, qint64 size)
{
    Q_D(Socket);
    qint64 bytesSent = d->send(data, size, false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 Socket::sendall(const char *data, qint64 size)
{
    Q_D(Socket);
    return d->send(data, size, true);
}

qint64 Socket::recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    return d->recvfrom(data, size, addr, port);
}

qint64 Socket::sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)
{
    Q_D(Socket);
    return d->sendto(data, size, addr, port);
}

QByteArray Socket::recv(qint64 size)
{
    Q_D(Socket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), false);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

QByteArray Socket::recvall(qint64 size)
{
    Q_D(Socket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), true);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint64 Socket::send(const QByteArray &data)
{
    Q_D(Socket);
    qint64 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 Socket::sendall(const QByteArray &data)
{
    Q_D(Socket);
    return d->send(data.data(), data.size(), true);
}


QByteArray Socket::recvfrom(qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    QByteArray bs;
    bs.resize(size);
    qint64 bytes = d->recvfrom(bs.data(), size, addr, port);
    if(bytes > 0)
    {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint64 Socket::sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)
{
    Q_D(Socket);
    return d->sendto(data.data(), data.size(), addr, port);
}

QList<QHostAddress> Socket::resolve(const QString &hostName)
{
//    static QMap<QString, QList<QHostAddress>> cache;
//    if(cache.contains(hostName)) {
//        return cache.value(hostName);
//    }

    QHostAddress tmp;
    if(tmp.setAddress(hostName)) {
        QList<QHostAddress> result;
        result.append(tmp);
//        cache.insert(hostName, result);
        return result;
    }

    std::function<QHostInfo()> task = [hostName](){
        const QHostInfo &info = QHostInfo::fromName(hostName);
        return info;
    };

    QHostInfo hostInfo = callInThread<QHostInfo>(task);
    //QHostInfo hostInfo = QHostInfo::fromName(hostName);
    const QList<QHostAddress> &result = hostInfo.addresses();
//    cache.insert(hostName, result);
    return result;
}

void Socket::setDnsCache(QSharedPointer<SocketDnsCache> dnsCache)
{
    Q_D(Socket);
    d->dnsCache = dnsCache;
}

class PollPrivate
{
public:
    PollPrivate(Poll * parent);
    ~PollPrivate();
public:
    void add(Socket *socket, EventLoopCoroutine::EventType event);
    void remove(Socket *socket);
    Socket *wait(qint64 msecs);
private:
    Poll * const q_ptr;
    QMap<Socket*, int> watchers;
    QSet<Socket*> events;
    Event done;
    Q_DECLARE_PUBLIC(Poll)
};

struct PollFunctor: public Functor
{
    PollFunctor(Event &done, QSet<Socket*> &events);
    virtual void operator()();
    Event &done;
    QSet<Socket*> &events;
    Socket *socket;
};

PollFunctor::PollFunctor(Event &done, QSet<Socket*> &events)
    :done(done), events(events), socket(0)
{}

void PollFunctor::operator ()()
{
    if(socket)
        events.insert(socket);
    done.set();
}

PollPrivate::PollPrivate(Poll *parent)
    :q_ptr(parent)
{}

PollPrivate::~PollPrivate()
{
    QMapIterator<Socket*, int> itor(watchers);
    while(itor.hasNext())
    {
        EventLoopCoroutine::get()->removeWatcher(itor.value());
    }
}

void PollPrivate::add(Socket *socket, EventLoopCoroutine::EventType event)
{
    if(watchers.contains(socket))
    {
        remove(socket);
    }
    PollFunctor *callback = new PollFunctor(done, events);
    int watcherId = EventLoopCoroutine::get()->createWatcher(event, socket->fileno(), callback);
    callback->socket = socket;
    watchers.insert(socket, watcherId);
}

void PollPrivate::remove(Socket *socket)
{
    int watcherId = watchers.value(socket, 0);
    if(!watcherId)
        return;
    EventLoopCoroutine::get()->removeWatcher(watcherId);
    watchers.remove(socket);
}

Socket *PollPrivate::wait(qint64 msecs)
{
    if(!events.isEmpty())
    {
        QMutableSetIterator<Socket*> itor(events);
        Socket *socket = itor.next();
        itor.remove();
        return socket;
    }
    Timeout timeout(msecs);
    Q_UNUSED(timeout);
    try
    {
        done.wait();
    }
    catch(TimeoutException &)
    {
        return 0;
    }
    if(!events.isEmpty())
    {
        // is there some one hungry?
        QMutableSetIterator<Socket*> itor(events);
        Socket *socket = itor.next();
        itor.remove();
        return socket;
    }
    else
    {
        return 0;
    }
}

Poll::Poll()
    :d_ptr(new PollPrivate(this))
{}

Poll::~Poll()
{
    delete d_ptr;
}

void Poll::add(Socket *socket, EventLoopCoroutine::EventType event)
{
    Q_D(Poll);
    d->add(socket, event);
}

void Poll::remove(Socket *socket)
{
    Q_D(Poll);
    d->remove(socket);
}

Socket *Poll::wait(qint64 msecs)
{
    Q_D(Poll);
    return d->wait(msecs);
}

class SocketDnsCachePrivate
{
public:
    SocketDnsCachePrivate()
        :cache(1024)
    {

    }

    QCache<QString, QList<QHostAddress>> cache;
};

SocketDnsCache::SocketDnsCache()
    :d_ptr(new SocketDnsCachePrivate())
{
}

SocketDnsCache::~SocketDnsCache()
{
    delete d_ptr;
}

QList<QHostAddress> SocketDnsCache::resolve(const QString &hostName)
{
    Q_D(SocketDnsCache);
    if(d->cache.contains(hostName)) {
        return *(d->cache.object(hostName));
    }
    QList<QHostAddress> *addresses = new QList<QHostAddress>();
    *addresses = Socket::resolve(hostName);
    if(addresses->isEmpty()) {
        delete addresses;
        return QList<QHostAddress>();
    } else {
        d->cache.insert(hostName, addresses);
        return *addresses;
    }
}

QTNETWORKNG_NAMESPACE_END
