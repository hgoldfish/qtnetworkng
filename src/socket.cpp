#include <QtCore/qthread.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qmap.h>
#include <QtCore/qcache.h>
#include "../include/private/socket_p.h"
#include "../include/coroutine_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

SocketPrivate::SocketPrivate(Socket::NetworkLayerProtocol protocol,
        Socket::SocketType type, Socket *parent)
    :q_ptr(parent), protocol(protocol), type(type), error(Socket::NoError),
      state(Socket::UnconnectedState), readGate(new Gate), writeGate(new Gate)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    if(!createSocket())
        return;
    if(type == Socket::UdpSocket) {
        if(!setOption(Socket::BroadcastSocketOption, 1)) {
//            setError(Socket::UnsupportedSocketOperationError);
//            close();
//            return;
        }
        setOption(Socket::ReceivePacketInformation, 1);
        setOption(Socket::ReceiveHopLimit, 1);
    }
}


SocketPrivate::SocketPrivate(qintptr socketDescriptor, Socket *parent)
    :q_ptr(parent), error(Socket::NoError), readGate(new Gate), writeGate(new Gate)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    fd = static_cast<int>(socketDescriptor);
    setNonblocking();
    if(!isValid())
        return;
    // FIXME determine the type and state of socket
    protocol = Socket::AnyIPProtocol;
    type = Socket::TcpSocket;
    state = Socket::ConnectedState;
    fetchConnectionParameters();
    if (type == Socket::UdpSocket) {
        state = Socket::UnconnectedState;
    }
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
    if (state != Socket::UnconnectedState && state != Socket::BoundState) {
        return false;
    }
    Socket::SocketState oldState = state;
    state = Socket::HostLookupState;
    QList<QHostAddress> addresses;
    QHostAddress t;
    if (t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if(dnsCache.isNull()) {
            addresses = Socket::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }

    if (addresses.isEmpty()) {
        state = oldState;
        setError(Socket::HostNotFoundError, QStringLiteral("Host not found."));
        return false;
    }
    bool done = true;
    state = oldState;
    for (int i = 0; i < addresses.size(); ++i) {
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
    if (error == Socket::NoError) {
        setError(Socket::HostNotFoundError, QStringLiteral("Host not found."));
    }
    state = oldState;
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
    }
    this->errorString = socketErrorString;
}


QString SocketPrivate::getErrorString() const
{
    return errorString;
}


Socket::Socket(NetworkLayerProtocol protocol, SocketType type)
    :dd_ptr(new SocketPrivate(protocol, type, this))
{

}


Socket::Socket(qintptr socketDescriptor)
    :dd_ptr(new SocketPrivate(socketDescriptor, this))
{
}


Socket::~Socket()
{
    delete dd_ptr;
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


class ScopedGate
{
public:
    ScopedGate(QSharedPointer<Gate> gate)
        :gate(gate)
    {
        if (gate.isNull()) {
            success = false;
            return;
        }
        success = gate->wait();
        if (success) {
            gate->close();
        }
    }
    ~ScopedGate()
    {
        if (success && !gate.isNull()) {
            gate.data()->open();
        }
    }
    bool isSuccess() { return success; }
private:
    QWeakPointer<Gate> gate;
    bool success;
};


Socket *Socket::accept()
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return nullptr;
    }
    return d->accept();
}


bool Socket::bind(const QHostAddress &address, quint16 port, Socket::BindMode mode)
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
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->connect(host, port);
}


bool Socket::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
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


qint32 Socket::recv(char *data, qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, false);
}


qint32 Socket::recvall(char *data, qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, true);
}


qint32 Socket::send(const char *data, qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    qint32 bytesSent = d->send(data, size, false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}


qint32 Socket::sendall(const char *data, qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->send(data, size, true);
}


qint32 Socket::recvfrom(char *data, qint32 size, QHostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->recvfrom(data, size, addr, port);
}


qint32 Socket::sendto(const char *data, qint32 size, const QHostAddress &addr, quint16 port)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->sendto(data, size, addr, port);
}


QByteArray Socket::recv(qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recv(bs.data(), bs.size(), false);
    if(bytes > 0) {
        bs.resize(static_cast<int>(bytes));
        return bs;
    }
    return QByteArray();
}


QByteArray Socket::recvall(qint32 size)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recv(bs.data(), bs.size(), true);
    if(bytes > 0) {
        bs.resize(static_cast<int>(bytes));
        return bs;
    }
    return QByteArray();
}


qint32 Socket::send(const QByteArray &data)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    qint32 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}


qint32 Socket::sendall(const QByteArray &data)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
    return d->send(data.data(), data.size(), true);
}


QByteArray Socket::recvfrom(qint32 size, QHostAddress *addr, quint16 *port)
{
    Q_D(Socket);
    ScopedGate gate(d->readGate);
    if (!gate.isSuccess()) {
        return QByteArray();
    }
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = d->recvfrom(bs.data(), size, addr, port);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}


qint32 Socket::sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)
{
    Q_D(Socket);
    ScopedGate gate(d->writeGate);
    if (!gate.isSuccess()) {
        return -1;
    }
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
    PollPrivate();
    ~PollPrivate();
public:
    void add(Socket *socket, EventLoopCoroutine::EventType event);
    void remove(Socket *socket);
    Socket *wait(float secs);
private:
    QMap<Socket*, int> watchers;
    QSharedPointer<QSet<Socket*>> events;
    QSharedPointer<Event> done;
};


struct PollFunctor: public Functor
{
    PollFunctor(QSharedPointer<QSet<Socket*>> events, QSharedPointer<Event> done, Socket *socket);
    virtual void operator()();
    QSharedPointer<QSet<Socket*>> events;
    QSharedPointer<Event> done;
    QPointer<Socket> socket;
};


PollFunctor::PollFunctor(QSharedPointer<QSet<Socket*>> events, QSharedPointer<Event> done, Socket *socket)
    :events(events), done(done), socket(socket)
{}


void PollFunctor::operator ()()
{
    if(!socket.isNull()) {
        events->insert(socket.data());
        done->set();
    }
}


PollPrivate::PollPrivate()
    :events(new QSet<Socket*>()), done(new Event())
{}


PollPrivate::~PollPrivate()
{
    QMapIterator<Socket*, int> itor(watchers);
    while(itor.hasNext()) {
        EventLoopCoroutine::get()->removeWatcher(itor.value());
    }
}


void PollPrivate::add(Socket *socket, EventLoopCoroutine::EventType event)
{
    if(watchers.contains(socket)) {
        remove(socket);
    }
    PollFunctor *callback = new PollFunctor(events, done, socket);
    int watcherId = EventLoopCoroutine::get()->createWatcher(event, socket->fileno(), callback);
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


Socket *PollPrivate::wait(float secs)
{
    if(!events->isEmpty()) {
        QMutableSetIterator<Socket*> itor(*events);
        Socket *socket = itor.next();
        itor.remove();
        return socket;
    }
    try {
        Timeout timeout(secs); Q_UNUSED(timeout);
        done->wait();
    } catch(TimeoutException &) {
        return nullptr;
    }
    if(!events->isEmpty()) {
        // is there some one hungry?
        QMutableSetIterator<Socket*> itor(*events);
        Socket *socket = itor.next();
        itor.remove();
        return socket;
    } else {
        return nullptr;
    }
}


Poll::Poll()
    :d_ptr(new PollPrivate())
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


Socket *Poll::wait(float secs)
{
    Q_D(Poll);
    return d->wait(secs);
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
