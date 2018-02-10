#include <QtCore/qthread.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qmap.h>
#include <QtCore/qcache.h>
#include "../include/socket_p.h"
#include "../include/coroutine_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

QSocketPrivate::QSocketPrivate(QSocket::NetworkLayerProtocol protocol,
        QSocket::SocketType type, QSocket *parent)
    :q_ptr(parent), protocol(protocol), type(type), error(QSocket::NoError),
      state(QSocket::UnconnectedState)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    if(!createSocket())
        return;
    if(type == QSocket::UdpSocket)
    {
        if(!setOption(QSocket::BroadcastSocketOption, 1))
        {
//            setError(QSocket::UnsupportedSocketOperationError);
//            close();
//            return;
        }
        setOption(QSocket::ReceivePacketInformation, 1);
        setOption(QSocket::ReceiveHopLimit, 1);
    }
}

QSocketPrivate::QSocketPrivate(qintptr socketDescriptor, QSocket *parent)
    :q_ptr(parent), error(QSocket::NoError)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    fd = socketDescriptor;
    setNonblocking();
    if(!isValid())
        return;
    // FIXME determine the type and state of socket
    protocol = QSocket::AnyIPProtocol;
    type = QSocket::TcpSocket;
    state = QSocket::ConnectedState;
    fetchConnectionParameters();
}

QSocketPrivate::~QSocketPrivate()
{
    close();
#ifdef Q_OS_WIN
    freeWinSock();
#endif
}

bool QSocketPrivate::bind(quint16 port, QSocket::BindMode mode)
{
    return bind(QHostAddress(QHostAddress::Any), port, mode);
}

bool QSocketPrivate::connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol)
{
    state = QSocket::HostLookupState;
    QList<QHostAddress> addresses;
    QHostAddress t;
    if(t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if(dnsCache.isNull()) {
            addresses = QSocket::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }

    if(addresses.isEmpty()) {
        state = QSocket::UnconnectedState;
        setError(QSocket::HostNotFoundError, QString::fromUtf8("Host not found."));
        return false;
    }
    bool done = true;
    state = QSocket::UnconnectedState;
    for(int i = 0; i < addresses.size(); ++i) {
        QHostAddress addr = addresses.at(i);
        if(protocol == QSocket::IPv4Protocol && addr.protocol() != QAbstractSocket::IPv4Protocol) {
            continue;
        }
        if(protocol == QSocket::IPv6Protocol && addr.protocol() != QAbstractSocket::IPv6Protocol) {
            continue;
        }
        done = connect(addr, port);
        if(done)
            return true;
    }
    if(error == QSocket::NoError) {
        setError(QSocket::HostNotFoundError, QString::fromUtf8("Host not found."));
    }
    return false;
}

void QSocketPrivate::setError(QSocket::SocketError error, const QString &errorString)
{
    this->error = error;
    this->errorString = errorString;
}

void QSocketPrivate::setError(QSocket::SocketError error, ErrorString errorString)
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

QString QSocketPrivate::getErrorString() const
{
    return errorString;
}

QSocket::QSocket(NetworkLayerProtocol protocol, SocketType type)
    :d_ptr(new QSocketPrivate(protocol, type, this))
{

}

QSocket::QSocket(qintptr socketDescriptor)
    :d_ptr(new QSocketPrivate(socketDescriptor, this))
{
}

QSocket::~QSocket()
{
    delete d_ptr;
}

QSocket::SocketError QSocket::error() const
{
    Q_D(const QSocket);
    return d->error;
}

QString QSocket::errorString() const
{
    Q_D(const QSocket);
    return d->getErrorString();
}

bool QSocket::isValid() const
{
    Q_D(const QSocket);
    return d->isValid();
}

QHostAddress QSocket::localAddress() const
{
    Q_D(const QSocket);
    return d->localAddress;
}

quint16 QSocket::localPort() const
{
    Q_D(const QSocket);
    return d->localPort;
}

QHostAddress QSocket::peerAddress() const
{
    Q_D(const QSocket);
    return d->peerAddress;
}

QString QSocket::peerName() const
{
    return QString();
}

quint16 QSocket::peerPort() const
{
    Q_D(const QSocket);
    return d->peerPort;
}

qintptr	QSocket::fileno() const
{
    Q_D(const QSocket);
    return d->fd;
}

QSocket::SocketType QSocket::type() const
{
    Q_D(const QSocket);
    return d->type;
}

QSocket::SocketState QSocket::state() const
{
    Q_D(const QSocket);
    return d->state;
}

QSocket::NetworkLayerProtocol QSocket::protocol() const
{
    Q_D(const QSocket);
    return d->protocol;
}


QSocket *QSocket::accept()
{
    Q_D(QSocket);
    return d->accept();
}

bool QSocket::bind(QHostAddress &address, quint16 port, QSocket::BindMode mode)
{
    Q_D(QSocket);
    return d->bind(address, port, mode);
}

bool QSocket::bind(quint16 port, QSocket::BindMode mode)
{
    Q_D(QSocket);
    return d->bind(port, mode);
}

bool QSocket::connect(const QHostAddress &host, quint16 port)
{
    Q_D(QSocket);
    return d->connect(host, port);
}

bool QSocket::connect(const QString &hostName, quint16 port, QSocket::NetworkLayerProtocol protocol)
{
    Q_D(QSocket);
    return d->connect(hostName, port, protocol);
}

bool QSocket::close()
{
    Q_D(QSocket);
    return d->close();
}

bool QSocket::listen(int backlog)
{
    Q_D(QSocket);
    return d->listen(backlog);
}

bool QSocket::setOption(QSocket::SocketOption option, const QVariant &value)
{
    Q_D(QSocket);
    return d->setOption(option, value);
}

QVariant QSocket::option(QSocket::SocketOption option) const
{
    Q_D(const QSocket);
    return d->option(option);
}

qint64 QSocket::recv(char *data, qint64 size)
{
    Q_D(QSocket);
    return d->recv(data, size, false);
}

qint64 QSocket::recvall(char *data, qint64 size)
{
    Q_D(QSocket);
    return d->recv(data, size, true);
}

qint64 QSocket::send(const char *data, qint64 size)
{
    Q_D(QSocket);
    qint64 bytesSent = d->send(data, size, false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 QSocket::sendall(const char *data, qint64 size)
{
    Q_D(QSocket);
    return d->send(data, size, true);
}

qint64 QSocket::recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(QSocket);
    return d->recvfrom(data, size, addr, port);
}

qint64 QSocket::sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)
{
    Q_D(QSocket);
    return d->sendto(data, size, addr, port);
}

QByteArray QSocket::recv(qint64 size)
{
    Q_D(QSocket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), false);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

QByteArray QSocket::recvall(qint64 size)
{
    Q_D(QSocket);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size(), true);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint64 QSocket::send(const QByteArray &data)
{
    Q_D(QSocket);
    qint64 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 QSocket::sendall(const QByteArray &data)
{
    Q_D(QSocket);
    return d->send(data.data(), data.size(), true);
}


QByteArray QSocket::recvfrom(qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(QSocket);
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

qint64 QSocket::sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)
{
    Q_D(QSocket);
    return d->sendto(data.data(), data.size(), addr, port);
}

QList<QHostAddress> QSocket::resolve(const QString &hostName)
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

void QSocket::setDnsCache(QSharedPointer<QSocketDnsCache> dnsCache)
{
    Q_D(QSocket);
    d->dnsCache = dnsCache;
}

class PollPrivate
{
public:
    PollPrivate(Poll * parent);
    ~PollPrivate();
public:
    void add(QSocket *socket, EventLoopCoroutine::EventType event);
    void remove(QSocket *socket);
    QSocket *wait(qint64 msecs);
private:
    Poll * const q_ptr;
    QMap<QSocket*, int> watchers;
    QSet<QSocket*> events;
    Event done;
    Q_DECLARE_PUBLIC(Poll)
};

struct PollFunctor: public Functor
{
    PollFunctor(Event &done, QSet<QSocket*> &events);
    virtual void operator()();
    Event &done;
    QSet<QSocket*> &events;
    QSocket *socket;
};

PollFunctor::PollFunctor(Event &done, QSet<QSocket*> &events)
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
    QMapIterator<QSocket*, int> itor(watchers);
    while(itor.hasNext())
    {
        EventLoopCoroutine::get()->removeWatcher(itor.value());
    }
}

void PollPrivate::add(QSocket *socket, EventLoopCoroutine::EventType event)
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

void PollPrivate::remove(QSocket *socket)
{
    int watcherId = watchers.value(socket, 0);
    if(!watcherId)
        return;
    EventLoopCoroutine::get()->removeWatcher(watcherId);
    watchers.remove(socket);
}

QSocket *PollPrivate::wait(qint64 msecs)
{
    if(!events.isEmpty())
    {
        QMutableSetIterator<QSocket*> itor(events);
        QSocket *socket = itor.next();
        itor.remove();
        return socket;
    }
    QTimeout timeout(msecs);
    Q_UNUSED(timeout);
    try
    {
        done.wait();
    }
    catch(QTimeoutException &)
    {
        return 0;
    }
    if(!events.isEmpty())
    {
        // is there some one hungry?
        QMutableSetIterator<QSocket*> itor(events);
        QSocket *socket = itor.next();
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

void Poll::add(QSocket *socket, EventLoopCoroutine::EventType event)
{
    Q_D(Poll);
    d->add(socket, event);
}

void Poll::remove(QSocket *socket)
{
    Q_D(Poll);
    d->remove(socket);
}

QSocket *Poll::wait(qint64 msecs)
{
    Q_D(Poll);
    return d->wait(msecs);
}

class QSocketDnsCachePrivate
{
public:
    QSocketDnsCachePrivate()
        :cache(1024)
    {

    }

    QCache<QString, QList<QHostAddress>> cache;
};

QSocketDnsCache::QSocketDnsCache()
    :d_ptr(new QSocketDnsCachePrivate())
{
}

QSocketDnsCache::~QSocketDnsCache()
{
    delete d_ptr;
}

QList<QHostAddress> QSocketDnsCache::resolve(const QString &hostName)
{
    Q_D(QSocketDnsCache);
    if(d->cache.contains(hostName)) {
        return *(d->cache.object(hostName));
    }
    QList<QHostAddress> *addresses = new QList<QHostAddress>();
    *addresses = QSocket::resolve(hostName);
    if(addresses->isEmpty()) {
        delete addresses;
        return QList<QHostAddress>();
    } else {
        d->cache.insert(hostName, addresses);
        return *addresses;
    }
}

QTNETWORKNG_NAMESPACE_END
