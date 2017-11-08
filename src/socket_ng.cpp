#include <QThread>
#include <QCoreApplication>
#include <QMap>
#include <QCache>
#include "../include/socket_ng_p.h"
#include "../include/coroutine_utils.h"

QSocketNgPrivate::QSocketNgPrivate(QSocketNg::NetworkLayerProtocol protocol,
        QSocketNg::SocketType type, QSocketNg *parent)
    :q_ptr(parent), protocol(protocol), type(type), error(QSocketNg::NoError),
      state(QSocketNg::UnconnectedState)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    if(!createSocket())
        return;
    if(type == QSocketNg::UdpSocket)
    {
        if(!setOption(QSocketNg::BroadcastSocketOption, 1))
        {
//            setError(QSocketNg::UnsupportedSocketOperationError);
//            close();
//            return;
        }
        setOption(QSocketNg::ReceivePacketInformation, 1);
        setOption(QSocketNg::ReceiveHopLimit, 1);
    }
}

QSocketNgPrivate::QSocketNgPrivate(qintptr socketDescriptor, QSocketNg *parent)
    :q_ptr(parent), error(QSocketNg::NoError)
{
#ifdef Q_OS_WIN
    initWinSock();
#endif
    fd = socketDescriptor;
    setNonblocking();
    if(!isValid())
        return;
    // FIXME determine the type and state of socket
    protocol = QSocketNg::AnyIPProtocol;
    type = QSocketNg::TcpSocket;
    state = QSocketNg::ConnectedState;
    fetchConnectionParameters();
}

QSocketNgPrivate::~QSocketNgPrivate()
{
    close();
#ifdef Q_OS_WIN
    freeWinSock();
#endif
}

bool QSocketNgPrivate::bind(quint16 port, QSocketNg::BindMode mode)
{
    return bind(QHostAddress(QHostAddress::Any), port, mode);
}

bool QSocketNgPrivate::connect(const QString &hostName, quint16 port, QSocketNg::NetworkLayerProtocol protocol)
{
    state = QSocketNg::HostLookupState;
    QList<QHostAddress> addresses;
    QHostAddress t;
    if(t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if(dnsCache.isNull()) {
            addresses = QSocketNg::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }

    if(addresses.isEmpty()) {
        state = QSocketNg::UnconnectedState;
        setError(QSocketNg::HostNotFoundError, QString::fromUtf8("Host not found."));
        return false;
    }
    bool done = true;
    state = QSocketNg::UnconnectedState;
    for(int i = 0; i < addresses.size(); ++i) {
        QHostAddress addr = addresses.at(i);
        if(protocol == QSocketNg::IPv4Protocol && addr.protocol() != QAbstractSocket::IPv4Protocol) {
            continue;
        }
        if(protocol == QSocketNg::IPv6Protocol && addr.protocol() != QAbstractSocket::IPv6Protocol) {
            continue;
        }
        done = connect(addr, port);
        if(done)
            return true;
    }
    if(error == QSocketNg::NoError) {
        setError(QSocketNg::HostNotFoundError, QString::fromUtf8("Host not found."));
    }
    return false;
}

void QSocketNgPrivate::setError(QSocketNg::SocketError error, const QString &errorString)
{
    this->error = error;
    this->errorString = errorString;
}

void QSocketNgPrivate::setError(QSocketNg::SocketError error, ErrorString errorString)
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

QString QSocketNgPrivate::getErrorString() const
{
    return errorString;
}

QSocketNg::QSocketNg(NetworkLayerProtocol protocol, SocketType type)
    :d_ptr(new QSocketNgPrivate(protocol, type, this))
{

}

QSocketNg::QSocketNg(qintptr socketDescriptor)
    :d_ptr(new QSocketNgPrivate(socketDescriptor, this))
{
}

QSocketNg::~QSocketNg()
{
    delete d_ptr;
}

QSocketNg::SocketError QSocketNg::error() const
{
    Q_D(const QSocketNg);
    return d->error;
}

QString QSocketNg::errorString() const
{
    Q_D(const QSocketNg);
    return d->getErrorString();
}

bool QSocketNg::isValid() const
{
    Q_D(const QSocketNg);
    return d->isValid();
}

QHostAddress QSocketNg::localAddress() const
{
    Q_D(const QSocketNg);
    return d->localAddress;
}

quint16 QSocketNg::localPort() const
{
    Q_D(const QSocketNg);
    return d->localPort;
}

QHostAddress QSocketNg::peerAddress() const
{
    Q_D(const QSocketNg);
    return d->peerAddress;
}

QString QSocketNg::peerName() const
{
    return QString();
}

quint16 QSocketNg::peerPort() const
{
    Q_D(const QSocketNg);
    return d->peerPort;
}

qintptr	QSocketNg::fileno() const
{
    Q_D(const QSocketNg);
    return d->fd;
}

QSocketNg::SocketType QSocketNg::type() const
{
    Q_D(const QSocketNg);
    return d->type;
}

QSocketNg::SocketState QSocketNg::state() const
{
    Q_D(const QSocketNg);
    return d->state;
}

QSocketNg *QSocketNg::accept()
{
    Q_D(QSocketNg);
    return d->accept();
}

bool QSocketNg::bind(QHostAddress &address, quint16 port, QSocketNg::BindMode mode)
{
    Q_D(QSocketNg);
    return d->bind(address, port, mode);
}

bool QSocketNg::bind(quint16 port, QSocketNg::BindMode mode)
{
    Q_D(QSocketNg);
    return d->bind(port, mode);
}

bool QSocketNg::connect(const QHostAddress &host, quint16 port)
{
    Q_D(QSocketNg);
    return d->connect(host, port);
}

bool QSocketNg::connect(const QString &hostName, quint16 port, QSocketNg::NetworkLayerProtocol protocol)
{
    Q_D(QSocketNg);
    return d->connect(hostName, port, protocol);
}

bool QSocketNg::close()
{
    Q_D(QSocketNg);
    return d->close();
}

bool QSocketNg::listen(int backlog)
{
    Q_D(QSocketNg);
    return d->listen(backlog);
}

bool QSocketNg::setOption(QSocketNg::SocketOption option, const QVariant &value)
{
    Q_D(QSocketNg);
    return d->setOption(option, value);
}

QVariant QSocketNg::option(QSocketNg::SocketOption option) const
{
    Q_D(const QSocketNg);
    return d->option(option);
}

qint64 QSocketNg::recv(char *data, qint64 size)
{
    Q_D(QSocketNg);
    return d->recv(data, size);
}

qint64 QSocketNg::send(const char *data, qint64 size)
{
    Q_D(QSocketNg);
    qint64 bytesSent = d->send(data, size, false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 QSocketNg::sendall(const char *data, qint64 size)
{
    Q_D(QSocketNg);
    return d->send(data, size, true);
}

qint64 QSocketNg::recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(QSocketNg);
    return d->recvfrom(data, size, addr, port);
}

qint64 QSocketNg::sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)
{
    Q_D(QSocketNg);
    return d->sendto(data, size, addr, port);
}

QByteArray QSocketNg::recv(qint64 size)
{
    Q_D(QSocketNg);
    QByteArray bs;
    bs.resize(size);

    qint64 bytes = d->recv(bs.data(), bs.size());
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint64 QSocketNg::send(const QByteArray &data)
{
    Q_D(QSocketNg);
    qint64 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

qint64 QSocketNg::sendall(const QByteArray &data)
{
    Q_D(QSocketNg);
    return d->send(data.data(), data.size(), true);
}


QByteArray QSocketNg::recvfrom(qint64 size, QHostAddress *addr, quint16 *port)
{
    Q_D(QSocketNg);
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

qint64 QSocketNg::sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)
{
    Q_D(QSocketNg);
    return d->sendto(data.data(), data.size(), addr, port);
}

QList<QHostAddress> QSocketNg::resolve(const QString &hostName)
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

void QSocketNg::setDnsCache(QSharedPointer<QSocketNgDnsCache> dnsCache)
{
    Q_D(QSocketNg);
    d->dnsCache = dnsCache;
}

class PollPrivate
{
public:
    PollPrivate(Poll * parent);
    ~PollPrivate();
public:
    void add(QSocketNg *socket, EventLoopCoroutine::EventType event);
    void remove(QSocketNg *socket);
    QSocketNg *wait(qint64 msecs);
private:
    Poll * const q_ptr;
    QMap<QSocketNg*, int> watchers;
    QSet<QSocketNg*> events;
    Event done;
    Q_DECLARE_PUBLIC(Poll)
};

struct PollFunctor: public Functor
{
    PollFunctor(Event &done, QSet<QSocketNg*> &events);
    virtual void operator()();
    Event &done;
    QSet<QSocketNg*> &events;
    QSocketNg *socket;
};

PollFunctor::PollFunctor(Event &done, QSet<QSocketNg*> &events)
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
    QMapIterator<QSocketNg*, int> itor(watchers);
    while(itor.hasNext())
    {
        EventLoopCoroutine::get()->removeWatcher(itor.value());
    }
}

void PollPrivate::add(QSocketNg *socket, EventLoopCoroutine::EventType event)
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

void PollPrivate::remove(QSocketNg *socket)
{
    int watcherId = watchers.value(socket, 0);
    if(!watcherId)
        return;
    EventLoopCoroutine::get()->removeWatcher(watcherId);
    watchers.remove(socket);
}

QSocketNg *PollPrivate::wait(qint64 msecs)
{
    if(!events.isEmpty())
    {
        QMutableSetIterator<QSocketNg*> itor(events);
        QSocketNg *socket = itor.next();
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
        QMutableSetIterator<QSocketNg*> itor(events);
        QSocketNg *socket = itor.next();
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

void Poll::add(QSocketNg *socket, EventLoopCoroutine::EventType event)
{
    Q_D(Poll);
    d->add(socket, event);
}

void Poll::remove(QSocketNg *socket)
{
    Q_D(Poll);
    d->remove(socket);
}

QSocketNg *Poll::wait(qint64 msecs)
{
    Q_D(Poll);
    return d->wait(msecs);
}

class QSocketNgDnsCachePrivate
{
public:
    QSocketNgDnsCachePrivate()
        :cache(1024)
    {

    }

    QCache<QString, QList<QHostAddress>> cache;
};

QSocketNgDnsCache::QSocketNgDnsCache()
    :d_ptr(new QSocketNgDnsCachePrivate())
{
}

QSocketNgDnsCache::~QSocketNgDnsCache()
{
    delete d_ptr;
}

QList<QHostAddress> QSocketNgDnsCache::resolve(const QString &hostName)
{
    Q_D(QSocketNgDnsCache);
    if(d->cache.contains(hostName)) {
        return *(d->cache.object(hostName));
    }
    QList<QHostAddress> *addresses = new QList<QHostAddress>();
    *addresses = QSocketNg::resolve(hostName);
    if(addresses->isEmpty()) {
        delete addresses;
        return QList<QHostAddress>();
    } else {
        d->cache.insert(hostName, addresses);
        return *addresses;
    }
}
