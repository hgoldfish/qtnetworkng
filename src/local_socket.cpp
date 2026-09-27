#include "../include/private/local_socket_p.h"
#include "../include/socket_utils.h"
#include "../include/coroutine_utils.h"
#include "debugger.h"
#include <QtCore/qdir.h>

QTNG_LOGGER("qtng.local_socket");

QTNETWORKNG_NAMESPACE_BEGIN

LocalSocketPrivate::LocalSocketPrivate(LocalSocket *parent)
    : q_ptr(parent)
    , error(Socket::NoError)
    , state(Socket::UnconnectedState)
#ifdef Q_OS_WIN
    , fd(0)
    , acceptWait(nullptr)
    , acceptArmed(false)
    , acceptGeneration(0)
    , ownsHandle(true)
#else
    , fd(-1)
    , unlinkPath()
    , shouldUnlink(false)
#endif
{
}

LocalSocketPrivate::LocalSocketPrivate(qintptr socketDescriptor, LocalSocket *parent)
    : LocalSocketPrivate(parent)
{
    setSocketDescriptor(socketDescriptor);
}

LocalSocketPrivate::~LocalSocketPrivate()
{
    // abort() skips the lock drain: close() would tryAcquire while another
    // coroutine may still hold a lock, and we must not hang in a destructor.
    abort();
#ifdef Q_OS_WIN
    releaseAcceptWait();
#endif
}

void LocalSocketPrivate::setError(Socket::SocketError error, const QString &errorString)
{
    this->error = error;
    this->errorString = errorString;
}

void LocalSocketPrivate::setError(Socket::SocketError error, ErrorString errorString)
{
    this->error = error;
    QString socketErrorString;
    switch (errorString) {
    case NonBlockingInitFailedErrorString:
        socketErrorString = QString::fromLatin1("Unable to initialize non-blocking socket");
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
    case InvalidSocketErrorString:
        socketErrorString = QString::fromLatin1("Invalid socket descriptor");
        break;
    case AccessErrorString:
        socketErrorString = QString::fromLatin1("Permission denied");
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
    case WriteErrorString:
        socketErrorString = QString::fromLatin1("Unable to write");
        break;
    case ReadErrorString:
        socketErrorString = QString::fromLatin1("Network error");
        break;
    case OutOfMemoryErrorString:
        socketErrorString = QString::fromLatin1("Out of memory");
        break;
    default:
        socketErrorString = QString::fromLatin1("Unknown error");
        break;
    }
    this->errorString = socketErrorString;
}

QString LocalSocketPrivate::getErrorString() const
{
    return errorString;
}

bool LocalSocketPrivate::isValid() const
{
    return checkState();
}

bool LocalSocketPrivate::checkState() const
{
    // Structural liveness only. A sticky error from a rejected call (e.g. bind()
    // while already Bound) must remain visible via error(), but must not make
    // accept()/recv()/send() pretend the socket is dead while fd and state are
    // still fine. close() sets Unconnected before draining, which is the hard
    // "stop new I/O" boundary.
    if (state == Socket::UnconnectedState) {
        return false;
    }
#ifdef Q_OS_WIN
    // INVALID_HANDLE_VALUE == (HANDLE)-1; also reject null handle.
    return fd != 0 && fd != -1;
#else
    return fd >= 0;
#endif
}

QString LocalSocketPrivate::makeFullServerName(const QString &name)
{
    if (name.isEmpty()) {
        return QString();
    }
    if (name.contains(QLatin1Char('/')) || name.contains(QLatin1Char('\\'))) {
#ifdef Q_OS_WIN
        QString n = name;
        n.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return n;
#else
        return name;
#endif
    }
#ifdef Q_OS_WIN
    return QString::fromLatin1("\\\\.\\pipe\\") + name;
#else
    return QDir::temp().absoluteFilePath(name + QString::fromLatin1(".sock"));
#endif
}

QString LocalSocketPrivate::localAddressURI() const
{
#ifdef Q_OS_WIN
    return QString::fromLatin1("pipe://") + (serverName.isEmpty() ? fullServerName : serverName);
#else
    return QString::fromLatin1("unix://") + fullServerName;
#endif
}

QString LocalSocketPrivate::peerAddressURI() const
{
    return localAddressURI();
}

bool LocalSocketPrivate::setOption(Socket::SocketOption, const QVariant &)
{
    return false;
}

QVariant LocalSocketPrivate::option(Socket::SocketOption) const
{
    return QVariant();
}

LocalSocket::LocalSocket()
    : d_ptr(new LocalSocketPrivate(this))
{
}

LocalSocket::LocalSocket(qintptr socketDescriptor)
    : d_ptr(new LocalSocketPrivate(socketDescriptor, this))
{
}

LocalSocket::LocalSocket(LocalSocketPrivate *d)
    : d_ptr(d)
{
    d_ptr->q_ptr = this;
}

LocalSocket::~LocalSocket()
{
    if (d_ptr->readLock.isLocked() || d_ptr->writeLock.isLocked()) {
        qtng_warning << "socket is deleted while receiving or sending.";
    }
    delete d_ptr;
}

Socket::SocketError LocalSocket::error() const
{
    Q_D(const LocalSocket);
    return d->error;
}

QString LocalSocket::errorString() const
{
    Q_D(const LocalSocket);
    return d->errorString;
}

bool LocalSocket::isValid() const
{
    Q_D(const LocalSocket);
    return d->isValid();
}

HostAddress LocalSocket::localAddress() const
{
    return HostAddress();
}

quint16 LocalSocket::localPort() const
{
    return 0;
}

HostAddress LocalSocket::peerAddress() const
{
    return HostAddress();
}

QString LocalSocket::peerName() const
{
    Q_D(const LocalSocket);
    return d->serverName;
}

quint16 LocalSocket::peerPort() const
{
    return 0;
}

qintptr LocalSocket::fileno() const
{
    Q_D(const LocalSocket);
    return static_cast<qintptr>(d->fd);
}

Socket::SocketType LocalSocket::type() const
{
    return Socket::LocalSocket;
}

Socket::SocketState LocalSocket::state() const
{
    Q_D(const LocalSocket);
    return d->state;
}

HostAddress::NetworkLayerProtocol LocalSocket::protocol() const
{
    return HostAddress::UnknownNetworkLayerProtocol;
}

QString LocalSocket::localAddressURI() const
{
    Q_D(const LocalSocket);
    return d->localAddressURI();
}

QString LocalSocket::peerAddressURI() const
{
    Q_D(const LocalSocket);
    return d->peerAddressURI();
}

QString LocalSocket::serverName() const
{
    Q_D(const LocalSocket);
    return d->serverName;
}

QString LocalSocket::fullServerName() const
{
    Q_D(const LocalSocket);
    return d->fullServerName;
}

LocalSocket *LocalSocket::accept()
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return nullptr;
    }
    return d->accept();
}

bool LocalSocket::bind(const QString &name, Socket::BindMode mode)
{
    Q_D(LocalSocket);
    return d->bind(name, mode);
}

bool LocalSocket::connect(const QString &name)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return false;
    }
    return d->connect(name);
}

void LocalSocket::close()
{
    Q_D(LocalSocket);
    d->close();
}

void LocalSocket::abort()
{
    Q_D(LocalSocket);
    d->abort();
}

bool LocalSocket::listen(int backlog)
{
    Q_D(LocalSocket);
    return d->listen(backlog);
}

bool LocalSocket::setOption(Socket::SocketOption option, const QVariant &value)
{
    Q_D(LocalSocket);
    return d->setOption(option, value);
}

QVariant LocalSocket::option(Socket::SocketOption option) const
{
    Q_D(const LocalSocket);
    return d->option(option);
}

qint32 LocalSocket::peek(char *data, qint32 size)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->peek(data, size);
}

qint32 LocalSocket::peekRaw(char *data, qint32 size)
{
    return peek(data, size);
}

qint32 LocalSocket::recv(char *data, qint32 size)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, false);
}

qint32 LocalSocket::recvall(char *data, qint32 size)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->readLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->recv(data, size, true);
}

qint32 LocalSocket::send(const char *data, qint32 size)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->send(data, size, false);
}

qint32 LocalSocket::sendall(const char *data, qint32 size)
{
    Q_D(LocalSocket);
    ScopedLock<Lock> lock(d->writeLock);
    if (!lock.isSuccess()) {
        return -1;
    }
    return d->send(data, size, true);
}

QByteArray LocalSocket::recv(qint32 size)
{
    QByteArray buf(size, Qt::Uninitialized);
    qint32 bytes = recv(buf.data(), size);
    if (bytes <= 0) {
        return QByteArray();
    }
    buf.resize(bytes);
    return buf;
}

QByteArray LocalSocket::recvall(qint32 size)
{
    QByteArray buf(size, Qt::Uninitialized);
    qint32 bytes = recvall(buf.data(), size);
    if (bytes <= 0) {
        return QByteArray();
    }
    buf.resize(bytes);
    return buf;
}

qint32 LocalSocket::send(const QByteArray &data)
{
    return send(data.constData(), data.size());
}

qint32 LocalSocket::sendall(const QByteArray &data)
{
    return sendall(data.constData(), data.size());
}

LocalSocket *LocalSocket::createConnection(const QString &name, Socket::SocketError *error)
{
    QScopedPointer<LocalSocket> socket(new LocalSocket());
    if (!socket->connect(name)) {
        if (error) {
            *error = socket->error();
        }
        return nullptr;
    }
    if (error) {
        *error = Socket::NoError;
    }
    return socket.take();
}

LocalSocket *LocalSocket::createServer(const QString &name, int backlog)
{
    QScopedPointer<LocalSocket> socket(new LocalSocket());
    if (!socket->bind(name)) {
        return nullptr;
    }
    if (backlog != 0) {
        if (!socket->listen(backlog)) {
            return nullptr;
        }
    }
    return socket.take();
}

namespace {

class LocalSocketLikeImpl : public SocketLike
{
public:
    LocalSocketLikeImpl(QSharedPointer<LocalSocket> s);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
    virtual QString localAddressURI() const override;
    virtual QString peerAddressURI() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool bind(const QString &name, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool connect(const QString &name) override;
    virtual void close() override;
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint32 peek(char *data, qint32 size) override;
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
public:
    QSharedPointer<LocalSocket> s;
};

LocalSocketLikeImpl::LocalSocketLikeImpl(QSharedPointer<LocalSocket> s)
    : s(s)
{
}

Socket::SocketError LocalSocketLikeImpl::error() const
{
    return s->error();
}

QString LocalSocketLikeImpl::errorString() const
{
    return s->errorString();
}

bool LocalSocketLikeImpl::isValid() const
{
    return s->isValid();
}

HostAddress LocalSocketLikeImpl::localAddress() const
{
    return s->localAddress();
}

quint16 LocalSocketLikeImpl::localPort() const
{
    return s->localPort();
}

HostAddress LocalSocketLikeImpl::peerAddress() const
{
    return s->peerAddress();
}

QString LocalSocketLikeImpl::peerName() const
{
    return s->peerName();
}

quint16 LocalSocketLikeImpl::peerPort() const
{
    return s->peerPort();
}

qintptr LocalSocketLikeImpl::fileno() const
{
    return s->fileno();
}

Socket::SocketType LocalSocketLikeImpl::type() const
{
    return s->type();
}

Socket::SocketState LocalSocketLikeImpl::state() const
{
    return s->state();
}

HostAddress::NetworkLayerProtocol LocalSocketLikeImpl::protocol() const
{
    return s->protocol();
}

QString LocalSocketLikeImpl::localAddressURI() const
{
    return s->localAddressURI();
}

QString LocalSocketLikeImpl::peerAddressURI() const
{
    return s->peerAddressURI();
}

Socket *LocalSocketLikeImpl::acceptRaw()
{
    return nullptr;
}

QSharedPointer<SocketLike> LocalSocketLikeImpl::accept()
{
    return asSocketLike(s->accept());
}

bool LocalSocketLikeImpl::bind(const HostAddress &, quint16, Socket::BindMode)
{
    return false;
}

bool LocalSocketLikeImpl::bind(quint16, Socket::BindMode)
{
    return false;
}

bool LocalSocketLikeImpl::bind(const QString &name, Socket::BindMode mode)
{
    return s->bind(name, mode);
}

bool LocalSocketLikeImpl::connect(const HostAddress &, quint16)
{
    return false;
}

bool LocalSocketLikeImpl::connect(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    // A local socket has no host:port peer. Forwarding to connect(name) here would
    // silently turn "connect to example.com:80" into "open the pipe named
    // example.com" for every generic caller that works on a SocketLike.
    return false;
}

bool LocalSocketLikeImpl::connect(const QString &name)
{
    return s->connect(name);
}

void LocalSocketLikeImpl::close()
{
    s->close();
}

void LocalSocketLikeImpl::abort()
{
    s->abort();
}

bool LocalSocketLikeImpl::listen(int backlog)
{
    return s->listen(backlog);
}

bool LocalSocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}

QVariant LocalSocketLikeImpl::option(Socket::SocketOption option) const
{
    return s->option(option);
}

qint32 LocalSocketLikeImpl::peek(char *data, qint32 size)
{
    return s->peek(data, size);
}

qint32 LocalSocketLikeImpl::peekRaw(char *data, qint32 size)
{
    return s->peekRaw(data, size);
}

qint32 LocalSocketLikeImpl::recv(char *data, qint32 size)
{
    return s->recv(data, size);
}

qint32 LocalSocketLikeImpl::recvall(char *data, qint32 size)
{
    return s->recvall(data, size);
}

qint32 LocalSocketLikeImpl::send(const char *data, qint32 size)
{
    return s->send(data, size);
}

qint32 LocalSocketLikeImpl::sendall(const char *data, qint32 size)
{
    return s->sendall(data, size);
}

QByteArray LocalSocketLikeImpl::recv(qint32 size)
{
    return s->recv(size);
}

QByteArray LocalSocketLikeImpl::recvall(qint32 size)
{
    return s->recvall(size);
}

qint32 LocalSocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}

qint32 LocalSocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}

}  // namespace

QSharedPointer<SocketLike> asSocketLike(QSharedPointer<LocalSocket> s)
{
    if (s.isNull()) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<LocalSocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QSharedPointer<LocalSocket> convertSocketLikeToLocalSocket(QSharedPointer<SocketLike> socket)
{
    QSharedPointer<LocalSocketLikeImpl> impl = socket.dynamicCast<LocalSocketLikeImpl>();
    if (impl.isNull()) {
        return QSharedPointer<LocalSocket>();
    }
    return impl->s;
}

QTNETWORKNG_NAMESPACE_END
