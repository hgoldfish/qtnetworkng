#include "../include/private/local_socket_p.h"
#include "../include/private/eventloop_p.h"
#include "../include/coroutine_utils.h"
#include <QtCore/qfile.h>
#include <string.h>
#include <cstddef>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

// macOS has no MSG_NOSIGNAL; SO_NOSIGPIPE below covers that platform.
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

QTNETWORKNG_NAMESPACE_BEGIN

static void setNoSigPipe(int sock)
{
#ifdef SO_NOSIGPIPE
    const int on = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    Q_UNUSED(sock);
#endif
}

void LocalSocketPrivate::setSocketDescriptor(qintptr socketDescriptor)
{
    fd = static_cast<int>(socketDescriptor);
    if (fd < 0) {
        setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
        return;
    }
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    setNoSigPipe(fd);
    state = Socket::ConnectedState;
    error = Socket::NoError;
}

bool LocalSocketPrivate::createSocket()
{
    int type = SOCK_STREAM;
#ifdef SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    type |= SOCK_NONBLOCK;
#endif
    fd = ::socket(AF_UNIX, type, 0);
    if (fd < 0) {
        setError(Socket::SocketResourceError, ResourceErrorString);
        return false;
    }
#ifndef SOCK_CLOEXEC
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#ifndef SOCK_NONBLOCK
    // macOS 等：socket() 不支持 SOCK_NONBLOCK type 标志，只能 fcntl。
    int fl = ::fcntl(fd, F_GETFL, 0);
    if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        ::close(fd);
        fd = -1;
        setError(Socket::UnsupportedSocketOperationError, NonBlockingInitFailedErrorString);
        return false;
    }
#endif
    setNoSigPipe(fd);
    return true;
}

static bool fillSockAddr(const QString &fullName, sockaddr_un *addr, socklen_t *addrLen)
{
    QByteArray path = QFile::encodeName(fullName);
    if (path.size() >= static_cast<int>(sizeof(addr->sun_path))) {
        return false;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path, path.constData(), static_cast<size_t>(path.size()) + 1);
    *addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    return true;
}

// Returns true when a live socket still owns `fullName`. Probes with a
// datagram connect(): the kernel looks the address up and answers EPROTOTYPE
// when a stream listener (or any live socket of a different type) is bound to
// it, and ECONNREFUSED when the file is just a leftover from a crashed server
// with nothing behind it. Unlike a stream connect() probe this neither hands
// the live server a ghost connection nor can it ever block, because a datagram
// connect() is a plain address lookup without any handshake. This also detects
// a peer that is bound but not yet listening, which a stream probe would have
// misjudged as stale.
//
// Only ECONNREFUSED is proof that nothing is bound to the name, and only then
// is the file removed (the same rule Qt's QLocalServer applies to its stream
// probe). Every other outcome - success, EPROTOTYPE, EACCES, or any unexpected
// error - is treated as "in use", so the file is never unlinked by mistake.
static bool isServerListening(const QString &fullName)
{
    sockaddr_un addr;
    socklen_t addrLen = 0;
    if (!fillSockAddr(fullName, &addr, &addrLen)) {
        // Cannot reason about the name; be conservative and keep the file.
        return true;
    }
    int probe = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (probe < 0) {
        return true;
    }
    const int result = ::connect(probe, reinterpret_cast<sockaddr *>(&addr), addrLen);
    const int err = errno;
    ::close(probe);
    if (result == 0) {
        // A datagram socket owns the name; it is occupied either way.
        return true;
    }
    return err != ECONNREFUSED;
}

static void removeStaleSocketFile(const QString &fullName)
{
    if (isServerListening(fullName)) {
        // Someone is still serving this name; leave it alone so that ::bind()
        // reports AddressInUseError instead of us stealing the name.
        return;
    }
    ::unlink(QFile::encodeName(fullName).constData());
}

bool LocalSocketPrivate::bind(const QString &name, Socket::BindMode mode)
{
    if (state != Socket::UnconnectedState) {
        setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
        return false;
    }
    if (name.isEmpty()) {
        setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
        return false;
    }
    if (fd < 0 && !createSocket()) {
        return false;
    }

    serverName = name;
    fullServerName = makeFullServerName(name);

    sockaddr_un addr;
    socklen_t addrLen = 0;
    if (!fillSockAddr(fullServerName, &addr, &addrLen)) {
        setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
        return false;
    }

    // Drop the socket file left behind by a previous (possibly crashed) server.
    // A name that is still being served is left untouched so that ::bind()
    // reports AddressInUseError.
    //
    // DontShareAddress asks for the opposite: never touch a file that is not
    // ours. The leftover then makes ::bind() fail with EADDRINUSE, which is
    // reported as AddressInUseError - the caller explicitly took the risk of a
    // name that somebody else may still own.
    if (!(mode & Socket::DontShareAddress)) {
        removeStaleSocketFile(fullServerName);
    }

    int result = ::bind(fd, reinterpret_cast<sockaddr *>(&addr), addrLen);
    if (result < 0) {
        switch (errno) {
        case EADDRINUSE:
            setError(Socket::AddressInUseError, AddressInuseErrorString);
            break;
        case EACCES:
            setError(Socket::SocketAccessError, AccessErrorString);
            break;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        }
        return false;
    }
    unlinkPath = fullServerName;
    shouldUnlink = true;
    state = Socket::BoundState;
    error = Socket::NoError;
    return true;
}

bool LocalSocketPrivate::listen(int backlog)
{
    // Do not use checkState(): a prior wrong-state bind() may have set
    // UnsupportedSocketOperationError while leaving a perfectly usable Bound
    // socket, and that sticky error must not block listen().
    if (fd < 0) {
        setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
        return false;
    }
    if (state != Socket::BoundState) {
        setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
        return false;
    }
    if (backlog <= 0) {
        backlog = 50;
    }
    if (::listen(fd, backlog) < 0) {
        setError(Socket::UnknownSocketError, UnknownSocketErrorString);
        return false;
    }
    state = Socket::ListeningState;
    error = Socket::NoError;
    return true;
}

LocalSocket *LocalSocketPrivate::accept()
{
    if (!checkState() || state != Socket::ListeningState) {
        return nullptr;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    while (true) {
        if (!checkState() || state != Socket::ListeningState) {
            return nullptr;
        }
        int accepted = -1;
        // accept4() is not available on older Android API levels; socket_unix.cpp
        // excludes Android for the same reason.
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK) && !defined(Q_OS_ANDROID)
        accepted = ::accept4(fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
        accepted = ::accept(fd, nullptr, nullptr);
        if (accepted >= 0) {
            ::fcntl(accepted, F_SETFD, FD_CLOEXEC);
            int fl = ::fcntl(accepted, F_GETFL, 0);
            if (fl >= 0) {
                ::fcntl(accepted, F_SETFL, fl | O_NONBLOCK);
            }
        }
#endif
        if (accepted < 0) {
            switch (errno) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNABORTED:
            case EINTR:
                continue;
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                return nullptr;
            }
        } else {
            LocalSocket *conn = new LocalSocket(static_cast<qintptr>(accepted));
            conn->d_func()->serverName = serverName;
            conn->d_func()->fullServerName = fullServerName;
            return conn;
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            return nullptr;
        }
    }
}

bool LocalSocketPrivate::connect(const QString &name)
{
    if (fd >= 0 && state != Socket::UnconnectedState && state != Socket::BoundState) {
        setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
        return false;
    }
    if (name.isEmpty()) {
        setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
        return false;
    }
    if (fd < 0 && !createSocket()) {
        return false;
    }

    serverName = name;
    fullServerName = makeFullServerName(name);

    sockaddr_un addr;
    socklen_t addrLen = 0;
    if (!fillSockAddr(fullServerName, &addr, &addrLen)) {
        setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
        return false;
    }

    state = Socket::ConnectingState;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    while (true) {
        if (fd < 0) {
            return false;
        }
        if (state != Socket::ConnectingState) {
            return false;
        }
        int result;
        do {
            result = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), addrLen);
        } while (result < 0 && errno == EINTR);

        if (result >= 0 || errno == EISCONN) {
            state = Socket::ConnectedState;
            error = Socket::NoError;
            return true;
        }
        switch (errno) {
        case EINPROGRESS:
        case EALREADY:
        case EAGAIN:
            break;
        case ECONNREFUSED:
            setError(Socket::ConnectionRefusedError, ConnectionRefusedErrorString);
            state = Socket::UnconnectedState;
            return false;
        case ENOENT:
            setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
            state = Socket::UnconnectedState;
            return false;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        }
    }
}

void LocalSocketPrivate::close()
{
    if (fd >= 0) {
        int sock = fd;
        ::shutdown(sock, SHUT_RDWR);
        ::close(sock);
        // Wake coroutines parked in accept()/recv()/send() on this fd, as
        // SocketPrivate::close() does. Without this a server.stop() leaves the
        // serving coroutine sleeping on a dead descriptor forever.
        EventLoopCoroutine::get()->triggerIoWatchers(sock);
        fd = -1;
    }
    if (shouldUnlink && !unlinkPath.isEmpty()) {
        ::unlink(QFile::encodeName(unlinkPath).constData());
        shouldUnlink = false;
        unlinkPath.clear();
    }
    if (state != Socket::UnconnectedState) {
        state = Socket::UnconnectedState;
    }

    // Unlike Windows named pipes, accept() returns a fresh kernel descriptor
    // that closing the listening socket cannot reach — the fd is already gone
    // above. Draining the locks still waits for parked coroutines to leave.
    if (readLock.isLocked()) {
        readLock.tryAcquire();
        readLock.release();
    }
    if (writeLock.isLocked()) {
        writeLock.tryAcquire();
        writeLock.release();
    }
}

void LocalSocketPrivate::abort()
{
    // Not a synonym for close(): release the fd at once without draining
    // readLock/writeLock. Safe from recv()/send() while holding a lock; do not
    // use this as "graceful server stop" while another coroutine is in accept().
    if (fd >= 0) {
        int sock = fd;
        ::shutdown(sock, SHUT_RDWR);
        ::close(sock);
        EventLoopCoroutine::get()->triggerIoWatchers(sock);
        fd = -1;
    }
    if (shouldUnlink && !unlinkPath.isEmpty()) {
        ::unlink(QFile::encodeName(unlinkPath).constData());
        shouldUnlink = false;
        unlinkPath.clear();
    }
    if (state != Socket::UnconnectedState) {
        state = Socket::UnconnectedState;
    }
}

qint32 LocalSocketPrivate::peek(char *data, qint32 size)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    ssize_t r;
    do {
        r = ::recv(fd, data, static_cast<size_t>(size), MSG_PEEK);
    } while (r < 0 && errno == EINTR);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    if (r == 0) {
        return -1;
    }
    return static_cast<qint32>(r);
}

qint32 LocalSocketPrivate::recv(char *data, qint32 size, bool all)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    qint32 total = 0;
    while (total < size) {
        if (!checkState()) {
            return total == 0 ? -1 : total;
        }
        ssize_t r = 0;
        do {
            r = ::recv(fd, data + total, static_cast<size_t>(size - total), 0);
        } while (r < 0 && errno == EINTR);

        if (r < 0) {
            switch (errno) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNRESET:
                setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                return total;
            default:
                setError(Socket::NetworkError, ReadErrorString);
                abort();
                return total == 0 ? -1 : total;
            }
        } else if (r == 0) {
            setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
            return total;
        } else {
            total += static_cast<qint32>(r);
            if (!all) {
                return total;
            }
            continue;
        }
        if (!watcher.start()) {
            setError(Socket::NetworkError, InvalidSocketErrorString);
            abort();
            return total == 0 ? -1 : total;
        }
    }
    return total;
}

qint32 LocalSocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    qint32 sent = 0;
    while (sent < size) {
        if (!checkState()) {
            return sent;
        }
        ssize_t w;
        do {
            w = ::send(fd, data + sent, static_cast<size_t>(size - sent), MSG_NOSIGNAL);
        } while (w < 0 && errno == EINTR);
        if (w > 0) {
            if (!all) {
                return static_cast<qint32>(w);
            }
            sent += static_cast<qint32>(w);
            continue;
        } else if (w == 0) {
            setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
            return sent;
        } else {
            switch (errno) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                if (sent > 0 && !all) {
                    return sent;
                }
                break;
            case EPIPE:
            case ECONNRESET:
                setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                return sent;
            default:
                setError(Socket::UnknownSocketError, WriteErrorString);
                abort();
                return -1;
            }
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, InvalidSocketErrorString);
            abort();
            return sent == 0 ? -1 : sent;
        }
    }
    return sent;
}

QTNETWORKNG_NAMESPACE_END
