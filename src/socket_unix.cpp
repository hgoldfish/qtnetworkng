#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "../include/private/socket_p.h"
#ifdef Q_OS_MACOS
#  define __APPLE_USE_RFC_3542
#endif
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef SOCK_NONBLOCK
#  define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifdef Q_OS_UNIX
#  ifdef Q_OS_ANDROID
#    include <unistd.h>
#    if !defined(__LP64__)
#      define QT_SOCKLEN_T int32_t
#    else
#      define QT_SOCKLEN_T socklen_t
#    endif
#  elif defined(Q_OS_OPENBSD)
#    define QT_SOCKLEN_T __socklen_t
#  else
#    include <qplatformdefs.h>
#    ifndef QT_SOCKLEN_T
#      if defined(__GLIBC__) && (__GLIBC__ < 2)
#        define QT_SOCKLEN_T int
#      else
#        define QT_SOCKLEN_T socklen_t
#      endif
#    endif
#  endif
#endif

// love linux
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

#include "debugger.h"

QTNG_LOGGER("qtng.socket_unix");

QTNETWORKNG_NAMESPACE_BEGIN

union qt_sockaddr {
    sockaddr a;
    sockaddr_in a4;
    sockaddr_in6 a6;
};

static void qt_ignore_sigpipe()
{
    // Set to ignore SIGPIPE once only.
    static QBasicAtomicInt atom = Q_BASIC_ATOMIC_INITIALIZER(0);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    if (!atom.loadRelaxed()) {
#else
    if (!atom.load()) {
#endif
        // More than one thread could turn off SIGPIPE at the same time
        // But that's acceptable because they all would be doing the same
        // action
        struct sigaction noaction;
        memset(&noaction, 0, sizeof(noaction));
        noaction.sa_handler = SIG_IGN;
        ::sigaction(SIGPIPE, &noaction, nullptr);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
        atom.storeRelaxed(1);
#else
        atom.store(1);
#endif
    }
}

static inline void qt_socket_getPortAndAddress(const qt_sockaddr *s, quint16 *port, HostAddress *addr)
{
    if (s->a.sa_family == AF_INET6) {
        IPv6Address tmp;
        memcpy(&tmp, &s->a6.sin6_addr, sizeof(tmp));
        if (addr) {
            HostAddress tmpAddress;
            tmpAddress.setAddress(tmp);
            *addr = tmpAddress;
            if (s->a6.sin6_scope_id) {
                char scopeid[IFNAMSIZ];
                if (::if_indextoname(s->a6.sin6_scope_id, scopeid)) {
                    addr->setScopeId(QLatin1String(scopeid));
                } else {
                    addr->setScopeId(QString::number(s->a6.sin6_scope_id));
                }
            }
        }
        if (port)
            *port = ntohs(s->a6.sin6_port);
    } else if (s->a.sa_family == AF_INET) {
        if (addr) {
            HostAddress tmpAddress;
            tmpAddress.setAddress(ntohl(s->a4.sin_addr.s_addr));
            *addr = tmpAddress;
        }
        if (port)
            *port = ntohs(s->a4.sin_port);
    } else {
        qFatal("qt_socket_getPortAndAddress() can only handle AF_INET6 and AF_INET.");
    }
}

#ifdef Q_OS_MAC
#  ifdef SOCK_CLOEXEC
#    define CREATE_FLAGS SOCK_CLOEXEC
#  else
#    define CREATE_FLAGS 0
#  endif
#else
#  ifdef SOCK_CLOEXEC
#    define CREATE_FLAGS SOCK_NONBLOCK | SOCK_CLOEXEC
#  else
#    define CREATE_FLAGS SOCK_NONBLOCK
#  endif
#endif

bool SocketPrivate::createSocket()
{
    qt_ignore_sigpipe();
    int flags = CREATE_FLAGS;
    int family = AF_INET;
    if (protocol == HostAddress::IPv6Protocol) {
        family = AF_INET6;
    }
    if (type == Socket::TcpSocket) {
        flags = SOCK_STREAM | flags;
    } else {
        flags = SOCK_DGRAM | flags;
    }
    fd = socket(family, flags, 0);
    if (fd < 0) {
        int ecopy = errno;
        switch (ecopy) {
        case EPROTONOSUPPORT:
        case EAFNOSUPPORT:
        case EINVAL:
            setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
            break;
        case ENFILE:
        case EMFILE:
        case ENOBUFS:
        case ENOMEM:
            setError(Socket::SocketResourceError, ResourceErrorString);
            break;
        case EACCES:
            setError(Socket::SocketAccessError, AccessErrorString);
            break;
        default:
            break;
        }

        return false;
    }
#ifdef Q_OS_MAC
    if (!setNonblocking()) {
        close();
        return false;
    }
#endif
    return true;
}

inline uint scopeIdFromString(const QString scopeId)
{
    if (scopeId.isEmpty())
        return 0;
    bool ok;
    uint id = scopeId.toUInt(&ok);
    if (!ok)
        id = if_nametoindex(scopeId.toLatin1());
    return id;
}

namespace {
// the sa_len or sin6_len is not always available.
namespace SetSALen {
template<typename T>
void set(T *sa, typename QtPrivate::QEnableIf<(&T::sa_len, true), QT_SOCKLEN_T>::Type len)
{
    sa->sa_len = len;
}
template<typename T>
void set(T *sin6, typename QtPrivate::QEnableIf<(&T::sin6_len, true), QT_SOCKLEN_T>::Type len)
{
    sin6->sin6_len = len;
}
template<typename T>
void set(T *, ...)
{
}
}  // namespace SetSALen
}  // namespace

bool SocketPrivate::setPortAndAddress(quint16 port, const HostAddress &address, qt_sockaddr *aa, int *sockAddrSize)
{
    if ((address.protocol() == HostAddress::IPv6Protocol || address.protocol() == HostAddress::AnyIPProtocol)
        && protocol == HostAddress::IPv6Protocol) {
        memset(&aa->a6, 0, sizeof(sockaddr_in6));
        aa->a6.sin6_family = AF_INET6;
        aa->a6.sin6_scope_id = scopeIdFromString(address.scopeId());
        aa->a6.sin6_port = htons(port);
        IPv6Address tmp = address.toIPv6Address();
        memcpy(&aa->a6.sin6_addr, &tmp, sizeof(tmp));
        *sockAddrSize = sizeof(sockaddr_in6);
        SetSALen::set(&aa->a, sizeof(sockaddr_in6));
        return true;
    } else if ((address.protocol() == HostAddress::IPv4Protocol || address.protocol() == HostAddress::AnyIPProtocol)
               && protocol == HostAddress::IPv4Protocol) {
        memset(&aa->a, 0, sizeof(sockaddr_in));
        aa->a4.sin_family = AF_INET;
        aa->a4.sin_port = htons(port);
        bool ok;
        aa->a4.sin_addr.s_addr = htonl(address.toIPv4Address(&ok));
        *sockAddrSize = sizeof(sockaddr_in);
        SetSALen::set(&aa->a, sizeof(sockaddr_in));
        return ok;
    } else {
        return false;
    }
}

bool SocketPrivate::isValid() const
{
    if (!checkState()) {
        return false;
    }
    int error = 0;
    socklen_t len = sizeof(error);
    int result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    return result == 0 && error == 0;
}

bool SocketPrivate::bind(const HostAddress &address, quint16 port, Socket::BindMode mode)
{
    if (!checkState()) {
        return false;
    }
    if (state != Socket::UnconnectedState) {
        return false;
    }
    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize;
    int t;
    if (!setPortAndAddress(port, address, &aa, &t)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return false;
    }
    sockAddrSize = static_cast<QT_SOCKLEN_T>(t);

    if (mode & Socket::ReuseAddressHint) {
        setOption(Socket::AddressReusable, true);
    }
#ifdef IPV6_V6ONLY
    if (aa.a.sa_family == AF_INET6) {
        int ipv6only = 1;
        // default value of this socket option varies depending on unix variant (or system configuration on BSD), so
        // always set it explicitly
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, static_cast<void *>(&ipv6only), sizeof(ipv6only));
    }
#endif

    int bindResult = ::bind(fd, &aa.a, sockAddrSize);
    if (bindResult < 0 && errno == EAFNOSUPPORT && address.protocol() == HostAddress::AnyIPProtocol) {
        // retry with v4
        aa.a4.sin_family = AF_INET;
        aa.a4.sin_port = htons(port);
        aa.a4.sin_addr.s_addr = htonl(address.toIPv4Address(nullptr));
        sockAddrSize = sizeof(aa.a4);
        bindResult = ::bind(fd, &aa.a, sockAddrSize);
    }
    if (bindResult < 0) {
        switch (errno) {
        case EADDRINUSE:
            setError(Socket::AddressInUseError, AddressInuseErrorString);
            break;
        case EACCES:
            setError(Socket::SocketAccessError, AddressProtectedErrorString);
            break;
        case EINVAL:
            setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
            break;
        case EADDRNOTAVAIL:
            setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
            break;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        }
        return false;
    }
    state = Socket::BoundState;
    fetchConnectionParameters();
    return true;
}

bool SocketPrivate::connect(const HostAddress &address, quint16 port)
{
    // if (!checkState()) { // not require NoError
    if (fd == 0) {
        return false;
    }
    if (state != Socket::UnconnectedState && state != Socket::BoundState && state != Socket::ConnectingState) {
        return false;
    }
    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize;
    int t;
    if (!setPortAndAddress(port, address, &aa, &t)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return false;
    }
    sockAddrSize = static_cast<QT_SOCKLEN_T>(t);
#ifdef IPV6_V6ONLY
    if (protocol == HostAddress::IPv6Protocol) {
        int ipv6only = 1;
        // default value of this socket option varies depending on unix variant (or system configuration on BSD), so
        // always set it explicitly
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, static_cast<void *>(&ipv6only), sizeof(ipv6only));
    }
#endif
    state = Socket::ConnectingState;
#ifdef Q_OS_MAC
    ScopedIoWatcher watcher(EventLoopCoroutine::ReadWrite, fd);
#else
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
#endif
    while (true) {
        if (!checkState())
            return false;
        if (state != Socket::ConnectingState)
            return false;
        int result;
        do {
            result = ::connect(fd, &aa.a, sockAddrSize);
        } while (result < 0 && errno == EINTR);
        if (result >= 0) {
            state = Socket::ConnectedState;
            fetchConnectionParameters();
            return true;
        }
        int t = errno;
        switch (t) {
        case EISCONN:
            state = Socket::ConnectedState;
            fetchConnectionParameters();
            return true;
        case EINPROGRESS:
        case EALREADY:
        case EAGAIN:
            break;

        case ECONNREFUSED:
        case EINVAL:
            setError(Socket::ConnectionRefusedError, ConnectionRefusedErrorString);
            state = Socket::UnconnectedState;
            return false;
        case ETIMEDOUT:
            setError(Socket::NetworkError, ConnectionTimeOutErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EHOSTUNREACH:
            setError(Socket::NetworkError, HostUnreachableErrorString);
            state = Socket::UnconnectedState;
            return false;
        case ENETUNREACH:
            setError(Socket::NetworkError, NetworkUnreachableErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EADDRINUSE:
            setError(Socket::NetworkError, AddressInuseErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EADDRNOTAVAIL:
            setError(Socket::NetworkError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EACCES:
        case EPERM:
            setError(Socket::SocketAccessError, AccessErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EAFNOSUPPORT:
            setError(Socket::UnsupportedSocketOperationError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        case EBADF:
        case EFAULT:
        case ENOTSOCK:
            fd = -1;
            setError(Socket::UnsupportedSocketOperationError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        default:
            qtng_debug << t << strerror(t);
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

void SocketPrivate::close()
{
    if (fd > 0) {
        // TODO flush socket.
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        EventLoopCoroutine::get()->triggerIoWatchers(fd);
        fd = -1;
    }
    state = Socket::UnconnectedState;
    localAddress.clear();
    localPort = 0;
    peerAddress.clear();
    peerPort = 0;
}

void SocketPrivate::abort()
{
    if (fd > 0) {
        ::close(fd);
        EventLoopCoroutine::get()->triggerIoWatchers(fd);
        fd = -1;
    }
    state = Socket::UnconnectedState;
    localAddress.clear();
    localPort = 0;
    peerAddress.clear();
    peerPort = 0;
}

bool SocketPrivate::listen(int backlog)
{
    if (!checkState())
        return false;
    if (state != Socket::BoundState && state != Socket::UnconnectedState)
        return false;

    if (::listen(fd, backlog) < 0) {
        switch (errno) {
        case EADDRINUSE:
            setError(Socket::AddressInUseError, PortInuseErrorString);
            break;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        }
        return false;
    }
    state = Socket::ListeningState;
    fetchConnectionParameters();
    return true;
}

bool SocketPrivate::fetchConnectionParameters()
{
    localPort = 0;
    localAddress.clear();
    peerPort = 0;
    peerAddress.clear();

    if (fd == -1)
        return false;

    qt_sockaddr sa;
    QT_SOCKLEN_T sockAddrSize = sizeof(sa);

    // Determine local address
    memset(&sa, 0, sizeof(sa));
    if (::getsockname(fd, &sa.a, &sockAddrSize) == 0) {
        qt_socket_getPortAndAddress(&sa, &localPort, &localAddress);

        // Determine protocol family
        switch (sa.a.sa_family) {
        case AF_INET:
            protocol = HostAddress::IPv4Protocol;
            break;
        case AF_INET6:
            protocol = HostAddress::IPv6Protocol;
            break;
        default:
            protocol = HostAddress::UnknownNetworkLayerProtocol;
            break;
        }
    } else if (errno == EBADF) {
        setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
        return false;
    }

    // Determine the remote address
    if (!::getpeername(fd, &sa.a, &sockAddrSize))
        qt_socket_getPortAndAddress(&sa, &peerPort, &peerAddress);

    // Determine the socket type (UDP/TCP)
    int value = 0;
    socklen_t valueSize = sizeof(int);
    if (::getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &valueSize) == 0) {
        if (value == SOCK_STREAM) {
            type = Socket::TcpSocket;
        } else if (value == SOCK_DGRAM) {
            type = Socket::UdpSocket;
            if (state == Socket::ConnectingState || state == Socket::ConnectedState || state == Socket::ListeningState) {
                state = Socket::UnconnectedState;
            }
        } else {
            type = Socket::UnknownSocketType;
        }
    }
    return true;
}

qint32 SocketPrivate::peek(char *data, qint32 size)
{
    if (fd <= 0) {
        return false;
    }
    ssize_t r = ::recv(fd, data, static_cast<size_t>(size), MSG_PEEK);
    if (r < 0){
        int err = errno;
        if (err == EINPROGRESS ||
            err == EAGAIN ||
            err == EWOULDBLOCK)
            return 0; /* connection still in place */
        if (err == ECONNRESET ||
            err == ECONNABORTED ||
            err == ENETDOWN ||
            err == ENETRESET ||
            err == ESHUTDOWN ||
            err == ETIMEDOUT ||
            err == ENOTCONN)
            return -1; /* connection has been closed */
    } else if (r == 0) { /* connection has been closed */
        return -1;
    } else if (r > 0) { /* connection still in place */
        return r;
    }
    /* connection status unknown */
    return 0;
}

qint32 SocketPrivate::recv(char *data, qint32 size, bool all)
{
    if (!checkState()) {
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
            int e = errno;
            switch (e) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNRESET:
#if defined(Q_OS_VXWORKS)
            case ESHUTDOWN:
#endif
                if (type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    // abort();
                }
                return total;
            case EBADF:
            case EINVAL:
            case EIO:
            default:
                setError(Socket::NetworkError, InvalidSocketErrorString);
                abort();
                return total == 0 ? -1 : total;
            }
        } else if (r == 0 && type == Socket::TcpSocket) {
            setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
            abort();
            return total;
        } else {
            total += r;
            if (all) {
                continue;
            } else {
                return total;
            }
        }
        if (!watcher.start()) {
            setError(Socket::NetworkError, InvalidSocketErrorString);
            abort();
            return total == 0 ? -1 : total;
        }
    }
    return total;
}

// openbsd do not support MSG_MORE?
#ifndef MSG_MORE
#  define MSG_MORE 0
#endif

qint32 SocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    qint32 sent = 0;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    // TODO UDP socket may send zero length packet
    while (sent < size) {
        if (!checkState()) {
            return sent;
        }
        ssize_t w;
        do {
            w = ::send(fd, data + sent, static_cast<size_t>(size - sent),
                       all && ((size - sent) > 1024 * 4) ? (MSG_MORE | MSG_NOSIGNAL) : MSG_NOSIGNAL);
        } while (w < 0 && errno == EINTR);
        if (w > 0) {
            if (!all) {
                return static_cast<qint32>(w);
            } else {
                sent += w;
                continue;
            }
        } else if (w == 0 && type == Socket::TcpSocket) {
            setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
            // abort();
            return sent;
        } else {  // w < 0 || (w == 0 && type != Socket::TcpSocket)
            int e = errno;
            switch (e) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                if (sent > 0 && !all) {
                    return sent;
                }
                break;
            case EACCES:
                setError(Socket::SocketAccessError, AccessErrorString);
                abort();
                return -1;
            case EBADF:
            case EFAULT:
            case EINVAL:
            case ENOTCONN:
            case ENOTSOCK:
                setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
                abort();
                return -1;
            case EMSGSIZE:
            case ENOBUFS:
                if (type != Socket::UdpSocket) {
                    qtng_warning << "not a udp socket!";
                }
                setError(Socket::DatagramTooLargeError, DatagramTooLargeErrorString);
                return -1;
            case ENOMEM:
                setError(Socket::OutOfMemoryError, OutOfMemoryErrorString);
                abort();
                return -1;
            case EPIPE:
            case ECONNRESET:
                setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                // abort();
                return -1;
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                abort();
                return -1;
            }
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            abort();
            return -1;
        }
    }
    return sent;
}

qint32 SocketPrivate::recvfrom(char *data, qint32 maxSize, HostAddress *addr, quint16 *port)
{
    if (!checkState()) {
        return -1;
    }

    if (maxSize <= 0)
        return -1;

    struct msghdr msg;
    struct iovec vec;
    qt_sockaddr aa;
    memset(&msg, 0, sizeof(msg));
    memset(&aa, 0, sizeof(aa));

    vec.iov_base = data;
    vec.iov_len = static_cast<size_t>(maxSize);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_name = &aa;
    msg.msg_namelen = sizeof(aa);

    ssize_t recvResult = 0;
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    while (true) {
        if (!checkState()) {
            return -1;
        }
        do {
            recvResult = ::recvmsg(fd, &msg, 0);
        } while (recvResult == -1 && errno == EINTR);

        if (recvResult < 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNRESET:
                if (type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    abort();
                    return -1;
                } else {
                    break;
                }
            case ECONNREFUSED:
            case ENOTCONN:
#if defined(Q_OS_VXWORKS)
            case ESHUTDOWN:
#endif
                if (type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    abort();
                }
                return -1;
            case ENOMEM:
                setError(Socket::SocketResourceError, ResourceErrorString);
                return -1;
            case ENOTSOCK:
            case EBADF:
            case EINVAL:
            case EIO:
            case EFAULT:
            default:
                setError(Socket::NetworkError, InvalidSocketErrorString);
                abort();
                return -1;
            }
        } else {
            qt_socket_getPortAndAddress(&aa, port, addr);
            // return qint64(maxSize ? recvResult : recvResult == -1 ? -1 : 0);
            return static_cast<qint32>(recvResult);
        }
        if (!watcher.start()) {
            setError(Socket::NetworkError, InvalidSocketErrorString);
            abort();
            return -1;
        }
    }
}

qint32 SocketPrivate::sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    struct msghdr msg;
    struct iovec vec;
    qt_sockaddr aa;
    QT_SOCKLEN_T len;

    int t;
    memset(&aa, 0, sizeof(aa));
    if (!setPortAndAddress(port, addr, &aa, &t)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return -1;
    }
    len = static_cast<QT_SOCKLEN_T>(t);

    memset(&msg, 0, sizeof(msg));
    vec.iov_base = const_cast<char *>(data);
    vec.iov_len = static_cast<size_t>(size);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_name = &aa.a;
    msg.msg_namelen = len;

    ssize_t sentBytes = 0;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    while (true) {
        if (!checkState()) {
            return -1;
        }
        do {
            sentBytes = ::sendmsg(fd, &msg, MSG_NOSIGNAL);
        } while (sentBytes == -1 && error == EINTR);

        if (sentBytes < 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case EACCES:
                setError(Socket::SocketAccessError, AccessErrorString);
                return -1;
            case EMSGSIZE:
                setError(Socket::DatagramTooLargeError, DatagramTooLargeErrorString);
                return -1;
            case EPIPE:
            case ECONNRESET:
            case ENOTSOCK:
                if (type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    abort();
                }
                return -1;
            case EDESTADDRREQ:  // not happen in sendto()
            case EISCONN:  // happens in udp socket
            case ENOTCONN:  // happens in tcp socket
                setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
                return -1;
            case ENOBUFS:
            case ENOMEM:
                setError(Socket::SocketResourceError, ResourceErrorString);
                return -1;
            case EFAULT:
            case EINVAL:
            default:
                setError(Socket::NetworkError, InvalidSocketErrorString);
                return -1;
            }
        } else {  // sentBytes == 0 || sentBytes > 0
            if (type == Socket::UdpSocket && !localPort && localAddress.isNull()) {
                fetchConnectionParameters();
            }
            return static_cast<qint32>(sentBytes);
        }
        if (!watcher.start()) {
            setError(Socket::NetworkError, InvalidSocketErrorString);
            return -1;
        }
    }
}

static void convertToLevelAndOption(Socket::SocketOption opt, HostAddress::NetworkLayerProtocol socketProtocol,
                                    int *level, int *n)
{
    *n = -1;
    *level = SOL_SOCKET;  // default

    switch (opt) {
    case Socket::BroadcastSocketOption:
        *n = SO_BROADCAST;
        break;
    case Socket::ReceiveBufferSizeSocketOption:
        *n = SO_RCVBUF;
        break;
    case Socket::SendBufferSizeSocketOption:
        *n = SO_SNDBUF;
        break;
    case Socket::AddressReusable:
        *n = SO_REUSEADDR;
        break;
    case Socket::ReceiveOutOfBandData:
        *n = SO_OOBINLINE;
        break;
    case Socket::LowDelayOption:
        *level = IPPROTO_TCP;
        *n = TCP_NODELAY;
        break;
    case Socket::KeepAliveOption:
        *n = SO_KEEPALIVE;
        break;
    case Socket::MulticastTtlOption:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_MULTICAST_HOPS;
        } else {
            *level = IPPROTO_IP;
            *n = IP_MULTICAST_TTL;
        }
        break;
    case Socket::MulticastLoopbackOption:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_MULTICAST_LOOP;
        } else {
            *level = IPPROTO_IP;
            *n = IP_MULTICAST_LOOP;
        }
        break;
    case Socket::TypeOfServiceOption:
        if (socketProtocol == HostAddress::IPv4Protocol) {
            *level = IPPROTO_IP;
            *n = IP_TOS;
        }
        break;
    case Socket::ReceivePacketInformation:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_RECVPKTINFO;
        } else {
            *level = IPPROTO_IP;
#ifdef IP_PKTINFO
            *n = IP_PKTINFO;
#elif defined(IP_RECVDSTADDR)
            // variant found in QNX and FreeBSD; it will get us only the
            // destination address, not the interface; we need IP_RECVIF for that.
            *n = IP_RECVDSTADDR;
#endif
        }
        break;
    case Socket::ReceiveHopLimit:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_RECVHOPLIMIT;
        } else {
#ifdef IP_RECVTTL  // IP_RECVTTL is a non-standard extension supported on some OS
            *level = IPPROTO_IP;
            *n = IP_RECVTTL;
#endif
        }
        break;
    case Socket::PathMtuSocketOption:
        if (socketProtocol == HostAddress::IPv6Protocol || socketProtocol == HostAddress::AnyIPProtocol) {
#ifdef IPV6_MTU
            *level = IPPROTO_IPV6;
            *n = IPV6_MTU;
#endif
        } else {
#ifdef IP_MTU
            *level = IPPROTO_IP;
            *n = IP_MTU;
#endif
        }
        break;
    case Socket::MaxStreamsSocketOption:
    case Socket::NonBlockingSocketOption:
    case Socket::BindExclusively:
    default:
        Q_UNREACHABLE();
    }
}

QVariant SocketPrivate::option(Socket::SocketOption option) const
{
    if (!checkState()) {
        return QVariant();
    }

    // handle non-getsockopt
    switch (option) {
    case Socket::MaxStreamsSocketOption:
    case Socket::NonBlockingSocketOption:
    case Socket::BindExclusively:
        return -1;
    case Socket::PathMtuSocketOption:
#if defined(IPV6_PATHMTU) && !defined(IPV6_MTU)
        // Prefer IPV6_MTU (handled by convertToLevelAndOption), if available
        // (Linux); fall back to IPV6_PATHMTU otherwise (FreeBSD):
        if (protocol == HostAddress::IPv6Protocol) {
            ip6_mtuinfo mtuinfo;
            QT_SOCKLEN_T len = sizeof(mtuinfo);
            if (::getsockopt(fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len) == 0)
                return int(mtuinfo.ip6m_mtu);
            return -1;
        }
#endif
        break;
    default:
        break;
    }

    int n, level;
    int v = -1;
    QT_SOCKLEN_T len = sizeof(v);
    convertToLevelAndOption(option, protocol, &level, &n);
    if (n != -1 && ::getsockopt(fd, level, n, reinterpret_cast<char *>(&v), &len) != -1) {
        return QVariant(v);
    }
    return QVariant();
}

bool SocketPrivate::setTcpKeepalive(bool keepalve, int keepaliveTimeoutSesc, int keepaliveIntervalSesc)
{
    int optval = keepalve ? 1 : 0;
    if (!setOption(Socket::KeepAliveOption, optval)) {
        qtng_debug << "failed to set SO_KEEPALIVE on fd" << fd << "errno:" << errno;
        return false;
    }
#ifdef TCP_KEEPIDLE
    optval = keepaliveTimeoutSesc;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *) &optval, sizeof(optval)) < 0) {
        qtng_debug << "failed to set TCP_KEEPIDLE on fd" << fd << "errno:" << errno;
    }
#elif defined(TCP_KEEPALIVE)
    /* Mac OS X style */
    optval = keepaliveTimeoutSesc;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (void *) &optval, sizeof(optval)) < 0) {
        qtng_debug << "failed to set TCP_KEEPALIVE on fd" << fd << "errno:" << errno;
    }
#endif

#ifdef TCP_KEEPINTVL
    optval = keepaliveIntervalSesc;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &optval, sizeof(optval)) < 0) {
        qtng_debug << "failed to set TCP_KEEPINTVL on fd" << fd << "errno:" << errno;
    }
#endif
    return true;
}

bool SocketPrivate::setOption(Socket::SocketOption option, const QVariant &value)
{
    if (!checkState())
        return false;

    // handle non-setsockopt
    switch (option) {
    case Socket::NonBlockingSocketOption:
    case Socket::MaxStreamsSocketOption:
        return false;
    case Socket::BindExclusively:
        return true;
    default:
        break;
    }

    int n, level;
    bool ok;
    int v = value.toInt(&ok);
    if (!ok)
        return false;

    convertToLevelAndOption(option, protocol, &level, &n);

#if defined(SO_REUSEPORT) && !defined(Q_OS_LINUX)
    if (option == Socket::AddressReusable) {
        // on OS X, SO_REUSEADDR isn't sufficient to allow multiple binds to the
        // same port (which is useful for multicast UDP). SO_REUSEPORT is, but
        // we most definitely do not want to use this for TCP. See QTBUG-6305.
        if (type == Socket::UdpSocket)
            n = SO_REUSEPORT;
    }
#endif
    return ::setsockopt(fd, level, n, reinterpret_cast<char *>(&v), sizeof(v)) == 0;
}

bool SocketPrivate::setNonblocking()
{
#if !defined(Q_OS_VXWORKS)
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return false;
    }
#else  // Q_OS_VXWORKS
    int onoff = 1;
    if (::ioctl(fd, FIONBIO, (int) &onoff) < 0) {
        return false;
    }
#endif  // Q_OS_VXWORKS
    return true;
}

static bool multicastMembershipHelper(SocketPrivate *d, int how6, int how4, const HostAddress &groupAddress,
                                      const NetworkInterface &interface)
{
    int level = 0;
    int sockOpt = 0;
    void *sockArg;
    int sockArgSize;

    ip_mreq mreq4;
    ipv6_mreq mreq6;

    if (groupAddress.protocol() == HostAddress::IPv6Protocol) {
        level = IPPROTO_IPV6;
        sockOpt = how6;
        sockArg = &mreq6;
        sockArgSize = sizeof(mreq6);
        memset(&mreq6, 0, sizeof(mreq6));
        IPv6Address ip6 = groupAddress.toIPv6Address();
        memcpy(&mreq6.ipv6mr_multiaddr, &ip6, sizeof(ip6));
        mreq6.ipv6mr_interface = interface.index();
    } else if (groupAddress.protocol() == HostAddress::IPv4Protocol) {
        level = IPPROTO_IP;
        sockOpt = how4;
        sockArg = &mreq4;
        sockArgSize = sizeof(mreq4);
        memset(&mreq4, 0, sizeof(mreq4));
        mreq4.imr_multiaddr.s_addr = htonl(groupAddress.toIPv4Address());

        if (interface.isValid()) {
            const QList<NetworkAddressEntry> addressEntries = interface.addressEntries();
            bool found = false;
            for (const NetworkAddressEntry &entry : addressEntries) {
                const HostAddress ip = entry.ip();
                if (ip.protocol() == HostAddress::IPv4Protocol) {
                    mreq4.imr_interface.s_addr = htonl(ip.toIPv4Address());
                    found = true;
                    break;
                }
            }
            if (!found) {
                d->setError(Socket::NetworkError, SocketPrivate::NetworkUnreachableErrorString);
                return false;
            }
        } else {
            mreq4.imr_interface.s_addr = INADDR_ANY;
        }
    } else {
        // unreachable
        d->setError(Socket::UnsupportedSocketOperationError, SocketPrivate::ProtocolUnsupportedErrorString);
        return false;
    }

    int res = setsockopt(d->fd, level, sockOpt, sockArg, sockArgSize);
    if (res == -1) {
        switch (errno) {
        case ENOPROTOOPT:
            d->setError(Socket::UnsupportedSocketOperationError, SocketPrivate::OperationUnsupportedErrorString);
            break;
        case EADDRNOTAVAIL:
            d->setError(Socket::SocketAddressNotAvailableError, SocketPrivate::AddressNotAvailableErrorString);
            break;
        default:
            d->setError(Socket::UnknownSocketError, SocketPrivate::UnknownSocketErrorString);
            break;
        }
        return false;
    }
    return true;
}

bool SocketPrivate::joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    if (!checkState()) {
        return false;
    }
    if (state != Socket::BoundState) {
        qtng_warning << "Socket::joinMulticastGroup() should be called only at bound state.";
        return false;
    }
    if (type != Socket::UdpSocket) {
        qtng_warning << "Socket::joinMulticastGroup() only apply to UDP socket type.";
        return false;
    }
    if (protocol == HostAddress::IPv6Protocol && groupAddress.isIPv4()) {
        qtng_warning << "Socket is IPv6 but join to an IPv4 group.";
        return false;
    }
    if (protocol == HostAddress::IPv4Protocol && !groupAddress.isIPv4()) {
        qtng_warning << "Socket is IPv4 but join to an IPv6 group.";
        return false;
    }

    return multicastMembershipHelper(this, IPV6_JOIN_GROUP, IP_ADD_MEMBERSHIP, groupAddress, iface);
}

bool SocketPrivate::leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    if (!checkState()) {
        return false;
    }
    if (state != Socket::BoundState) {
        qtng_warning << "Socket::leaveMulticastGroup() should be called only at bound state.";
        return false;
    }
    if (type != Socket::UdpSocket) {
        qtng_warning << "Socket::leaveMulticastGroup() only apply to UDP socket type.";
        return false;
    }
    if (protocol == HostAddress::IPv6Protocol && groupAddress.isIPv4()) {
        qtng_warning << "Socket is IPv6 but leave from an IPv4 group.";
        return false;
    }
    if (protocol == HostAddress::IPv4Protocol && !groupAddress.isIPv4()) {
        qtng_warning << "Socket is IPv4 but leave from an IPv6 group.";
        return false;
    }
    return multicastMembershipHelper(this, IPV6_LEAVE_GROUP, IP_DROP_MEMBERSHIP, groupAddress, iface);
}

NetworkInterface SocketPrivate::multicastInterface() const
{
    if (!checkState()) {
        return NetworkInterface();
    }
    if (type != Socket::UdpSocket) {
        qtng_warning << "Socket::multicastInterface() only apply to UDP socket type.";
        return NetworkInterface();
    }

    if (protocol == HostAddress::IPv6Protocol || protocol == HostAddress::AnyIPProtocol) {
        uint v;
        QT_SOCKLEN_T sizeofv = sizeof(v);
        if (::getsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v, &sizeofv) == -1)
            return NetworkInterface();
        return NetworkInterface::interfaceFromIndex(v);
    }

    struct in_addr v = { 0 };
    QT_SOCKLEN_T sizeofv = sizeof(v);
    if (::getsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &v, &sizeofv) == -1) {
        return NetworkInterface();
    }
    if (v.s_addr != 0 && sizeofv >= QT_SOCKLEN_T(sizeof(v))) {
        HostAddress ipv4(ntohl(v.s_addr));
        const QList<NetworkInterface> &ifaces = NetworkInterface::allInterfaces();
        for (int i = 0; i < ifaces.count(); ++i) {
            const NetworkInterface &iface = ifaces.at(i);
            if (!(iface.flags() & NetworkInterface::CanMulticast)) {
                continue;
            }
            const QList<NetworkAddressEntry> &entries = iface.addressEntries();
            for (int j = 0; j < entries.count(); ++j) {
                const NetworkAddressEntry &entry = entries.at(j);
                if (entry.ip() == ipv4) {
                    return iface;
                }
            }
        }
    }
    return NetworkInterface();
}

bool SocketPrivate::setMulticastInterface(const NetworkInterface &iface)
{
    if (!checkState()) {
        return false;
    }

    if (type != Socket::UdpSocket) {
        qtng_warning << "Socket::multicastInterface() only apply to UDP socket type.";
        return false;
    }

    if (protocol == HostAddress::IPv6Protocol || protocol == HostAddress::AnyIPProtocol) {
        uint v = iface.index();
        return (::setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &v, sizeof(v)) != -1);
    }

    struct in_addr v;
    if (iface.isValid()) {
        QList<NetworkAddressEntry> entries = iface.addressEntries();
        for (int i = 0; i < entries.count(); ++i) {
            const NetworkAddressEntry &entry = entries.at(i);
            const HostAddress &ip = entry.ip();
            if (ip.protocol() == HostAddress::IPv4Protocol) {
                v.s_addr = htonl(ip.toIPv4Address());
                int r = ::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &v, sizeof(v));
                if (r != -1) {
                    return true;
                }
            }
        }
        return false;
    }

    v.s_addr = INADDR_ANY;
    return (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &v, sizeof(v)) != -1);
}

// Tru64 redefines accept -> _accept with _XOPEN_SOURCE_EXTENDED
static inline int qt_safe_accept(int s, struct sockaddr *addr, socklen_t *addrlen, int flags = 0)
{
    Q_ASSERT((flags & ~O_NONBLOCK) == 0);

    int fd;
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK) && !defined(Q_OS_ANDROID)
    // use accept4
    int sockflags = SOCK_CLOEXEC;
    if (flags & O_NONBLOCK)
        sockflags |= SOCK_NONBLOCK;
#  if defined(Q_OS_NETBSD)
    fd = ::paccept(s, addr, static_cast<QT_SOCKLEN_T *>(addrlen), NULL, sockflags);
#  else
    fd = ::accept4(s, addr, static_cast<QT_SOCKLEN_T *>(addrlen), sockflags);
#  endif
#else
    fd = ::accept(s, addr, addrlen);
    if (fd < 0)
        return -1;

    ::fcntl(fd, F_SETFD, FD_CLOEXEC);

    // set non-block too?
    if (flags & O_NONBLOCK)
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
    return fd;
}

Socket *SocketPrivate::accept()
{
    if (!checkState()) {
        return nullptr;
    }

    if (state != Socket::ListeningState || type != Socket::TcpSocket) {
        return nullptr;
    }

    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    while (true) {
        if (!checkState() || state != Socket::ListeningState) {
            return nullptr;
        }
        int acceptedDescriptor = qt_safe_accept(fd, nullptr, nullptr);
        if (acceptedDescriptor == -1) {
            int e = errno;
            switch (e) {
            case EBADF:
            case EOPNOTSUPP:
                setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
                return nullptr;
            case ECONNABORTED:
                setError(Socket::NetworkError, RemoteHostClosedErrorString);
                return nullptr;
            case EFAULT:
            case ENOTSOCK:
                setError(Socket::SocketResourceError, NotSocketErrorString);
                return nullptr;
            case EPROTONOSUPPORT:
            case EPROTO:
            case EAFNOSUPPORT:
            case EINVAL:
                setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
                return nullptr;
            case ENFILE:
            case EMFILE:
            case ENOBUFS:
            case ENOMEM:
                setError(Socket::SocketResourceError, ResourceErrorString);
                return nullptr;
            case EACCES:
            case EPERM:
                setError(Socket::SocketAccessError, AccessErrorString);
                return nullptr;
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                return nullptr;
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            }
        } else {
            Socket *conn = new Socket(acceptedDescriptor);
            return conn;
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            return nullptr;
        }
    }
}

QTNETWORKNG_NAMESPACE_END
