#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "../include/private/socket_p.h"

#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifdef Q_OS_UNIX
    #ifdef Q_OS_ANDROID
        #include <unistd.h>
        #if !defined(__LP64__)
            #define QT_SOCKLEN_T int32_t
        #else
            #define QT_SOCKLEN_T socklen_t
        #endif
    #elif defined(Q_OS_OPENBSD)
        #define QT_SOCKLEN_T __socklen_t
    #else
        #include <qplatformdefs.h>
        #ifndef QT_SOCKLEN_T
            #if defined(__GLIBC__) && (__GLIBC__ < 2)
                #define QT_SOCKLEN_T int
            #else
                #define QT_SOCKLEN_T socklen_t
            #endif
        #endif
    #endif
#endif

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
    if (!atom.load()) {
        // More than one thread could turn off SIGPIPE at the same time
        // But that's acceptable because they all would be doing the same
        // action
        struct sigaction noaction;
        memset(&noaction, 0, sizeof(noaction));
        noaction.sa_handler = SIG_IGN;
        ::sigaction(SIGPIPE, &noaction, nullptr);
        atom.store(1);
    }
}

static inline void qt_socket_getPortAndAddress(const qt_sockaddr *s, quint16 *port, QHostAddress *addr)
{
    if (s->a.sa_family == AF_INET6) {
        Q_IPV6ADDR tmp;
        memcpy(&tmp, &s->a6.sin6_addr, sizeof(tmp));
        if (addr) {
            QHostAddress tmpAddress;
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
            QHostAddress tmpAddress;
            tmpAddress.setAddress(ntohl(s->a4.sin_addr.s_addr));
            *addr = tmpAddress;
        }
        if (port)
            *port = ntohs(s->a4.sin_port);
    } else {
        qFatal("qt_socket_getPortAndAddress() can only handle AF_INET6 and AF_INET.");
    }
}

bool SocketPrivate::createSocket()
{
    qt_ignore_sigpipe();
    int flags = SOCK_NONBLOCK ; //| SOCK_CLOEXEC
    int family = AF_INET;
    if (protocol == Socket::IPv6Protocol || protocol == Socket::AnyIPProtocol) {
        family = AF_INET6;
    }
    if (type == Socket::TcpSocket) {
        flags = SOCK_STREAM | flags;
    } else {
        flags = SOCK_DGRAM | flags;
    }
    fd = socket(family, flags, 0);
    if (fd < 0 && protocol == Socket::AnyIPProtocol && errno == EAFNOSUPPORT) {
        fd = socket(AF_INET, flags, 0);
        this->protocol = Socket::IPv4Protocol;
    }
    if (fd < 0) {
        int ecopy = errno;
        switch(ecopy) {
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
    }
    return fd > 0;
}

inline uint scopeIdFromString(const QString scopeId)
{
    if (scopeId.isEmpty())
        return 0;
    bool ok;
    uint id = scopeId.toUInt(&ok);
    if(!ok)
        id = if_nametoindex(scopeId.toLatin1());
    return id;
}

namespace {
// the sa_len or sin6_len is not always available.
namespace SetSALen {
    template <typename T> void set(T *sa, typename QtPrivate::QEnableIf<(&T::sa_len, true), QT_SOCKLEN_T>::Type len)
    { sa->sa_len = len; }
    template <typename T> void set(T *sin6, typename QtPrivate::QEnableIf<(&T::sin6_len, true), QT_SOCKLEN_T>::Type len)
    { sin6->sin6_len = len; }
    template <typename T> void set(T *, ...) {}
}
}


void SocketPrivate::setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, int *sockAddrSize)
{
    if (address.protocol() == QAbstractSocket::IPv6Protocol
        || address.protocol() == QAbstractSocket::AnyIPProtocol
        || protocol == Socket::IPv6Protocol
        || protocol == Socket::AnyIPProtocol) {
        memset(&aa->a6, 0, sizeof(sockaddr_in6));
        aa->a6.sin6_family = AF_INET6;
        aa->a6.sin6_scope_id = scopeIdFromString(address.scopeId());
        aa->a6.sin6_port = htons(port);
        Q_IPV6ADDR tmp = address.toIPv6Address();
        memcpy(&aa->a6.sin6_addr, &tmp, sizeof(tmp));
        *sockAddrSize = sizeof(sockaddr_in6);
        SetSALen::set(&aa->a, sizeof(sockaddr_in6));
    } else {
        memset(&aa->a, 0, sizeof(sockaddr_in));
        aa->a4.sin_family = AF_INET;
        aa->a4.sin_port = htons(port);
        aa->a4.sin_addr.s_addr = htonl(address.toIPv4Address());
        *sockAddrSize = sizeof(sockaddr_in);
        SetSALen::set(&aa->a, sizeof(sockaddr_in));
    }
}


bool SocketPrivate::isValid() const
{
    if (!checkState()) {
        return false;
    }
    int error = 0;
    socklen_t len = sizeof (error);
    int result = getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len);
    return result == 0 && error == 0;
}


bool SocketPrivate::bind(const QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    if (!checkState())  {
        return false;
    }
    if (state != Socket::UnconnectedState) {
        return false;
    }
    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize;
    int t;
    setPortAndAddress(port, address, &aa, &t);
    sockAddrSize = static_cast<QT_SOCKLEN_T>(t);

    if(mode & Socket::ReuseAddressHint) {
        setOption(Socket::AddressReusable, true);
    }
#ifdef IPV6_V6ONLY
    if (aa.a.sa_family == AF_INET6) {
        int ipv6only = 0;
        if (address.protocol() == QAbstractSocket::IPv6Protocol)
            ipv6only = 1;
        //default value of this socket option varies depending on unix variant (or system configuration on BSD), so always set it explicitly
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, static_cast<void*>(&ipv6only), sizeof(ipv6only) );
    }
#endif

    int bindResult = ::bind(fd, &aa.a, sockAddrSize);
    if (bindResult < 0 && errno == EAFNOSUPPORT && address.protocol() == QAbstractSocket::AnyIPProtocol) {
        // retry with v4
        aa.a4.sin_family = AF_INET;
        aa.a4.sin_port = htons(port);
        aa.a4.sin_addr.s_addr = htonl(address.toIPv4Address());
        sockAddrSize = sizeof(aa.a4);
        bindResult = ::bind(fd, &aa.a, sockAddrSize);
    }
    if (bindResult < 0) {
        switch(errno)
        {
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
            setError(Socket::SocketAddressNotAvailableError,AddressNotAvailableErrorString);
            break;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        }
        return false;
    }
    state = Socket::BoundState;
    return true;
}


bool SocketPrivate::connect(const QHostAddress &address, quint16 port)
{
    if (!checkState()) {
        return false;
    }
    if (state != Socket::UnconnectedState && state != Socket::BoundState && state != Socket::ConnectingState) {
        return false;
    }
    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize;
    int t;
    setPortAndAddress(port, address, &aa, &t);
    sockAddrSize = static_cast<QT_SOCKLEN_T>(t);
    state = Socket::ConnectingState;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    while (true) {
        if (!checkState())
            return false;
        if (state != Socket::ConnectingState)
            return false;
        int result;
        do {
            result = ::connect(fd, &aa.a, sockAddrSize);
        } while(result < 0 && errno == EINTR);
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
            qDebug() << t << strerror(t);
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            state = Socket::UnconnectedState;
            return false;
        }
        watcher.start();
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
        switch (sa.a.sa_family)
        {
        case AF_INET:
            protocol = Socket::IPv4Protocol;
            break;
        case AF_INET6:
            protocol = Socket::IPv6Protocol;
            break;
        default:
            protocol = Socket::UnknownNetworkLayerProtocol;
            break;
        }
    } else if (errno == EBADF) {
        setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
        return false;
    }

#if defined (IPV6_V6ONLY)
    // determine if local address is dual mode
    // On linux, these are returned as "::" (==AnyIPv6)
    // On OSX, these are returned as "::FFFF:0.0.0.0" (==AnyIPv4)
    // in either case, the IPV6_V6ONLY option is cleared
    int ipv6only = 0;
    socklen_t optlen = sizeof(ipv6only);
    if (protocol == Socket::IPv6Protocol
        && (localAddress == QHostAddress::AnyIPv4 || localAddress == QHostAddress::AnyIPv6)
        && !getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&ipv6only), &optlen )) {
            if (optlen != sizeof(ipv6only))
                qWarning("unexpected size of IPV6_V6ONLY socket option");
            if (!ipv6only) {
                protocol = Socket::AnyIPProtocol;
                localAddress = QHostAddress::Any;
            }
    }
#endif

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
            state = Socket::UnconnectedState;
        } else {
            type = Socket::UnknownSocketType;
        }
    }
    return true;
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
            setError(Socket::SocketAccessError, AccessErrorString);
            return total == 0 ? -1: total;
        }
        ssize_t r = 0;
        do {
            r = ::recv(fd, data + total, static_cast<size_t>(size - total), 0);
        } while (r < 0 && errno == EINTR);

        if (r < 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNRESET:
#if defined(Q_OS_VXWORKS)
            case ESHUTDOWN:
#endif
                if(type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    abort();
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
            if(all) {
                continue;
            } else {
                return total;
            }
        }
        watcher.start();
    }
    return total;
}

// openbsd do not support MSG_MORE?
#ifndef MSG_MORE
#define MSG_MORE 0
#endif

qint32 SocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (!checkState()) {
        return 0;
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
            w = ::send(fd, data + sent, static_cast<size_t>(size - sent), all ? 0 : MSG_MORE);
        } while(w < 0 && errno == EINTR);
        if (w > 0) {
            if(!all) {
                return static_cast<qint32>(w);
            } else {
                sent += w;
                continue;
            }
        } else if(w < 0) {
            int e = errno;
            switch(e) {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
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
                return sent;
            case EBADF:
            case EFAULT:
            case EINVAL:
            case ENOTCONN:
            case ENOTSOCK:
                setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
                abort();
                return sent;
            case EMSGSIZE:
            case ENOBUFS:
            case ENOMEM:
                setError(Socket::DatagramTooLargeError, DatagramTooLargeErrorString);
                return sent;
            case EPIPE:
            case ECONNRESET:
                setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                abort();
                return sent;
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                abort();
                return sent;
            }
        }
        watcher.start();
    }
    return sent;
}


qint32 SocketPrivate::recvfrom(char *data, qint32 maxSize, QHostAddress *addr, quint16 *port)
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
        if (!checkState()){
            setError(Socket::SocketAccessError, AccessErrorString);
            return -1;
        }
        do {
            recvResult = ::recvmsg(fd, &msg, 0);
        } while (recvResult == -1 && errno == EINTR);

        if (recvResult < 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case ECONNRESET:
            case ECONNREFUSED:
            case ENOTCONN:
#if defined(Q_OS_VXWORKS)
            case ESHUTDOWN:
#endif
                if(type == Socket::TcpSocket) {
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
        } else{
            qt_socket_getPortAndAddress(&aa, port, addr);
            //return qint64(maxSize ? recvResult : recvResult == -1 ? -1 : 0);
            return static_cast<qint32>(recvResult);
        }
        watcher.start();
    }
}


qint32 SocketPrivate::sendto(const char *data, qint32 size, const QHostAddress &addr, quint16 port)
{
    if (!checkState()) {
        return -1;
    }
    struct msghdr msg;
    struct iovec vec;
    qt_sockaddr aa;
    QT_SOCKLEN_T len;

    memset(&msg, 0, sizeof(msg));
    memset(&aa, 0, sizeof(aa));
    vec.iov_base = const_cast<char *>(data);
    vec.iov_len = static_cast<size_t>(size);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_name = &aa.a;

    int t;
    setPortAndAddress(port, addr, &aa, &t);
    len = static_cast<QT_SOCKLEN_T>(t);
    msg.msg_namelen = len;

    ssize_t sentBytes = 0;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
#ifdef MSG_NOSIGNAL
    int flags = MSG_NOSIGNAL;
#else
    int flags = 0;
#endif
    while(true) {
        if (!checkState()) {
            return -1;
        }
        do {
            sentBytes = ::sendmsg(fd, &msg, flags);
        } while(sentBytes == -1 && error == EINTR);

        if(sentBytes < 0) {
            int e = errno;
            switch(e)
            {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
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
            case ECONNRESET:
            case ENOTSOCK:
                if(type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    abort();
                }
                return -1;
            case EDESTADDRREQ: // not happen in sendto()
            case EISCONN: // happens in udp socket
            case ENOTCONN: // happens in tcp socket
                setError(Socket::UnsupportedSocketOperationError,InvalidSocketErrorString);
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
        } else { // sentBytes == 0 || sentBytes > 0
            if (type == Socket::UdpSocket && !localPort && localAddress.isNull()) {
                fetchConnectionParameters();
            }
            return static_cast<qint32>(sentBytes);
        }
        watcher.start();
    }
}


static void convertToLevelAndOption(Socket::SocketOption opt,
                                    Socket::NetworkLayerProtocol socketProtocol, int *level, int *n)
{
    *n = -1;
    *level = SOL_SOCKET; // default

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
        if (socketProtocol == Socket::IPv6Protocol || socketProtocol == Socket::AnyIPProtocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_MULTICAST_HOPS;
        } else
        {
            *level = IPPROTO_IP;
            *n = IP_MULTICAST_TTL;
        }
        break;
    case Socket::MulticastLoopbackOption:
        if (socketProtocol == Socket::IPv6Protocol || socketProtocol == Socket::AnyIPProtocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_MULTICAST_LOOP;
        } else
        {
            *level = IPPROTO_IP;
            *n = IP_MULTICAST_LOOP;
        }
        break;
    case Socket::TypeOfServiceOption:
        if (socketProtocol == Socket::IPv4Protocol) {
            *level = IPPROTO_IP;
            *n = IP_TOS;
        }
        break;
    case Socket::ReceivePacketInformation:
        if (socketProtocol == Socket::IPv6Protocol || socketProtocol == Socket::AnyIPProtocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_RECVPKTINFO;
        } else if (socketProtocol == Socket::IPv4Protocol) {
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
        if (socketProtocol == Socket::IPv6Protocol || socketProtocol == Socket::AnyIPProtocol) {
            *level = IPPROTO_IPV6;
            *n = IPV6_RECVHOPLIMIT;
        } else if (socketProtocol == Socket::IPv4Protocol) {
#ifdef IP_RECVTTL               // IP_RECVTTL is a non-standard extension supported on some OS
            *level = IPPROTO_IP;
            *n = IP_RECVTTL;
#endif
        }
        break;
    case Socket::MaxStreamsSocketOption:
        // FIXME support stcp
        break;
    case Socket::NonBlockingSocketOption:
    case Socket::BindExclusively:
        Q_UNREACHABLE();
    }
}


QVariant SocketPrivate::option(Socket::SocketOption option) const
{
    if (!checkState())
        return QVariant();

    if (option == Socket::BroadcastSocketOption) {
        return QVariant(true);
    }
    int n, level;
    int v = -1;
    QT_SOCKLEN_T len = sizeof(v);
    convertToLevelAndOption(option, protocol, &level, &n);
    if (n != -1 && ::getsockopt(fd, level, n, reinterpret_cast<char*>(&v), &len) != -1) {
        return QVariant(v);
    }
    return QVariant();
}


bool SocketPrivate::setOption(Socket::SocketOption option, const QVariant &value)
{
    if (!checkState())
        return false;

//    if(option == Socket::BroadcastSocketOption) {
//        return true;
//    }

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
    return ::setsockopt(fd, level, n, reinterpret_cast<char*>(&v), sizeof(v)) == 0;
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
#else // Q_OS_VXWORKS
    int onoff = 1;
    if (::ioctl(fd, FIONBIO, (int)&onoff) < 0) {
        return false;
    }
#endif // Q_OS_VXWORKS
    return true;
}

// Tru64 redefines accept -> _accept with _XOPEN_SOURCE_EXTENDED
static inline int qt_safe_accept(int s, struct sockaddr *addr, socklen_t *addrlen, int flags = 0)
{
    Q_ASSERT((flags & ~O_NONBLOCK) == 0);

    int fd;
#if defined (QT_UNIX_SUPPORTS_THREADSAFE_CLOEXEC) && defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    // use accept4
    int sockflags = SOCK_CLOEXEC;
    if (flags & O_NONBLOCK)
        sockflags |= SOCK_NONBLOCK;
    fd = ::accept4(s, addr, static_cast<QT_SOCKLEN_T *>(addrlen), sockflags);
    if (fd != -1 || !(errno == ENOSYS || errno == EINVAL))
        return fd;
#endif

    fd = ::accept(s, addr, addrlen);
    if (fd < 0)
        return -1;

    ::fcntl(fd, F_SETFD, FD_CLOEXEC);

    // set non-block too?
    if (flags & O_NONBLOCK)
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);

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
        watcher.start();
    }
}


QTNETWORKNG_NAMESPACE_END
