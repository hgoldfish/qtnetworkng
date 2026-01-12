#define NOMINMAX 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <Mstcpip.h>
#include <QtCore/qbytearray.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
#include <QtCore/qoperatingsystemversion.h>
#else
#include <QtCore/qsysinfo.h>
#endif
#include "../include/private/socket_p.h"
#include "../include/private/network_interface_p.h"
#include "debugger.h"

QTNG_LOGGER("qtng.socket.win");

#ifdef Q_OS_WIN
    #define QT_SOCKLEN_T int
    #define QT_SOCKOPTLEN_T int
#endif

// The following definitions are copied from the MinGW header mswsock.h which
// was placed in the public domain. The WSASendMsg and WSARecvMsg functions
// were introduced with Windows Vista, so some Win32 headers are lacking them.
// There are no known versions of Windows CE or Embedded that contain them.
#ifndef Q_OS_WINCE
#  ifndef WSAID_WSARECVMSG
typedef INT (WINAPI *LPFN_WSARECVMSG)(SOCKET s, LPWSAMSG lpMsg,
                                      LPDWORD lpdwNumberOfBytesRecvd,
                                      LPWSAOVERLAPPED lpOverlapped,
                                      LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
#    define WSAID_WSARECVMSG {0xf689d7c8,0x6f1f,0x436b,{0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}}
#  endif
#  ifndef WSAID_WSASENDMSG
typedef struct {
  LPWSAMSG lpMsg;
  DWORD dwFlags;
  LPDWORD lpNumberOfBytesSent;
  LPWSAOVERLAPPED lpOverlapped;
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine;
} WSASENDMSG, *LPWSASENDMSG;

typedef INT (WSAAPI *LPFN_WSASENDMSG)(SOCKET s, LPWSAMSG lpMsg, DWORD dwFlags,
                                      LPDWORD lpNumberOfBytesSent,
                                      LPWSAOVERLAPPED lpOverlapped,
                                      LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

#    define WSAID_WSASENDMSG {0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}}
#  endif
#endif

//Some distributions of mingw (including 4.7.2 from mingw.org) are missing this from headers.
//Also microsoft headers don't include it when building on XP and earlier.
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#ifndef IP_HOPLIMIT
#define IP_HOPLIMIT               21 // Receive packet hop limit.
#endif

#if defined(SOCKET_DEBUG)

static void verboseWSErrorDebug(int r)
{
    switch (r) {
        case WSANOTINITIALISED : qDebug("WSA error : WSANOTINITIALISED"); break;
        case WSAEINTR: qDebug("WSA error : WSAEINTR"); break;
        case WSAEBADF: qDebug("WSA error : WSAEBADF"); break;
        case WSAEACCES: qDebug("WSA error : WSAEACCES"); break;
        case WSAEFAULT: qDebug("WSA error : WSAEFAULT"); break;
        case WSAEINVAL: qDebug("WSA error : WSAEINVAL"); break;
        case WSAEMFILE: qDebug("WSA error : WSAEMFILE"); break;
        case WSAEWOULDBLOCK: qDebug("WSA error : WSAEWOULDBLOCK"); break;
        case WSAEINPROGRESS: qDebug("WSA error : WSAEINPROGRESS"); break;
        case WSAEALREADY: qDebug("WSA error : WSAEALREADY"); break;
        case WSAENOTSOCK: qDebug("WSA error : WSAENOTSOCK"); break;
        case WSAEDESTADDRREQ: qDebug("WSA error : WSAEDESTADDRREQ"); break;
        case WSAEMSGSIZE: qDebug("WSA error : WSAEMSGSIZE"); break;
        case WSAEPROTOTYPE: qDebug("WSA error : WSAEPROTOTYPE"); break;
        case WSAENOPROTOOPT: qDebug("WSA error : WSAENOPROTOOPT"); break;
        case WSAEPROTONOSUPPORT: qDebug("WSA error : WSAEPROTONOSUPPORT"); break;
        case WSAESOCKTNOSUPPORT: qDebug("WSA error : WSAESOCKTNOSUPPORT"); break;
        case WSAEOPNOTSUPP: qDebug("WSA error : WSAEOPNOTSUPP"); break;
        case WSAEPFNOSUPPORT: qDebug("WSA error : WSAEPFNOSUPPORT"); break;
        case WSAEAFNOSUPPORT: qDebug("WSA error : WSAEAFNOSUPPORT"); break;
        case WSAEADDRINUSE: qDebug("WSA error : WSAEADDRINUSE"); break;
        case WSAEADDRNOTAVAIL: qDebug("WSA error : WSAEADDRNOTAVAIL"); break;
        case WSAENETDOWN: qDebug("WSA error : WSAENETDOWN"); break;
        case WSAENETUNREACH: qDebug("WSA error : WSAENETUNREACH"); break;
        case WSAENETRESET: qDebug("WSA error : WSAENETRESET"); break;
        case WSAECONNABORTED: qDebug("WSA error : WSAECONNABORTED"); break;
        case WSAECONNRESET: qDebug("WSA error : WSAECONNRESET"); break;
        case WSAENOBUFS: qDebug("WSA error : WSAENOBUFS"); break;
        case WSAEISCONN: qDebug("WSA error : WSAEISCONN"); break;
        case WSAENOTCONN: qDebug("WSA error : WSAENOTCONN"); break;
        case WSAESHUTDOWN: qDebug("WSA error : WSAESHUTDOWN"); break;
        case WSAETOOMANYREFS: qDebug("WSA error : WSAETOOMANYREFS"); break;
        case WSAETIMEDOUT: qDebug("WSA error : WSAETIMEDOUT"); break;
        case WSAECONNREFUSED: qDebug("WSA error : WSAECONNREFUSED"); break;
        case WSAELOOP: qDebug("WSA error : WSAELOOP"); break;
        case WSAENAMETOOLONG: qDebug("WSA error : WSAENAMETOOLONG"); break;
        case WSAEHOSTDOWN: qDebug("WSA error : WSAEHOSTDOWN"); break;
        case WSAEHOSTUNREACH: qDebug("WSA error : WSAEHOSTUNREACH"); break;
        case WSAENOTEMPTY: qDebug("WSA error : WSAENOTEMPTY"); break;
        case WSAEPROCLIM: qDebug("WSA error : WSAEPROCLIM"); break;
        case WSAEUSERS: qDebug("WSA error : WSAEUSERS"); break;
        case WSAEDQUOT: qDebug("WSA error : WSAEDQUOT"); break;
        case WSAESTALE: qDebug("WSA error : WSAESTALE"); break;
        case WSAEREMOTE: qDebug("WSA error : WSAEREMOTE"); break;
        case WSAEDISCON: qDebug("WSA error : WSAEDISCON"); break;
        default: qDebug("WSA error : Unknown"); break;
    }
    qErrnoWarning(r, "more details");
}

/*
    Returns a human readable representation of the first \a len
    characters in \a data.
*/
static QByteArray qt_prettyDebug(const char *data, int len, int maxLength)
{
    if (!data) return "(null)";
    QByteArray out;
    for (int i = 0; i < len; ++i) {
        char c = data[i];
        if (isprint(int(uchar(c)))) {
            out += c;
        } else switch (c) {
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            QString tmp = QString::asprintf("\\%o", c);
            out += tmp.toLatin1().constData();
        }
    }

    if (len < maxLength)
        out += "...";

    return out;
}


#define WS_ERROR_DEBUG(x) verboseWSErrorDebug(x);
#else
#define WS_ERROR_DEBUG(x) Q_UNUSED(x)

#endif

#ifndef AF_INET6
#define AF_INET6        23              /* Internetwork Version 6 */
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR)) /* disallow local address reuse */
#endif


QTNETWORKNG_NAMESPACE_BEGIN

union qt_sockaddr {
    sockaddr a;
    sockaddr_in a4;
    sockaddr_in6 a6;
};


/*
    Extracts the port and address from a sockaddr, and stores them in
    \a port and \a addr if they are non-null.
*/
static inline void qt_socket_getPortAndAddress(SOCKET socketDescriptor, const qt_sockaddr *sa, quint16 *port, HostAddress *address)
{
    if (sa->a.sa_family == AF_INET6) {
        const sockaddr_in6 *sa6 = &sa->a6;
        IPv6Address tmp;
        for (int i = 0; i < 16; ++i)
            tmp.c[i] = sa6->sin6_addr.s6_addr[i];
        if (address) {
            HostAddress a;
            a.setAddress(tmp);
            if (sa6->sin6_scope_id)
                a.setScopeId(QString::number(sa6->sin6_scope_id));
            *address = a;
        }
        if (port)
            WSANtohs(socketDescriptor, sa6->sin6_port, port);
    } else if (sa->a.sa_family == AF_INET) {
        const sockaddr_in *sa4 = &sa->a4;
        unsigned long addr;
        WSANtohl(socketDescriptor, sa4->sin_addr.s_addr, &addr);
        HostAddress a;
        a.setAddress(addr);
        if (address)
            *address = a;
        if (port)
            WSANtohs(socketDescriptor, sa4->sin_port, port);
    } else {
        qtng_warning << "qt_socket_getPortAndAddress can only handle AF_INET6 and AF_INET";
    }
}

static void convertToLevelAndOption(Socket::SocketOption opt,
                                    HostAddress::NetworkLayerProtocol socketProtocol, int &level, int &n)
{
    n = 0;
    level = SOL_SOCKET; // default

    switch (opt) {
    case Socket::NonBlockingSocketOption:      // WSAIoctl
    case Socket::TypeOfServiceOption:          // not supported
    case Socket::MaxStreamsSocketOption:
        Q_UNREACHABLE();

    case Socket::ReceiveBufferSizeSocketOption:
        n = SO_RCVBUF;
        break;
    case Socket::SendBufferSizeSocketOption:
        n = SO_SNDBUF;
        break;
    case Socket::BroadcastSocketOption:
        n = SO_BROADCAST;
        break;
    case Socket::AddressReusable:
        n = SO_REUSEADDR;
        break;
    case Socket::BindExclusively:
        n = SO_EXCLUSIVEADDRUSE;
        break;
    case Socket::ReceiveOutOfBandData:
        n = SO_OOBINLINE;
        break;
    case Socket::LowDelayOption:
        level = IPPROTO_TCP;
        n = TCP_NODELAY;
        break;
    case Socket::KeepAliveOption:
        n = SO_KEEPALIVE;
        break;
    case Socket::MulticastTtlOption:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            level = IPPROTO_IPV6;
            n = IPV6_MULTICAST_HOPS;
        } else {
            level = IPPROTO_IP;
            n = IP_MULTICAST_TTL;
        }
        break;
    case Socket::MulticastLoopbackOption:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            level = IPPROTO_IPV6;
            n = IPV6_MULTICAST_LOOP;
        } else {
            level = IPPROTO_IP;
            n = IP_MULTICAST_LOOP;
        }
        break;
    case Socket::ReceivePacketInformation:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            level = IPPROTO_IPV6;
            n = IPV6_PKTINFO;
        } else {
            level = IPPROTO_IP;
            n = IP_PKTINFO;
        }
        break;
    case Socket::ReceiveHopLimit:
        if (socketProtocol == HostAddress::IPv6Protocol) {
            level = IPPROTO_IPV6;
            n = IPV6_HOPLIMIT;
        } else {
            level = IPPROTO_IP;
            n = IP_HOPLIMIT;
        }
        break;
    case Socket::PathMtuSocketOption:
        break;
    }
}


static inline Socket::SocketType qt_socket_getType(qintptr socketDescriptor)
{
    int value = 0;
    QT_SOCKLEN_T valueSize = sizeof(value);
    if (::getsockopt(static_cast<SOCKET>(socketDescriptor), SOL_SOCKET, SO_TYPE, (char *) &value, &valueSize) != 0) {
        WS_ERROR_DEBUG(WSAGetLastError());
    } else {
        if (value == SOCK_STREAM) {
            return Socket::TcpSocket;
        } else if (value == SOCK_DGRAM) {
            return Socket::UdpSocket;
        }
    }
    return Socket::UnknownSocketType;
}


inline uint scopeIdFromString(const QString &scopeid)
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    return static_cast<uint>(NetworkInterface::interfaceIndexFromName(scopeid));
#else
    return NetworkInterface::interfaceFromName(scopeid).index();
#endif
}


namespace {
namespace SetSALen {
    template <typename T> void set(T *sa, typename QtPrivate::QEnableIf<(&T::sa_len, true), int>::Type len)
    { sa->sa_len = len; }
    template <typename T> void set(T *sin6, typename QtPrivate::QEnableIf<(&T::sin6_len, true), int>::Type len)
    { sin6->sin6_len = len; }
    template <typename T> void set(T *, ...) {}
}
}

bool SocketPrivate::setPortAndAddress(quint16 port, const HostAddress &address, qt_sockaddr *aa, int *sockAddrSize)
{
    if ((address.protocol() == HostAddress::IPv6Protocol
        || address.protocol() == HostAddress::AnyIPProtocol)
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
    } else if ((address.protocol() == HostAddress::IPv4Protocol
        || address.protocol() == HostAddress::AnyIPProtocol)
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

bool SocketPrivate::createSocket()
{
    //Windows XP and 2003 support IPv6 but not dual stack sockets
    int protocol = this->protocol == HostAddress::IPv6Protocol ? AF_INET6 : AF_INET;
    int type = (this->type == Socket::UdpSocket) ? SOCK_DGRAM : SOCK_STREAM;

    // MSDN KB179942 states that on winnt 4 WSA_FLAG_OVERLAPPED is needed if socket is to be non blocking
    // and recomends alwasy doing it for cross windows version comapablity.

    // WSA_FLAG_NO_HANDLE_INHERIT is atomic (like linux O_CLOEXEC), but requires windows 7 SP 1 or later
    // SetHandleInformation is supported since W2K but isn't atomic
#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

    SOCKET socket = ::WSASocketW(protocol, type, 0, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
    // previous call fails if the windows 7 service pack 1 or hot fix isn't installed.

    // Try the old API if the new one failed on Windows 7
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
    if (socket == INVALID_SOCKET && QOperatingSystemVersion::current() < QOperatingSystemVersion::Windows8) {
#else
    if (socket == INVALID_SOCKET && QSysInfo::windowsVersion() < QSysInfo::WV_WINDOWS8) {
#endif
        socket = ::WSASocketW(protocol, type, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
#ifdef HANDLE_FLAG_INHERIT
        if (socket != INVALID_SOCKET) {
            // make non inheritable the old way
            SetHandleInformation((HANDLE)socket, HANDLE_FLAG_INHERIT, 0);
        }
#endif
    }

    if (socket == INVALID_SOCKET) {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        switch (err) {
        case WSANOTINITIALISED:
            //###
            break;
        case WSAEAFNOSUPPORT:
        case WSAESOCKTNOSUPPORT:
        case WSAEPROTOTYPE:
        case WSAEINVAL:
            setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
            break;
        case WSAEMFILE:
        case WSAENOBUFS:
            setError(Socket::SocketResourceError, ResourceErrorString);
            break;
        default:
            break;
        }
        return false;
    }

    if (this->type == Socket::UdpSocket) {
        // enable new behavior using
        // SIO_UDP_CONNRESET
        DWORD dwBytesReturned = 0;
        int bNewBehavior = 1;
        if (::WSAIoctl(socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
                       NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
            // not to worry isBogusUdpReadNotification() should handle this otherwise
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
        }
    }

//    // get the pointer to sendmsg and recvmsg
//    DWORD bytesReturned;
//    GUID recvmsgguid = WSAID_WSARECVMSG;
//    if (::WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
//                 &recvmsgguid, sizeof(recvmsgguid),
//                 &recvmsg, sizeof(recvmsg), &bytesReturned, NULL, NULL) == SOCKET_ERROR)
//        recvmsg = 0;

//    GUID sendmsgguid = WSAID_WSASENDMSG;
//    if (WSAIoctl(socketDescriptor, SIO_GET_EXTENSION_FUNCTION_POINTER,
//                 &sendmsgguid, sizeof(sendmsgguid),
//                 &sendmsg, sizeof(sendmsg), &bytesReturned, NULL, NULL) == SOCKET_ERROR)
//        sendmsg = 0;

    fd = static_cast<qintptr>(socket);
    if (socket == INVALID_SOCKET) {
        return false;
    } else {
        if(!setNonblocking()) {
            close();
            return false;
        }
    }
    return true;
}


bool SocketPrivate::isValid() const
{
    if (!checkState()) {
        return false;
    }
    int error = 0;
    int len = sizeof (error);
    int result = getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len);
    return result == 0 && error == 0;
}


bool SocketPrivate::bind(const HostAddress &a, quint16 port, Socket::BindMode mode)
{
    Q_UNUSED(mode);
    if (!checkState())  {
        return false;
    }
    if (state != Socket::UnconnectedState) {
        return false;
    }

    HostAddress address = a;
    if (address.protocol() == HostAddress::IPv4Protocol) {
        if ((address.toIPv4Address(nullptr) & 0xffff0000) == 0xefff0000) {
            // binding to a multicast address
            address = HostAddress(HostAddress::AnyIPv4);
        }
    }

    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize = 0;
    if (!setPortAndAddress(port, address, &aa, &sockAddrSize)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return false;
    }

    if (protocol == HostAddress::IPv6Protocol) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
        if (QOperatingSystemVersion::current() >= QOperatingSystemVersion(QOperatingSystemVersion::Windows, 6, 0)) {
#else
        if (QSysInfo::windowsVersion() >= QSysInfo::WV_6_0) {
#endif
            // The default may change in future, so set it explicitly
            int ipv6only = 1;
            ::setsockopt(static_cast<SOCKET>(fd), IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );
        }
    }


    int bindResult = ::bind(static_cast<SOCKET>(fd), &aa.a, sockAddrSize);
    if (bindResult == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT
            && address.protocol() == HostAddress::AnyIPProtocol) {
        // retry with v4
        aa.a4.sin_family = AF_INET;
        aa.a4.sin_port = htons(port);
        aa.a4.sin_addr.s_addr = htonl(address.toIPv4Address(nullptr));
        sockAddrSize = sizeof(aa.a4);
        bindResult = ::bind(static_cast<SOCKET>(fd), &aa.a, sockAddrSize);
    }
    if (bindResult == SOCKET_ERROR) {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        switch (err) {
        case WSANOTINITIALISED:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        case WSAEADDRINUSE:
        case WSAEINVAL:
            setError(Socket::AddressInUseError, AddressInuseErrorString);
            break;
        case WSAEACCES:
            setError(Socket::SocketAccessError, AddressProtectedErrorString);
            break;
        case WSAEADDRNOTAVAIL:
            setError(Socket::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
            break;
        default:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        }

#if defined (SOCKET_DEBUG)
        qDebug("SocketPrivate::bind(%s, %i) == false (%s)",
               address.toString().toLatin1().constData(), port, errorString.toLatin1().constData());
#endif
        return false;
    }

#if defined (SOCKET_DEBUG)
    qDebug("SocketPrivate::bind(%s, %i) == true",
           address.toString().toLatin1().constData(), port);
#endif
    state = Socket::BoundState;

    if (port == 0) {
        fetchConnectionParameters();
    }
    return true;
}


static bool setErrorFromWASError(SocketPrivate *d, int err)
{
    switch (err) {
    case WSANOTINITIALISED:
        d->setError(Socket::UnknownSocketError, SocketPrivate::UnknownSocketErrorString);
    case WSAEISCONN:
        d->state = Socket::ConnectedState;
        d->fetchConnectionParameters();
        return true;
    case WSAEADDRINUSE:
        d->setError(Socket::NetworkError, SocketPrivate::AddressInuseErrorString);
        break;
    case WSAECONNREFUSED:
        d->setError(Socket::ConnectionRefusedError, SocketPrivate::ConnectionRefusedErrorString);
        break;
    case WSAETIMEDOUT:
        d->setError(Socket::NetworkError, SocketPrivate::ConnectionTimeOutErrorString);
        break;
    case WSAEACCES:
        d->setError(Socket::SocketAccessError, SocketPrivate::AccessErrorString);
        break;
    case WSAEHOSTUNREACH:
        d->setError(Socket::NetworkError, SocketPrivate::HostUnreachableErrorString);
        break;
    case WSAENETUNREACH:
        d->setError(Socket::NetworkError, SocketPrivate::NetworkUnreachableErrorString);
        break;
    case WSAEINVAL:
    case WSAEALREADY:
        d->setError(Socket::UnfinishedSocketOperationError, SocketPrivate::InvalidSocketErrorString);
        break;
    default:
        d->setError(Socket::UnknownSocketError, SocketPrivate::UnknownSocketErrorString);
        break;
    }
    d->state = Socket::UnconnectedState;
    return false;
}


bool SocketPrivate::connect(const HostAddress &address, quint16 port)
{
    //if (!checkState()) {
    if (fd == 0) {
        return false;
    }
    if (state != Socket::UnconnectedState && state != Socket::BoundState && state != Socket::ConnectingState)
        return false;

    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize = 0;
    if (!setPortAndAddress(port, address, &aa, &sockAddrSize)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return false;
    }

    if (protocol == HostAddress::IPv6Protocol) {
        //IPV6_V6ONLY option must be cleared to connect to a V4 mapped address
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
        if (QOperatingSystemVersion::current() >= QOperatingSystemVersion(QOperatingSystemVersion::Windows, 6, 0)) {
#else
        if (QSysInfo::windowsVersion() >= QSysInfo::WV_6_0) {
#endif
            DWORD ipv6only = 1;
            ipv6only = ::setsockopt(static_cast<SOCKET>(fd), IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );
        }
    }

    state = Socket::ConnectingState;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    int tries = 0;
    while (true) {
        if (!checkState())
            return false;
        if (state != Socket::ConnectingState)
            return false;

        int connectResult = ::WSAConnect(static_cast<SOCKET>(fd), &aa.a, sockAddrSize, 0,0,0,0);
        if (connectResult == SOCKET_ERROR) {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
            switch (err) {
            case WSANOTINITIALISED:
                break;
            case WSAEWOULDBLOCK:
                // If WSAConnect returns WSAEWOULDBLOCK on the second
                // connection attempt, we have to check SO_ERROR's
                // value to detect ECONNREFUSED. If we don't get
                // ECONNREFUSED, we'll have to treat it as an
                // unfinished operation.
                ++tries;
                if (tries >= 2) {
                    int value = 0;
                    QT_SOCKLEN_T valueSize = sizeof(value);
                    if (::getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR, (char *) &value, &valueSize) == 0) {
                        if (value != NOERROR) {
                            // MSDN says getsockopt with SO_ERROR clears the error, but it's not actually cleared
                            // and this can affect all subsequent WSAConnect attempts, so clear it now.
                            const int val = NO_ERROR;
                            ::setsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR, reinterpret_cast<const char*>(&val), sizeof val);
                            if (value != WSAEWOULDBLOCK) {
                                return setErrorFromWASError(this, value);
                            }
                        }
                    }
                }
#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)
                    Q_FALLTHROUGH();
#endif
            case WSAEINPROGRESS:
                break;
            default:
                return setErrorFromWASError(this, err);
            }
            if (!watcher.start()) {
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                return false;
            }
        } else {
            state = Socket::ConnectedState;
            fetchConnectionParameters();
            return true;
        }
    }
}


void SocketPrivate::close()
{
    if (fd > 0) {
        ::closesocket(static_cast<SOCKET>(fd));
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
        ::closesocket(static_cast<SOCKET>(fd));
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
    if (!checkState()) {
        return false;
    }
    if (state != Socket::BoundState) {
        return false;
    }
    if (::listen(static_cast<SOCKET>(fd), backlog) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        switch (err) {
        case WSANOTINITIALISED:
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            break;
        case WSAEADDRINUSE:
            setError(Socket::AddressInUseError, PortInuseErrorString);
            break;
        default:
            break;
        }

    #if defined (SOCKET_DEBUG)
            qDebug("SocketPrivate::listen(%i) == false (%s)",
                   backlog, errorString.toLatin1().constData());
    #endif
        return false;
    }

    #if defined (QNATIVESOCKETENGINE_DEBUG)
        qDebug("SocketPrivate::listen(%i) == true", backlog);
    #endif

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

    if (!checkState()) {
        return false;
    }

    qt_sockaddr sa;
    QT_SOCKLEN_T sockAddrSize = sizeof(sa);

    // Determine local address
    memset(&sa, 0, sizeof(sa));
    if (::getsockname(static_cast<SOCKET>(fd), &sa.a, &sockAddrSize) == 0) {
        qt_socket_getPortAndAddress(static_cast<SOCKET>(fd), &sa, &localPort, &localAddress);
        // Determine protocol family
        switch (sa.a.sa_family) {
        case AF_INET:
            this->protocol = HostAddress::IPv4Protocol;
            break;
        case AF_INET6:
            this->protocol = HostAddress::IPv6Protocol;
            break;
        default:
            this->protocol = HostAddress::UnknownNetworkLayerProtocol;
            break;
        }
    } else {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        if (err == WSAENOTSOCK) {
            setError(Socket::UnsupportedSocketOperationError, InvalidSocketErrorString);
            return false;
        }
    }

    // Some Windows kernels return a v4-mapped HostAddress::AnyIPv4 as a
    // local address of the socket which bound on both IPv4 and IPv6 interfaces.
    // This address does not match to any special address and should not be used
    // to send the data. So, replace it with HostAddress::Any.
    if (this->protocol == HostAddress::IPv6Protocol) {
        bool ok = false;
        const quint32 localIPv4 = localAddress.toIPv4Address(&ok);
        if (ok && localIPv4 == INADDR_ANY) {
            localAddress = HostAddress::Any;
        }
    }

    memset(&sa, 0, sizeof(sa));
    if (::getpeername(static_cast<SOCKET>(fd), &sa.a, &sockAddrSize) == 0) {
        qt_socket_getPortAndAddress(static_cast<SOCKET>(fd), &sa, &peerPort, &peerAddress);
    } else {
        WS_ERROR_DEBUG(WSAGetLastError());
    }

    this->type = qt_socket_getType(fd);

#if defined (SOCKET_DEBUG)
    QString socketProtocolStr = QString::fromLatin1("UnknownProtocol");
    if (protocol == HostAddress::IPv4Protocol) socketProtocolStr = QString::fromLatin1("IPv4Protocol");
    else if (protocol == HostAddress::IPv6Protocol) socketProtocolStr = QString::fromLatin1("IPv6Protocol");

    QString socketTypeStr = QString::fromLatin1("UnknownSocketType");
    if (type == Socket::TcpSocket) socketTypeStr = QString::fromLatin1("TcpSocket");
    else if (type == Socket::UdpSocket) socketTypeStr = QString::fromLatin1("UdpSocket");

    qDebug("SocketPrivate::fetchConnectionParameters() localAddress == %s, localPort = %i, peerAddress == %s, peerPort = %i, socketProtocol == %s, socketType == %s", localAddress.toString().toLatin1().constData(), localPort, peerAddress.toString().toLatin1().constData(), peerPort, socketProtocolStr.toLatin1().constData(), socketTypeStr.toLatin1().constData());
#endif

    return true;
}

qint32 SocketPrivate::peek(char *data, qint32 size)
{
    if (fd == -1) {
        return false;
    }
    WSABUF buf;
    buf.buf = data;
    buf.len = size;
    DWORD flags = MSG_PEEK;
    DWORD bytesRead = 0;
    if (::WSARecv(static_cast<SOCKET>(fd), &buf, 1, &bytesRead, &flags, nullptr, nullptr) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEINPROGRESS ||
            err == WSAEWOULDBLOCK)
            return 0; /* connection still in place */
        if (err == WSAECONNRESET ||
            err == WSAECONNABORTED ||
            err == WSAENETDOWN ||
            err == WSAENETRESET ||
            err == WSAESHUTDOWN ||
            err == WSAETIMEDOUT ||
            err == WSAENOTCONN)
            return -1; /* connection has been closed */
    } else if (bytesRead == 0) { /* connection has been closed */
        return -1;
    } else if (bytesRead > 0) { /* connection still in place */
        return bytesRead;

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
            return total == 0 ? -1: total;
        }
        WSABUF buf;
        buf.buf = data + total;
        buf.len = static_cast<quint32>(size - total);
        DWORD flags = 0;
        DWORD bytesRead = 0;
        if (::WSARecv(static_cast<SOCKET>(fd), &buf, 1, &bytesRead, &flags, nullptr, nullptr) ==  SOCKET_ERROR) {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
            switch (err) {
            case WSAEWOULDBLOCK:
                break;
            case WSAECONNRESET:
            case WSAECONNABORTED:
                if(type == Socket::TcpSocket) {
                    setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
                    // close();
                }
                return total;
            case WSAEBADF:
            case WSAEINVAL:
            default:
                setError(Socket::NetworkError, ConnectionResetErrorString);
                close();
                return total == 0 ? -1 : total;
            }
        } else if(bytesRead == 0 && type == Socket::TcpSocket) {
            setError(Socket::RemoteHostClosedError, RemoteHostClosedErrorString);
            // close();
            return total;
        } else { // bytesRead > 0 || type == Socket::UdpSocket
            total += bytesRead;
            if(all) {
                continue;
            } else {
                return total;
            }
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            close();
            return total == 0 ? -1 : total;
        }
    }
    return total;
}

qint32 SocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    qint32 ret = 0;
    qint32 bytesToSend = qMin<qint32>(49152, size);
    while (bytesToSend > 0) {
        if (!checkState()) {
            return ret == 0 ? -1: ret;
        }

        WSABUF buf;
        buf.buf = const_cast<char*>(data + ret);
        buf.len = static_cast<u_long>(bytesToSend);
        DWORD flags = 0;
        DWORD bytesWritten = 0;

        int socketRet = ::WSASend(static_cast<SOCKET>(fd), &buf, 1, &bytesWritten, flags, nullptr, nullptr);
        ret += bytesWritten;
        bytesToSend = qMin<qint32>(49152, size - ret);

        if (socketRet != SOCKET_ERROR) {
            if (ret == size || !all) {
                return ret;
            } else if (ret > size) {
                qWarning("sent too much data. there must be something went wrong.");
                return size;
            } else {
                continue;
            }
        } else {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
            switch(err) {
            case WSAEWOULDBLOCK:
            case WSAEINPROGRESS:
                if(ret > 0 && !all) {
                    return ret;
                }
                break;
            case WSANOTINITIALISED:
            case WSAEACCES:
            case WSAEADDRNOTAVAIL:
            case WSAEAFNOSUPPORT:
            case WSAENOTSOCK:
                setError(Socket::SocketAccessError, AccessErrorString);
                return -1;
            case WSAEDESTADDRREQ: // only happen in sendto()
            case WSAESHUTDOWN:
                setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                close();
                return -1;
            case WSAEMSGSIZE: // must be udp socket, need not close()
                setError(Socket::DatagramTooLargeError, DatagramTooLargeErrorString);
                return ret == 0 ? -1 : ret;
            case WSAENOBUFS:
                // this function used to not send more than 49152 per call to WSASendTo
                // to avoid getting a WSAENOBUFS. However this is a performance regression
                // and we think it only appears with old windows versions. We now handle the
                // WSAENOBUFS and hope it never appears anyway.
                // just go on, the next loop run we will try a smaller number
                break;
            case WSAECONNRESET:
            case WSAECONNABORTED:
            case WSAENOTCONN:
                setError(Socket::NetworkError, WriteErrorString);
                //close();
                return ret == 0 ? -1 : ret;
            case WSAEHOSTUNREACH:
                setError(Socket::NetworkError, HostUnreachableErrorString);
                close();
                return -1;
            case WSAENETDOWN:
                setError(Socket::NetworkError, NetworkDroppedConnectionErrorString);
                close();
                return -1;
            case WSAENETRESET:
                setError(Socket::NetworkError, ConnectionResetErrorString);
                close();
                return -1;
            case WSAENETUNREACH:
                setError(Socket::NetworkError, NetworkUnreachableErrorString);
                close();
                return -1;
            case WSAEFAULT:
            case WSAEINTR:
            case WSAEINVAL:
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                close();
                return -1;
            }
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            close();
            return -1;
        }
    }
    return ret;
}


qint32 SocketPrivate::recvfrom(char *data, qint32 size, HostAddress *addr, quint16 *port)
{
    if (!checkState() || size < 0) {
        return -1;
    }

    WSAMSG msg;
    WSABUF buf;
    qt_sockaddr aa;
    char c;
    memset(&msg, 0, sizeof(msg));
    memset(&aa, 0, sizeof(aa));

    // we need to receive at least one byte, even if our user isn't interested in it
    buf.buf = size ? data : &c;
    buf.len = size ? static_cast<quint32>(size) : 1;
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.name = reinterpret_cast<LPSOCKADDR>(&aa);
    msg.namelen = sizeof(aa);

    DWORD flags = 0;
    DWORD bytesRead = 0;
    qint32 ret;

    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);

    while (true) {
        if (!checkState()) {
            return -1;
        }
        ret = ::WSARecvFrom(static_cast<SOCKET>(fd), &buf, 1, &bytesRead, &flags,
                            msg.name, &msg.namelen, nullptr, nullptr);
//        if (static_cast<qint32>(bytesRead) < 0) {
//            qWarning("recv too much data.");
//            return -1;
//        }
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEMSGSIZE) {
                // it is ok the buffer was to small if bytesRead is larger than
                // maxLength then assume bytes read is really maxLenth
                ret = qMin(size, static_cast<qint32>(bytesRead));
            } else {
                WS_ERROR_DEBUG(err);
                switch (err) {
                case WSAEINPROGRESS:
                case WSAEINTR:
                case WSAEWOULDBLOCK:
                    break;
                case WSAECONNRESET:
                    if (type == Socket::TcpSocket) {
                        setError(Socket::ConnectionRefusedError, ConnectionResetErrorString);
                        abort();
                        return -1;
                    } else {
                        break; // windows throws this error, just kidding me?
                    }
                case WSAENOTCONN: // not connected for tcp
                case WSAEINVAL: // not bound for udp
                    setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                    // need not close()
                    return -1;
                case WSAENETRESET:
                    if(type == Socket::TcpSocket) {
                        setError(Socket::NetworkError, NetworkDroppedConnectionErrorString);
                        abort();
                    } else {
                        setError(Socket::NetworkError, QString::fromLatin1("the time to live has expired."));
                        // need not close()
                    }
                    return -1;
                case WSANOTINITIALISED:
                case WSAENETDOWN:
                case WSAEFAULT:
                    setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                    abort();
                    return -1;
                default:
                    setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                    return -1;
                }
            }
        } else {
            ret = static_cast<qint32>(bytesRead);

        }
        if (ret > 0) {
            qt_socket_getPortAndAddress(static_cast<SOCKET>(fd), &aa, port, addr);
#if defined (SOCKET_DEBUG)
            bool printSender = (ret != -1);
            qDebug("SocketPrivate::recvfrom(%p \"%s\", %i, %s, %i) == %i",
                   data, qt_prettyDebug(data, qMin<qint32>(ret, 16), ret).data(), size,
                   printSender ? addr->toString().toLatin1().constData() : "(unknown)",
                   printSender ? *port : 0, ret);
#endif
            return ret;
        } else {
            if (!watcher.start()) {
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                return -1;
            }
        }
    }
}

qint32 SocketPrivate::sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    if (!checkState() || size <= 0) {
        return -1;
    }
    qint32 ret = 0;
    qint32 bytesToSend = size;

    WSAMSG msg;
    WSABUF buf;
    qt_sockaddr aa;
    memset(&aa, 0, sizeof(aa));
    memset(&msg, 0, sizeof(msg));
    if (!setPortAndAddress(port, addr, &aa, &msg.namelen)) {
        setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
        return -1;
    }
    
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.name = &aa.a;

    buf.buf = bytesToSend ? const_cast<char*>(data) : nullptr;
    buf.len = static_cast<u_long>(bytesToSend); // TODO datagram max size!

    DWORD flags = 0;
    DWORD bytesSent = 0;

    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    while (true) {
        if (!checkState()) {
            return -1;
        }
        int socketRet = ::WSASendTo(static_cast<SOCKET>(fd), &buf, 1, &bytesSent, flags,
                                    msg.name, msg.namelen, nullptr, nullptr);
        ret += bytesSent;

        if (socketRet == SOCKET_ERROR) {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
            switch (err) {
            case WSANOTINITIALISED:
            case WSAEACCES:
            case WSAEADDRNOTAVAIL:
            case WSAEAFNOSUPPORT:
            case WSAENOBUFS:
            case WSAENOTSOCK:
                setError(Socket::SocketAccessError, AccessErrorString);
                return -1;
            case WSAECONNRESET:
            case WSAENOTCONN:
            case WSAEDESTADDRREQ:
            case WSAESHUTDOWN:
                setError(Socket::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return -1;
            case WSAEMSGSIZE:
                setError(Socket::DatagramTooLargeError, DatagramTooLargeErrorString);
                return -1;
            case WSAEINPROGRESS:
            case WSAEWOULDBLOCK:
                break;
            case WSAEHOSTUNREACH:
            case WSAEFAULT:
            case WSAEINTR:
            case WSAEINVAL:
            case WSAENETDOWN:
            case WSAENETRESET:
            case WSAENETUNREACH:
            default:
                setError(Socket::NetworkError, SendDatagramErrorString);
                return -1;
            }
        } else {
            if (ret >= size) {
                if (type == Socket::UdpSocket && !localPort && localAddress.isNull()) {
                    fetchConnectionParameters();
                }
                return ret;
            }
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            return -1;
        }
    }
}


QVariant SocketPrivate::option(Socket::SocketOption option) const
{
    if (!checkState())
        return -1;

    // handle non-getsockopt
    switch (option) {
    case Socket::NonBlockingSocketOption:
    case Socket::TypeOfServiceOption:
    case Socket::MaxStreamsSocketOption:
        return -1;
    default:
        break;
    }

#if Q_BYTE_ORDER != Q_LITTLE_ENDIAN
#error code assumes windows is little endian
#endif
    int n, level;
    int v = 0; //note: windows doesn't write to all bytes if the option type is smaller than int
    QT_SOCKOPTLEN_T len = sizeof(v);

    convertToLevelAndOption(option, this->protocol, level, n);
    if (getsockopt(static_cast<SOCKET>(fd), level, n, static_cast<char*>(static_cast<void*>(&v)), &len) == 0)
        return v;
    WS_ERROR_DEBUG(WSAGetLastError());
    return -1;
}

bool SocketPrivate::setTcpKeepalive(bool keepalve, int keepaliveTimeoutSesc, int keepaliveIntervalSesc)
{
    if (!setOption(Socket::KeepAliveOption, keepalve ? 1 : 0)) {
        qtng_debug << "failed to set SO_KEEPALIVE on fd" << fd << "errno:" << WSAGetLastError();
        return false;
    }
#if defined(SIO_KEEPALIVE_VALS)
    struct tcp_keepalive vals;
    DWORD dummy;
    vals.onoff = 1;
    vals.keepalivetime = 1000 * keepaliveTimeoutSesc;
    vals.keepaliveinterval = 1000 * keepaliveIntervalSesc;
    if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, (LPVOID)&vals, sizeof(vals), NULL, 0, &dummy, NULL, NULL) != 0) {
        qtng_debug << "failed to set SIO_KEEPALIVE_VALS on fd" << fd << "errno:" << WSAGetLastError();
        return false;
    }
#endif
    return true;
}

bool SocketPrivate::setOption(Socket::SocketOption option, const QVariant &value)
{
    if (!checkState())
        return false;

    // handle non-setsockopt options
    switch (option) {
    case Socket::SendBufferSizeSocketOption:
        // see QTBUG-30478 SO_SNDBUF should not be used on Vista or later
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
        if (QOperatingSystemVersion::current() >= QOperatingSystemVersion(QOperatingSystemVersion::Windows, 6, 0))
#else
        if (QSysInfo::windowsVersion() >= QSysInfo::WV_VISTA)
#endif
            return false;
        break;
    case Socket::NonBlockingSocketOption:
    case Socket::TypeOfServiceOption:
    case Socket::MaxStreamsSocketOption:
        return false;

    default:
        break;
    }

    int n, level;
    convertToLevelAndOption(option, protocol, level, n);
    if (::setsockopt(static_cast<SOCKET>(fd), level, n, (char*)&value, sizeof(value)) != 0) {
        WS_ERROR_DEBUG(WSAGetLastError());
        return false;
    }
    return true;
}

bool SocketPrivate::setNonblocking()
{
    unsigned long buf = 1;
    unsigned long outBuf;
    DWORD sizeWritten = 0;
    if (::WSAIoctl(static_cast<SOCKET>(fd), FIONBIO, &buf, sizeof(unsigned long), &outBuf,
                   sizeof(unsigned long), &sizeWritten, 0,0) == SOCKET_ERROR) {
        WS_ERROR_DEBUG(WSAGetLastError());
        return false;
    }
    return true;
}


static bool multicastMembershipHelper(SocketPrivate *d, int how6, int how4, const HostAddress &groupAddress,
                                      const NetworkInterface &iface)
{
    int level = 0;
    int sockOpt = 0;
    char *sockArg;
    int sockArgSize;

    ip_mreq mreq4;
    ipv6_mreq mreq6;

    if (groupAddress.protocol() == HostAddress::IPv6Protocol) {
        level = IPPROTO_IPV6;
        sockOpt = how6;
        sockArg = reinterpret_cast<char *>(&mreq6);
        sockArgSize = sizeof(mreq6);
        memset(&mreq6, 0, sizeof(mreq6));
        IPv6Address ip6 = groupAddress.toIPv6Address();
        memcpy(&mreq6.ipv6mr_multiaddr, &ip6, sizeof(ip6));
        mreq6.ipv6mr_interface = iface.index();
    } else if (groupAddress.protocol() == HostAddress::IPv4Protocol) {
        level = IPPROTO_IP;
        sockOpt = how4;
        sockArg = reinterpret_cast<char *>(&mreq4);
        sockArgSize = sizeof(mreq4);
        memset(&mreq4, 0, sizeof(mreq4));
        mreq4.imr_multiaddr.s_addr = htonl(groupAddress.toIPv4Address());

        if (iface.isValid()) {
            const QList<NetworkAddressEntry> &addressEntries = iface.addressEntries();
            bool found = false;
            for (const NetworkAddressEntry &entry : addressEntries) {
                const HostAddress &ip = entry.ip();
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

    int res = setsockopt(static_cast<SOCKET>(d->fd), level, sockOpt, sockArg, sockArgSize);
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
        qWarning("Socket::joinMulticastGroup() should be called only at bound state.");
        return false;
    }
    if (type != Socket::UdpSocket) {
        qWarning("Socket::joinMulticastGroup() only apply to UDP socket type.");
        return false;
    }
    if (protocol == HostAddress::IPv6Protocol && groupAddress.isIPv4()) {
        qWarning("Socket is IPv6 but join to an IPv4 group.");
        return false;
    }
    if (protocol == HostAddress::IPv4Protocol && !groupAddress.isIPv4()) {
        qWarning("Socket is IPv4 but join to an IPv6 group.");
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
        qWarning("Socket::leaveMulticastGroup() should be called only at bound state.");
        return false;
    }
    if (type != Socket::UdpSocket) {
        qWarning("Socket::leaveMulticastGroup() only apply to UDP socket type.");
        return false;
    }
    if (protocol == HostAddress::IPv6Protocol && groupAddress.isIPv4()) {
        qWarning("Socket is IPv6 but leave from an IPv4 group.");
        return false;
    }
    if (protocol == HostAddress::IPv4Protocol && !groupAddress.isIPv4()) {
        qWarning("Socket is IPv4 but leave from an IPv6 group.");
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
        qWarning("Socket::multicastInterface() only apply to UDP socket type.");
        return NetworkInterface();
    }

    if (protocol == HostAddress::IPv6Protocol || protocol == HostAddress::AnyIPProtocol) {
        uint v;
        QT_SOCKLEN_T sizeofv = sizeof(v);
        if (::getsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&v, &sizeofv) == -1)
            return NetworkInterface();
        return NetworkInterface::interfaceFromIndex(v);
    }

    struct in_addr v;
    memset(&v, 0, sizeof(v));
    QT_SOCKLEN_T sizeofv = sizeof(v);
    if (::getsockopt(static_cast<SOCKET>(fd), IPPROTO_IP, IP_MULTICAST_IF, (char *)&v, &sizeofv) == -1) {
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
        qWarning("Socket::multicastInterface() only apply to UDP socket type.");
        return false;
    }

    if (protocol == HostAddress::IPv6Protocol || protocol == HostAddress::AnyIPProtocol) {
        uint v = iface.index();
        return (::setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *) &v, sizeof(v)) != -1);
    }

    struct in_addr v;
    if (iface.isValid()) {
        QList<NetworkAddressEntry> entries = iface.addressEntries();
        for (int i = 0; i < entries.count(); ++i) {
            const NetworkAddressEntry &entry = entries.at(i);
            const HostAddress &ip = entry.ip();
            if (ip.protocol() == HostAddress::IPv4Protocol) {
                v.s_addr = htonl(ip.toIPv4Address());
                int r = ::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (char *) &v, sizeof(v));
                if (r != -1) {
                    return true;
                }
            }
        }
        return false;
    }

    v.s_addr = INADDR_ANY;
    return (::setsockopt(static_cast<SOCKET>(fd), IPPROTO_IP, IP_MULTICAST_IF, (char *) &v, sizeof(v)) != -1);
}


Socket *SocketPrivate::accept()
{
    if (!checkState()) {
        return nullptr;
    }
    if (state != Socket::ListeningState || type != Socket::TcpSocket)
        return nullptr;

    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    while (true) {
        SOCKET acceptedDescriptor = WSAAccept(static_cast<SOCKET>(fd), nullptr, nullptr, nullptr, 0);
        if (acceptedDescriptor == static_cast<SOCKET>(SOCKET_ERROR)) {
            int err = WSAGetLastError();
            switch (err) {
            case WSAEACCES:
                setError(Socket::SocketAccessError, AccessErrorString);
                return nullptr;
            case WSAECONNREFUSED:
                setError(Socket::ConnectionRefusedError, ConnectionRefusedErrorString);
                return nullptr;
            case WSAECONNRESET:
                setError(Socket::NetworkError, RemoteHostClosedErrorString);
                return nullptr;
            case WSAENETDOWN:
                setError(Socket::NetworkError, NetworkUnreachableErrorString);
                return nullptr;
            case WSAENOTSOCK:
                setError(Socket::SocketResourceError, NotSocketErrorString);
                return nullptr;
            case WSAEINVAL:
            case WSAEOPNOTSUPP:
                setError(Socket::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
                return nullptr;
            case WSAEFAULT:
            case WSAEMFILE:
            case WSAENOBUFS:
                setError(Socket::SocketResourceError, ResourceErrorString);
                return nullptr;
            case WSAEINPROGRESS:
            case WSAEWOULDBLOCK:
                break;
            default:
                setError(Socket::UnknownSocketError, UnknownSocketErrorString);
                return nullptr;
            }
        } else {
            Socket *conn = new Socket(static_cast<qintptr>(acceptedDescriptor));
            return conn;
        }
        if (!watcher.start()) {
            setError(Socket::UnknownSocketError, UnknownSocketErrorString);
            return nullptr;
        }
    }
}


QTNETWORKNG_NAMESPACE_END
