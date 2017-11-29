#define NOMINMAX 1
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <QtCore/QSysInfo>
#include <QtNetwork/QNetworkInterface>
#include "../include/socket_ng_p.h"


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

#if defined(QSOCKETNG_DEBUG)

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
            QString tmp;
            tmp.sprintf("\\%o", c);
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


static QAtomicInt refcount;

void initWinSock()
{
    if(refcount.fetchAndAddAcquire(1) > 0) {
        return;
    }
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        qDebug("WSAStartup failed with error: %d\n", err);
    }
}

void freeWinSock()
{
    if(refcount.fetchAndSubAcquire(1) > 0) {
        return;
    }
    WSACleanup();
}

/*
    Extracts the port and address from a sockaddr, and stores them in
    \a port and \a addr if they are non-null.
*/
static inline void qt_socket_getPortAndAddress(SOCKET socketDescriptor, const qt_sockaddr *sa, quint16 *port, QHostAddress *address)
{
    if (sa->a.sa_family == AF_INET6) {
        const sockaddr_in6 *sa6 = &sa->a6;
        Q_IPV6ADDR tmp;
        for (int i = 0; i < 16; ++i)
            tmp.c[i] = sa6->sin6_addr.s6_addr[i];
        if (address) {
            QHostAddress a;
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
        QHostAddress a;
        a.setAddress(addr);
        if (address)
            *address = a;
        if (port)
            WSANtohs(socketDescriptor, sa4->sin_port, port);
    } else {
        qFatal("qt_socket_getPortAndAddress can only handle AF_INET6 and AF_INET");
    }
}

static void convertToLevelAndOption(QSocketNg::SocketOption opt,
                                    QSocketNg::NetworkLayerProtocol socketProtocol, int &level, int &n)
{
    n = 0;
    level = SOL_SOCKET; // default

    switch (opt) {
    case QSocketNg::NonBlockingSocketOption:      // WSAIoctl
    case QSocketNg::TypeOfServiceOption:          // not supported
    case QSocketNg::MaxStreamsSocketOption:
        Q_UNREACHABLE();

    case QSocketNg::ReceiveBufferSizeSocketOption:
        n = SO_RCVBUF;
        break;
    case QSocketNg::SendBufferSizeSocketOption:
        n = SO_SNDBUF;
        break;
    case QSocketNg::BroadcastSocketOption:
        n = SO_BROADCAST;
        break;
    case QSocketNg::AddressReusable:
        n = SO_REUSEADDR;
        break;
    case QSocketNg::BindExclusively:
        n = SO_EXCLUSIVEADDRUSE;
        break;
    case QSocketNg::ReceiveOutOfBandData:
        n = SO_OOBINLINE;
        break;
    case QSocketNg::LowDelayOption:
        level = IPPROTO_TCP;
        n = TCP_NODELAY;
        break;
    case QSocketNg::KeepAliveOption:
        n = SO_KEEPALIVE;
        break;
    case QSocketNg::MulticastTtlOption:
        if (socketProtocol == QSocketNg::IPv6Protocol || socketProtocol == QSocketNg::AnyIPProtocol) {
            level = IPPROTO_IPV6;
            n = IPV6_MULTICAST_HOPS;
        } else
        {
            level = IPPROTO_IP;
            n = IP_MULTICAST_TTL;
        }
        break;
    case QSocketNg::MulticastLoopbackOption:
        if (socketProtocol == QSocketNg::IPv6Protocol || socketProtocol == QSocketNg::AnyIPProtocol) {
            level = IPPROTO_IPV6;
            n = IPV6_MULTICAST_LOOP;
        } else
        {
            level = IPPROTO_IP;
            n = IP_MULTICAST_LOOP;
        }
        break;
    case QSocketNg::ReceivePacketInformation:
        if (socketProtocol == QSocketNg::IPv6Protocol || socketProtocol == QSocketNg::AnyIPProtocol) {
            level = IPPROTO_IPV6;
            n = IPV6_PKTINFO;
        } else if (socketProtocol == QSocketNg::IPv4Protocol) {
            level = IPPROTO_IP;
            n = IP_PKTINFO;
        }
        break;
    case QSocketNg::ReceiveHopLimit:
        if (socketProtocol == QSocketNg::IPv6Protocol || socketProtocol == QSocketNg::AnyIPProtocol) {
            level = IPPROTO_IPV6;
            n = IPV6_HOPLIMIT;
        } else if (socketProtocol == QSocketNg::IPv4Protocol) {
            level = IPPROTO_IP;
            n = IP_HOPLIMIT;
        }
        break;
    }
}

static inline QSocketNg::SocketType qt_socket_getType(qintptr socketDescriptor)
{
    int value = 0;
    QT_SOCKLEN_T valueSize = sizeof(value);
    if (::getsockopt(socketDescriptor, SOL_SOCKET, SO_TYPE, (char *) &value, &valueSize) != 0) {
        WS_ERROR_DEBUG(WSAGetLastError());
    } else {
        if (value == SOCK_STREAM)
            return QSocketNg::TcpSocket;
        else if (value == SOCK_DGRAM)
            return QSocketNg::UdpSocket;
    }
    return QSocketNg::UnknownSocketType;
}


inline uint scopeIdFromString(const QString &scopeid)
{
    return QNetworkInterface::interfaceIndexFromName(scopeid);
}


namespace {
namespace SetSALen {
    template <typename T> void set(T *sa, typename QtPrivate::QEnableIf<(&T::sa_len, true), QT_SOCKLEN_T>::Type len)
    { sa->sa_len = len; }
    template <typename T> void set(T *sin6, typename QtPrivate::QEnableIf<(&T::sin6_len, true), QT_SOCKLEN_T>::Type len)
    { sin6->sin6_len = len; }
    template <typename T> void set(T *, ...) {}
}
}

void QSocketNgPrivate::setPortAndAddress(quint16 port, const QHostAddress &address, qt_sockaddr *aa, QT_SOCKLEN_T *sockAddrSize)
{
    if (address.protocol() == QAbstractSocket::IPv6Protocol
        || address.protocol() == QAbstractSocket::AnyIPProtocol
        || protocol == QSocketNg::IPv6Protocol
        || protocol == QSocketNg::AnyIPProtocol) {
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

bool QSocketNgPrivate::createSocket()
{
    //Windows XP and 2003 support IPv6 but not dual stack sockets
    int protocol = (this->protocol == QSocketNg::IPv6Protocol
        || (this->protocol == QSocketNg::AnyIPProtocol)) ? AF_INET6 : AF_INET;
    int type = (this->type == QSocketNg::UdpSocket) ? SOCK_DGRAM : SOCK_STREAM;

    // MSDN KB179942 states that on winnt 4 WSA_FLAG_OVERLAPPED is needed if socket is to be non blocking
    // and recomends alwasy doing it for cross windows version comapablity.

    // WSA_FLAG_NO_HANDLE_INHERIT is atomic (like linux O_CLOEXEC), but requires windows 7 SP 1 or later
    // SetHandleInformation is supported since W2K but isn't atomic
#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

    SOCKET socket = ::WSASocket(protocol, type, 0, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT | WSA_FLAG_OVERLAPPED);
    // previous call fails if the windows 7 service pack 1 or hot fix isn't installed.

    // Try the old API if the new one failed on Windows 7
    if (socket == INVALID_SOCKET && QSysInfo::windowsVersion() < QSysInfo::WV_WINDOWS8) {
        socket = ::WSASocket(protocol, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
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
            setError(QSocketNg::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
            break;
        case WSAEMFILE:
        case WSAENOBUFS:
            setError(QSocketNg::SocketResourceError, ResourceErrorString);
            break;
        default:
            break;
        }
        return false;
    }

    if (this->type == QSocketNg::UdpSocket) {
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

    fd = socket;
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


bool QSocketNgPrivate::bind(const QHostAddress &a, quint16 port, QSocketNg::BindMode mode)
{
    Q_UNUSED(mode);
    QHostAddress address = a;
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        if ((address.toIPv4Address() & 0xffff0000) == 0xefff0000) {
            // binding to a multicast address
            address = QHostAddress(QHostAddress::AnyIPv4);
        }
    }

    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize = 0;
    setPortAndAddress(port, address, &aa, &sockAddrSize);

    if (aa.a.sa_family == AF_INET6) {
        // The default may change in future, so set it explicitly
        int ipv6only = 0;
        if (address.protocol() == QAbstractSocket::IPv6Protocol)
            ipv6only = 1;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );
    }


    int bindResult = ::bind(fd, &aa.a, sockAddrSize);
    if (bindResult == SOCKET_ERROR && WSAGetLastError() == WSAEAFNOSUPPORT
            && address.protocol() == QAbstractSocket::AnyIPProtocol) {
        // retry with v4
        aa.a4.sin_family = AF_INET;
        aa.a4.sin_port = htons(port);
        aa.a4.sin_addr.s_addr = htonl(address.toIPv4Address());
        sockAddrSize = sizeof(aa.a4);
        bindResult = ::bind(fd, &aa.a, sockAddrSize);
    }
    if (bindResult == SOCKET_ERROR) {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        switch (err) {
        case WSANOTINITIALISED:
            setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
            break;
        case WSAEADDRINUSE:
        case WSAEINVAL:
            setError(QSocketNg::AddressInUseError, AddressInuseErrorString);
            break;
        case WSAEACCES:
            setError(QSocketNg::SocketAccessError, AddressProtectedErrorString);
            break;
        case WSAEADDRNOTAVAIL:
            setError(QSocketNg::SocketAddressNotAvailableError, AddressNotAvailableErrorString);
            break;
        default:
            setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
            break;
        }

#if defined (QSOCKETNG_DEBUG)
        qDebug("QSocketNgPrivate::bind(%s, %i) == false (%s)",
               address.toString().toLatin1().constData(), port, errorString.toLatin1().constData());
#endif
        return false;
    }

#if defined (QSOCKETNG_DEBUG)
    qDebug("QSocketNgPrivate::bind(%s, %i) == true",
           address.toString().toLatin1().constData(), port);
#endif
    state = QSocketNg::BoundState;
    return true;
}


bool QSocketNgPrivate::connect(const QHostAddress &address, quint16 port)
{
    if(!isValid())
        return false;
    if(state != QSocketNg::UnconnectedState && state != QSocketNg::BoundState && state != QSocketNg::ConnectingState)
        return false;

    qt_sockaddr aa;
    QT_SOCKLEN_T sockAddrSize = 0;
    setPortAndAddress(port, address, &aa, &sockAddrSize);

    if ((protocol == QSocketNg::IPv6Protocol || protocol == QSocketNg::AnyIPProtocol) && address.toIPv4Address()) {
        //IPV6_V6ONLY option must be cleared to connect to a V4 mapped address
        if (QSysInfo::windowsVersion() >= QSysInfo::WV_6_0) {
            DWORD ipv6only = 0;
            ipv6only = ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, sizeof(ipv6only) );
        }
    }

    state = QSocketNg::ConnectingState;
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    while(true) {
        if(!isValid())
            return false;
        if(state != QSocketNg::ConnectingState)
            return false;

        int connectResult = ::WSAConnect(fd, &aa.a, sockAddrSize, 0,0,0,0);
        if (connectResult == SOCKET_ERROR) {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);

            switch (err) {
            case WSANOTINITIALISED:
                setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                return false;
            case WSAEISCONN:
                state = QSocketNg::ConnectedState;
                fetchConnectionParameters();
                return true;
            case WSAEWOULDBLOCK: {
                // If WSAConnect returns WSAEWOULDBLOCK on the second
                // connection attempt, we have to check SO_ERROR's
                // value to detect ECONNREFUSED. If we don't get
                // ECONNREFUSED, we'll have to treat it as an
                // unfinished operation.
                int value = 0;
                QT_SOCKLEN_T valueSize = sizeof(value);
                bool tryAgain = false;
                int tries = 0;
                do {
                    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &value, &valueSize) == 0) {
                        if (value != NOERROR) {
                            // MSDN says getsockopt with SO_ERROR clears the error, but it's not actually cleared
                            // and this can affect all subsequent WSAConnect attempts, so clear it now.
                            const int val = NO_ERROR;
                            ::setsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<const char*>(&val), sizeof val);
                        }

                        if (value == WSAECONNREFUSED) {
                            setError(QSocketNg::ConnectionRefusedError, ConnectionRefusedErrorString);
                            state = QSocketNg::UnconnectedState;
                            return false;
                        }
                        if (value == WSAETIMEDOUT) {
                            setError(QSocketNg::NetworkError, ConnectionTimeOutErrorString);
                            state = QSocketNg::UnconnectedState;
                            return false;
                        }
                        if (value == WSAEHOSTUNREACH) {
                            setError(QSocketNg::NetworkError, HostUnreachableErrorString);
                            state = QSocketNg::UnconnectedState;
                            return false;
                        }
                        if (value == WSAEADDRNOTAVAIL) {
                            setError(QSocketNg::NetworkError, AddressNotAvailableErrorString);
                            state = QSocketNg::UnconnectedState;
                            return false;
                        }
                        if (value == NOERROR) {
                            // When we get WSAEWOULDBLOCK the outcome was not known, so a
                            // NOERROR might indicate that the result of the operation
                            // is still unknown. We try again to increase the chance that we did
                            // get the correct result.
                            tryAgain = !tryAgain;
                        }
                    }
                    tries++;
                } while (tryAgain && (tries < 2));
                    Q_FALLTHROUGH();
                }
            case WSAEINPROGRESS:
                break;
            case WSAEADDRINUSE:
                setError(QSocketNg::NetworkError, AddressInuseErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAECONNREFUSED:
                setError(QSocketNg::ConnectionRefusedError, ConnectionRefusedErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAETIMEDOUT:
                setError(QSocketNg::NetworkError, ConnectionTimeOutErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAEACCES:
                setError(QSocketNg::SocketAccessError, AccessErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAEHOSTUNREACH:
                setError(QSocketNg::NetworkError, HostUnreachableErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAENETUNREACH:
                setError(QSocketNg::NetworkError, NetworkUnreachableErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            case WSAEINVAL:
            case WSAEALREADY:
                setError(QSocketNg::UnfinishedSocketOperationError, InvalidSocketErrorString);
                state = QSocketNg::UnconnectedState;
                return false;
            default:
                setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                return false;
            }
            watcher.start();
        }
    }
}


bool QSocketNgPrivate::close()
{
    if(fd > 0)
    {
        ::closesocket(fd);
        EventLoopCoroutine::get()->triggerIoWatchers(fd);
        fd = -1;
    }
    state = QSocketNg::UnconnectedState;
    localAddress.clear();
    localPort = 0;
    peerAddress.clear();
    peerPort = 0;
    return true;
}

bool QSocketNgPrivate::listen(int backlog)
{
    if(!isValid()) {
        return false;
    }
    if(state != QSocketNg::BoundState) {
        return false;
    }
    if (::listen(fd, backlog) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        switch (err) {
        case WSANOTINITIALISED:
            setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
            break;
        case WSAEADDRINUSE:
            setError(QSocketNg::AddressInUseError,
                     PortInuseErrorString);
            break;
        default:
            break;
        }

    #if defined (QSOCKETNG_DEBUG)
            qDebug("QSocketNgPrivate::listen(%i) == false (%s)",
                   backlog, errorString.toLatin1().constData());
    #endif
        return false;
    }

    #if defined (QNATIVESOCKETENGINE_DEBUG)
        qDebug("QSocketNgPrivate::listen(%i) == true", backlog);
    #endif

    state = QSocketNg::ListeningState;
    return true;
}


bool QSocketNgPrivate::fetchConnectionParameters()
{
    localPort = 0;
    localAddress.clear();
    peerPort = 0;
    peerAddress.clear();

    if(!isValid()) {
        return false;
    }

    qt_sockaddr sa;
    QT_SOCKLEN_T sockAddrSize = sizeof(sa);

    // Determine local address
    memset(&sa, 0, sizeof(sa));
    if (::getsockname(fd, &sa.a, &sockAddrSize) == 0) {
        qt_socket_getPortAndAddress(fd, &sa, &localPort, &localAddress);
        // Determine protocol family
        switch (sa.a.sa_family) {
        case AF_INET:
            this->protocol = QSocketNg::IPv4Protocol;
            break;
        case AF_INET6:
            this->protocol = QSocketNg::IPv6Protocol;
            break;
        default:
            this->protocol = QSocketNg::UnknownNetworkLayerProtocol;
            break;
        }
    } else {
        int err = WSAGetLastError();
        WS_ERROR_DEBUG(err);
        if (err == WSAENOTSOCK) {
            setError(QSocketNg::UnsupportedSocketOperationError,
                InvalidSocketErrorString);
            return false;
        }
    }

    // determine if local address is dual mode
    DWORD ipv6only = 0;
    QT_SOCKOPTLEN_T optlen = sizeof(ipv6only);
    if (localAddress == QHostAddress::AnyIPv6
        && QSysInfo::windowsVersion() >= QSysInfo::WV_6_0
        && !getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&ipv6only, &optlen )) {
            if (!ipv6only) {
                protocol = QSocketNg::AnyIPProtocol;
                localAddress = QHostAddress::Any;
            }
    }

    // Some Windows kernels return a v4-mapped QHostAddress::AnyIPv4 as a
    // local address of the socket which bound on both IPv4 and IPv6 interfaces.
    // This address does not match to any special address and should not be used
    // to send the data. So, replace it with QHostAddress::Any.
    if (this->protocol == QSocketNg::IPv6Protocol) {
        bool ok = false;
        const quint32 localIPv4 = localAddress.toIPv4Address(&ok);
        if (ok && localIPv4 == INADDR_ANY) {
            protocol = QSocketNg::AnyIPProtocol;
            localAddress = QHostAddress::Any;
        }
    }

    memset(&sa, 0, sizeof(sa));
    if (::getpeername(fd, &sa.a, &sockAddrSize) == 0) {
        qt_socket_getPortAndAddress(fd, &sa, &peerPort, &peerAddress);
    } else {
        WS_ERROR_DEBUG(WSAGetLastError());
    }

    this->type = qt_socket_getType(fd);

#if defined (QSOCKETNG_DEBUG)
    QString socketProtocolStr = "UnknownProtocol";
    if (protocol == QSocketNg::IPv4Protocol) socketProtocolStr = "IPv4Protocol";
    else if (protocol == QSocketNg::IPv6Protocol) socketProtocolStr = "IPv6Protocol";

    QString socketTypeStr = "UnknownSocketType";
    if (type == QSocketNg::TcpSocket) socketTypeStr = "TcpSocket";
    else if (type == QSocketNg::UdpSocket) socketTypeStr = "UdpSocket";

    qDebug("QSocketNgPrivate::fetchConnectionParameters() localAddress == %s, localPort = %i, peerAddress == %s, peerPort = %i, socketProtocol == %s, socketType == %s", localAddress.toString().toLatin1().constData(), localPort, peerAddress.toString().toLatin1().constData(), peerPort, socketProtocolStr.toLatin1().constData(), socketTypeStr.toLatin1().constData());
#endif

    return true;
}


qint64 QSocketNgPrivate::recv(char *data, qint64 size)
{
    if(!isValid()) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    qint64 total = 0;
    while(total < size)
    {
        if(!isValid()) {
            setError(QSocketNg::SocketAccessError, AccessErrorString);
            return total == 0 ? -1: total;
        }
        if(type == QSocketNg::TcpSocket) {
            if(state != QSocketNg::ConnectedState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return total == 0 ? -1 : total;
            }
        } else if(type == QSocketNg::UdpSocket) {
            if(state != QSocketNg::UnconnectedState || state != QSocketNg::BoundState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return total == 0 ? -1 : total;
            }
        } else {
            setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
            return total == 0 ? -1 : total;
        }
        WSABUF buf;
        buf.buf = data + total;
        buf.len = size - total;
        DWORD flags = 0;
        DWORD bytesRead = 0;
        if (::WSARecv(fd, &buf, 1, &bytesRead, &flags, 0,0) ==  SOCKET_ERROR) {
            int err = WSAGetLastError();
            WS_ERROR_DEBUG(err);
            switch (err) {
            case WSAEWOULDBLOCK:
                break;
            case WSAECONNRESET:
            case WSAECONNABORTED:
                if(type == QSocketNg::TcpSocket) {
                    setError(QSocketNg::RemoteHostClosedError, RemoteHostClosedErrorString);
                    close();
                }
                return total;
            case WSAEBADF:
            case WSAEINVAL:
            default:
                setError(QSocketNg::NetworkError, ConnectionResetErrorString);
                close();
                return total == 0 ? -1 : total;
            }
        } else if(bytesRead == 0 && type == QSocketNg::TcpSocket) {
            setError(QSocketNg::RemoteHostClosedError, RemoteHostClosedErrorString);
            close();
            return total;
        } else {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                total += qint64(bytesRead);
            }
        }
        watcher.start();
    }
    return total;
}

qint64 QSocketNgPrivate::send(const char *data, qint64 size, bool all)
{
    if(!isValid()) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    qint64 ret = 0;
    qint64 bytesToSend = size;
    while(bytesToSend > 0)
    {
        if(!isValid()) {
            setError(QSocketNg::SocketAccessError, AccessErrorString);
            return ret == 0 ? -1: ret;
        }
        if(type == QSocketNg::TcpSocket) {
            if(state != QSocketNg::ConnectedState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return ret == 0 ? -1 : ret;
            }
        } else if(type == QSocketNg::UdpSocket) {
            if(state != QSocketNg::ConnectedState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return ret == 0 ? -1 : ret;
            }
        } else {
            setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
            return -1;
        }

        WSABUF buf;
        buf.buf = (char*)data + ret;
        buf.len = bytesToSend;
        DWORD flags = 0;
        DWORD bytesWritten = 0;

        int socketRet = ::WSASend(fd, &buf, 1, &bytesWritten, flags, 0,0);
        ret += qint64(bytesWritten);

        if (socketRet != SOCKET_ERROR) {
            if (ret == size) {
                return ret;
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
                setError(QSocketNg::SocketAccessError, AccessErrorString);
                return -1;
            case WSAEDESTADDRREQ: // only happen in sendto()
            case WSAESHUTDOWN:
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                close();
                return -1;
            case WSAEMSGSIZE: // must be udp socket, need not close()
                setError(QSocketNg::DatagramTooLargeError, DatagramTooLargeErrorString);
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
                setError(QSocketNg::NetworkError, WriteErrorString);
                close();
                return ret == 0 ? -1 : ret;
            case WSAEHOSTUNREACH:
                setError(QSocketNg::NetworkError, HostUnreachableErrorString);
                close();
                return -1;
            case WSAENETDOWN:
                setError(QSocketNg::NetworkError, NetworkDroppedConnectionErrorString);
                close();
                return -1;
            case WSAENETRESET:
                setError(QSocketNg::NetworkError, ConnectionResetErrorString);
                close();
                return -1;
            case WSAENETUNREACH:
                setError(QSocketNg::NetworkError, NetworkUnreachableErrorString);
                close();
                return -1;
            case WSAEFAULT:
            case WSAEINTR:
            case WSAEINVAL:
            default:
                setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                close();
                return -1;
            }
        }
        bytesToSend = qMin<qint64>(49152, size - ret);
        watcher.start();
    }
    return ret;
}


qint64 QSocketNgPrivate::recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)
{
    if(!isValid()) {
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
    buf.len = size ? size : 1;
    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.name = reinterpret_cast<LPSOCKADDR>(&aa);
    msg.namelen = sizeof(aa);

    DWORD flags = 0;
    DWORD bytesRead = 0;
    qint64 ret;

    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);

    while(true) {
        if(!isValid()){
            setError(QSocketNg::SocketAccessError, AccessErrorString);
            return -1;
        }
        if(type == QSocketNg::TcpSocket) {
            if(state != QSocketNg::ConnectedState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return -1;
            }
        } else if(type == QSocketNg::UdpSocket) {
            if(state != QSocketNg::ConnectedState || state != QSocketNg::BoundState) {
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return -1;
            }
        } else {
            // do it.
        }

        //        if (recvmsg)
        //            ret = recvmsg(socketDescriptor, &msg, &bytesRead, 0,0);
        //        else
        //            ret = ::WSARecvFrom(socketDescriptor, &buf, 1, &bytesRead, &flags, msg.name, &msg.namelen,0,0);

        ret = ::WSARecvFrom(fd, &buf, 1, &bytesRead, &flags, msg.name, &msg.namelen,0,0);
        if (ret == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEMSGSIZE) {
                // it is ok the buffer was to small if bytesRead is larger than
                // maxLength then assume bytes read is really maxLenth
                ret = qMin(size, qint64(bytesRead));
            } else {
                WS_ERROR_DEBUG(err);
                switch (err) {
                case WSAEINPROGRESS:
                case WSAEINTR:
                    break;
                case WSAECONNRESET:
                    setError(QSocketNg::ConnectionRefusedError, ConnectionResetErrorString);
                    close();
                    return -1;
                case WSAENOTCONN: // not connected for tcp
                case WSAEINVAL: // not bound for udp
                    setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                    // need not close()
                    return -1;
                case WSAENETRESET:
                    if(type == QSocketNg::TcpSocket) {
                        setError(QSocketNg::NetworkError, NetworkDroppedConnectionErrorString);
                        close();
                    } else {
                        setError(QSocketNg::NetworkError, QString::fromLatin1("the time to live has expired."));
                        // need not close()
                    }
                    return -1;
                case WSANOTINITIALISED:
                case WSAENETDOWN:
                case WSAEFAULT:
                    setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                    close();
                    return -1;
                default:
                    setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                    return -1;
                }
            }
        } else {
            ret = qint64(bytesRead);

        }
        if(ret > 0) {
            qt_socket_getPortAndAddress(fd, &aa, port, addr);
#if defined (QSOCKETNG_DEBUG)
            bool printSender = (ret != -1);
            qDebug("QSocketNgPrivate::recvfrom(%p \"%s\", %lli, %s, %i) == %lli",
                   data, qt_prettyDebug(data, qMin<qint64>(ret, 16), ret).data(), size,
                   printSender ? addr->toString().toLatin1().constData() : "(unknown)",
                   printSender ? port : 0, ret);
#endif
            return ret;
        }
        watcher.start();
    }
}

qint64 QSocketNgPrivate::sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)
{
    if(!isValid()) {
        return -1;
    }
    if(type == QSocketNg::TcpSocket) {
        setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
        return -1;
    } else if(type == QSocketNg::UdpSocket) {
        if(state == QSocketNg::ConnectedState) {
            setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
            return -1;
        }
    } else {
        // do it!
    }

    ScopedIoWatcher watcher(EventLoopCoroutine::Write, fd);
    qint64 ret = 0;
    qint64 bytesToSend = size;

    WSAMSG msg;
    WSABUF buf;
    qt_sockaddr aa;
    setPortAndAddress(port, addr, &aa, &msg.namelen);
    memset(&msg, 0, sizeof(msg));
    memset(&aa, 0, sizeof(aa));

    msg.lpBuffers = &buf;
    msg.dwBufferCount = 1;
    msg.name = &aa.a;


    do {
        if(!isValid()) {
            return ret == 0 ? -1 : ret;
        }
        if(state == QSocketNg::ConnectedState) {
            setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
            return ret == 0 ? -1 : ret;
        }

        buf.buf = bytesToSend ? (char*)data : 0;
        buf.len = bytesToSend; // TODO datagram max size!

        DWORD flags = 0;
        DWORD bytesSent = 0;
        int socketRet;

//        if (sendmsg) {
//            socketRet = sendmsg(fd, &msg, flags, &bytesSent, 0,0);
//        } else {
//            socketRet = ::WSASendTo(fd, &buf, 1, &bytesSent, flags, msg.name, msg.namelen, 0,0);
//        }
        socketRet = ::WSASendTo(fd, &buf, 1, &bytesSent, flags, msg.name, msg.namelen, 0,0);
        ret += qint64(bytesSent);

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
                setError(QSocketNg::SocketAccessError, AccessErrorString);
                return -1;
            case WSAECONNRESET:
            case WSAENOTCONN:
            case WSAEDESTADDRREQ:
            case WSAESHUTDOWN:
                setError(QSocketNg::UnsupportedSocketOperationError, OperationUnsupportedErrorString);
                return -1;
            case WSAEMSGSIZE:
                setError(QSocketNg::DatagramTooLargeError, DatagramTooLargeErrorString);
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
                setError(QSocketNg::NetworkError, SendDatagramErrorString);
                return -1;
            }
        } else {
            if(ret >= size) {
                return ret;
            }
        }
        watcher.start();
    } while(bytesToSend > 0);


#if defined (QSOCKETNG_DEBUG)
    qDebug("QSocketNgPrivate::sendto(%p \"%s\", %lli, \"%s\", %i) == %lli", data,
           qt_prettyDebug(data, qMin<qint64>(size, 16), size).data(), size,
           addr.toString().toLatin1().constData(),
           port, ret);
#endif

    return ret;
}

QVariant QSocketNgPrivate::option(QSocketNg::SocketOption option) const
{
    if (!isValid())
        return -1;

    // handle non-getsockopt
    switch (option) {
    case QSocketNg::NonBlockingSocketOption:
        return QVariant(-1); // TODO return true if nonblocking is implemented.
    case QSocketNg::TypeOfServiceOption:
    case QSocketNg::MaxStreamsSocketOption:
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
    if (getsockopt(fd, level, n, (char *) &v, &len) == 0)
        return v;
    WS_ERROR_DEBUG(WSAGetLastError());
    return -1;
}


bool QSocketNgPrivate::setOption(QSocketNg::SocketOption option, const QVariant &value)
{
    if(!isValid())
        return false;

    // handle non-setsockopt options
    switch (option) {
    case QSocketNg::SendBufferSizeSocketOption:
        // see QTBUG-30478 SO_SNDBUF should not be used on Vista or later
        if (QSysInfo::windowsVersion() >= QSysInfo::WV_VISTA)
            return false;
        break;
    case QSocketNg::NonBlockingSocketOption:
        return false;
    case QSocketNg::TypeOfServiceOption:
    case QSocketNg::MaxStreamsSocketOption:
        return false;

    default:
        break;
    }

    int n, level;
    convertToLevelAndOption(option, protocol, level, n);
    if (::setsockopt(fd, level, n, (char*)&value, sizeof(value)) != 0) {
        WS_ERROR_DEBUG(WSAGetLastError());
        return false;
    }
    return true;
}

bool QSocketNgPrivate::setNonblocking()
{
    unsigned long buf = 1;
    unsigned long outBuf;
    DWORD sizeWritten = 0;
    if (::WSAIoctl(fd, FIONBIO, &buf, sizeof(unsigned long), &outBuf, sizeof(unsigned long), &sizeWritten, 0,0) == SOCKET_ERROR) {
        WS_ERROR_DEBUG(WSAGetLastError());
        return false;
    }
    return true;
}


QSocketNg *QSocketNgPrivate::accept()
{
    if(!isValid()) {
        return 0;
    }
    if(state != QSocketNg::ListeningState || type != QSocketNg::TcpSocket)
        return 0;

    ScopedIoWatcher watcher(EventLoopCoroutine::Read, fd);
    while(true) {
        int acceptedDescriptor = WSAAccept(fd, 0,0,0,0);
        if (acceptedDescriptor == -1) {
            int err = WSAGetLastError();
            switch (err) {
            case WSAEACCES:
                setError(QSocketNg::SocketAccessError, AccessErrorString);
                return 0;
            case WSAECONNREFUSED:
                setError(QSocketNg::ConnectionRefusedError, ConnectionRefusedErrorString);
                return 0;
            case WSAECONNRESET:
                setError(QSocketNg::NetworkError, RemoteHostClosedErrorString);
                return 0;
            case WSAENETDOWN:
                setError(QSocketNg::NetworkError, NetworkUnreachableErrorString);
                return 0;
            case WSAENOTSOCK:
                setError(QSocketNg::SocketResourceError, NotSocketErrorString);
                return 0;
            case WSAEINVAL:
            case WSAEOPNOTSUPP:
                setError(QSocketNg::UnsupportedSocketOperationError, ProtocolUnsupportedErrorString);
                return 0;
            case WSAEFAULT:
            case WSAEMFILE:
            case WSAENOBUFS:
                setError(QSocketNg::SocketResourceError, ResourceErrorString);
                return 0;
            case WSAEINPROGRESS:
            case WSAEWOULDBLOCK:
                break;
            default:
                setError(QSocketNg::UnknownSocketError, UnknownSocketErrorString);
                return 0;
            }
        } else {
            QSocketNg *conn = new QSocketNg(acceptedDescriptor);
            return conn;
        }
        watcher.start();
    }
}


QTNETWORKNG_NAMESPACE_END
