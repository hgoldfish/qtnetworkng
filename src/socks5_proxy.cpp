#include <QtCore/qurl.h>
#include <QtCore/qendian.h>
#include "../include/socks5_proxy.h"

QTNETWORKNG_NAMESPACE_BEGIN

#define S5_VERSION_5 0x05
#define S5_CONNECT 0x01
#define S5_BIND 0x02
#define S5_UDP_ASSOCIATE 0x03
#define S5_IP_V4 0x01
#define S5_DOMAINNAME 0x03
#define S5_IP_V6 0x04
#define S5_SUCCESS 0x00
#define S5_R_ERROR_SOCKS_FAILURE 0x01
#define S5_R_ERROR_CON_NOT_ALLOWED 0x02
#define S5_R_ERROR_NET_UNREACH 0x03
#define S5_R_ERROR_HOST_UNREACH 0x04
#define S5_R_ERROR_CONN_REFUSED 0x05
#define S5_R_ERROR_TTL 0x06
#define S5_R_ERROR_CMD_NOT_SUPPORTED 0x07
#define S5_R_ERROR_ADD_TYPE_NOT_SUPORTED 0x08

#define S5_AUTHMETHOD_NONE 0x00
#define S5_AUTHMETHOD_PASSWORD 0x02
#define S5_AUTHMETHOD_NOTACCEPTABLE 0xFF

#define S5_PASSWORDAUTH_VERSION 0x01

QString Socks5Exception::errorString() const
{
    switch (err) {
    case ProxyConnectionRefusedError:
        return QString::fromLatin1("Connection to proxy refused");
    case ProxyConnectionClosedError:
        return QString::fromLatin1("Connection to proxy closed prematurely");
    case ProxyNotFoundError:
        return QString::fromLatin1("Proxy host not found");
    case ProxyProtocolError:
        return QString::fromLatin1("SOCKS version 5 protocol error");
    case ProxyAuthenticationRequiredError:
        return QString::fromLatin1("Proxy authentication failed");
    case SocksFailure:
        return QString::fromLatin1("General SOCKSv5 server failure");
    case ConnectionNotAllowed:
        return QString::fromLatin1("Connection not allowed by SOCKSv5 server");
    case NetworkUnreachable:
        return QString::fromLatin1("Network unreachable");
    case HostUnreachable:
        return QString::fromLatin1("Host not found");
    case ConnectionRefused:
        return QString::fromLatin1("Connection refused");
    case TTLExpired:
        return QString::fromLatin1("TTL expired");
    case CommandNotSupported:
        return QString::fromLatin1("SOCKSv5 command not supported");
    case AddressTypeNotSupported:
        return QString::fromLatin1("Address type not supported");
    default:
        return QString::fromLatin1("some error occured in socks5.");
    }
}

class Socks5ProxyPrivate
{
public:
    Socks5ProxyPrivate() { }
    Socks5ProxyPrivate(const QString &hostName, quint16 port, const QString &user, const QString &password)
        : hostName(hostName)
        , user(user)
        , password(password)
        , port(port)
    {
        capabilities |= Socks5Proxy::TunnelingCapability;
        capabilities |= Socks5Proxy::HostNameLookupCapability;
    }
public:
    QSharedPointer<Socket> getControlSocket() const;
    QSharedPointer<SocketLike> connect(const QString &hostName, quint16 port) const;
    QSharedPointer<SocketLike> connect(const HostAddress &host, quint16 port) const;
    QSharedPointer<SocketLike> listen(quint16 port) const;
public:
    QString hostName;
    QString user;
    QString password;
    QFlags<Socks5Proxy::Capability> capabilities;
    quint16 port;
};

QSharedPointer<Socket> Socks5ProxyPrivate::getControlSocket() const
{
    Socket::SocketError error;
    QSharedPointer<Socket> s(Socket::createConnection(hostName, port, &error));
    if (s.isNull()) {
        if (error == Socket::HostNotFoundError) {
            throw Socks5Exception(Socks5Exception::ProxyNotFoundError);
        } else if (error == Socket::RemoteHostClosedError) {
            throw Socks5Exception(Socks5Exception::ProxyConnectionClosedError);
        } else if (error == Socket::ConnectionRefusedError) {
            throw Socks5Exception(Socks5Exception::ProxyConnectionRefusedError);
        } else if (error == Socket::SocketTimeoutError) {
            throw Socks5Exception(Socks5Exception::ProxyConnectionTimeoutError);
        } else {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
    }

    QByteArray helloRequest;
    helloRequest.reserve(3);
    helloRequest.append(static_cast<char>(S5_VERSION_5));
    helloRequest.append(static_cast<char>(1));
    if (!user.isEmpty() && !password.isEmpty()) {
        helloRequest.append(static_cast<char>(S5_AUTHMETHOD_PASSWORD));
    } else {
        helloRequest.append(static_cast<char>(S5_AUTHMETHOD_NONE));
    }

    qint64 sentBytes = s->sendall(helloRequest);
    if (sentBytes < helloRequest.size()) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    const QByteArray &helloResponse = s->recvall(2);
    if (helloResponse.size() != 2) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    if (helloResponse.at(0) != S5_VERSION_5) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    Q_CONSTEXPR char negOne = std::numeric_limits<char>::is_signed ? -1 : S5_AUTHMETHOD_NOTACCEPTABLE;
    if (helloResponse.at(1) == S5_AUTHMETHOD_PASSWORD) {
        if (user.isEmpty() || password.isEmpty()) {
            throw Socks5Exception(Socks5Exception::ProxyAuthenticationRequiredError);
        }
        QByteArray authRequest;
        authRequest.reserve(3 + user.size() + password.size());
        authRequest.append(static_cast<char>(S5_PASSWORDAUTH_VERSION));
        authRequest.append(static_cast<char>(user.size()));
        authRequest.append(user.toUtf8());
        authRequest.append(static_cast<char>(password.size()));
        authRequest.append(password.toUtf8());
        sentBytes = s->sendall(authRequest);
        if (sentBytes < authRequest.size()) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        const QByteArray authResponse = s->recvall(2);
        if (authResponse.size() != 2) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        if (authResponse.at(0) != S5_PASSWORDAUTH_VERSION) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        if (authResponse.at(1) != 0x0) {
            throw Socks5Exception(Socks5Exception::ProxyAuthenticationRequiredError);
        }
    } else if (helloResponse.at(1) == negOne) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    return s;
}

static QByteArray makeConnectRequest()
{
    QByteArray connectRequest;
    connectRequest.reserve(270);  // big enough for domain name;
    connectRequest.append(static_cast<char>(S5_VERSION_5));
    connectRequest.append(static_cast<char>(S5_CONNECT));
    connectRequest.append(static_cast<char>(0x00));
    return connectRequest;
}

/*
   inserts the host address in buf at pos and updates pos.
   if the func fails the data in buf and the vallue of pos is undefined
*/
static bool qt_socks5_set_host_address_and_port(const HostAddress &address, quint16 port, QByteArray *pBuf)
{
    union {
        quint16 port;
        quint32 ipv4;
        IPv6Address ipv6;
        char ptr;
    } data;

    if (address.protocol() == HostAddress::IPv4Protocol) {
        data.ipv4 = qToBigEndian<quint32>(address.toIPv4Address(nullptr));
        pBuf->append(S5_IP_V4);
        pBuf->append(QByteArray::fromRawData(&data.ptr, sizeof(data.ipv4)));
    } else if (address.protocol() == HostAddress::IPv6Protocol) {
        data.ipv6 = address.toIPv6Address();
        pBuf->append(S5_IP_V6);
        pBuf->append(QByteArray::fromRawData(&data.ptr, sizeof data.ipv6));
    } else {
        return false;
    }

    data.port = qToBigEndian<quint16>(port);
    pBuf->append(QByteArray::fromRawData(&data.ptr, sizeof(data.port)));
    return true;
}

/*
   like above, but for a hostname
*/
static bool qt_socks5_set_host_name_and_port(const QString &hostname, quint16 port, QByteArray *pBuf)
{
    QByteArray encodedHostName = QUrl::toAce(hostname);
    QByteArray &buf = *pBuf;

    if (encodedHostName.length() > 255)
        return false;

    buf.append(S5_DOMAINNAME);
    buf.append(static_cast<char>(encodedHostName.length()));
    buf.append(encodedHostName);

    // add port
    union {
        quint16 port;
        char ptr;
    } data;
    data.port = qToBigEndian<quint16>(port);
    buf.append(QByteArray::fromRawData(&data.ptr, sizeof data.port));

    return true;
}

static QSharedPointer<Socket> sendConnectRequest(QSharedPointer<Socket> s, const QByteArray &connectRequest)
{
    qint64 sentBytes = s->sendall(connectRequest);
    if (sentBytes < connectRequest.size()) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    const QByteArray &connectResponse = s->recvall(2);
    if (connectResponse.size() < 2) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    if (connectResponse.at(0) != S5_VERSION_5) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    int code = connectResponse.at(1);
    switch (code) {
    case S5_SUCCESS:
        break;
    case S5_R_ERROR_SOCKS_FAILURE:
        throw Socks5Exception(Socks5Exception::SocksFailure);
    case S5_R_ERROR_CON_NOT_ALLOWED:
        throw Socks5Exception(Socks5Exception::ConnectionNotAllowed);
    case S5_R_ERROR_NET_UNREACH:
        throw Socks5Exception(Socks5Exception::NetworkUnreachable);
    case S5_R_ERROR_HOST_UNREACH:
        throw Socks5Exception(Socks5Exception::HostUnreachable);
    case S5_R_ERROR_CONN_REFUSED:
        throw Socks5Exception(Socks5Exception::ConnectionRefused);
    case S5_R_ERROR_TTL:
        throw Socks5Exception(Socks5Exception::TTLExpired);
    case S5_R_ERROR_CMD_NOT_SUPPORTED:
        throw Socks5Exception(Socks5Exception::CommandNotSupported);
    case S5_R_ERROR_ADD_TYPE_NOT_SUPORTED:
        throw Socks5Exception(Socks5Exception::AddressTypeNotSupported);
    default:
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    const QByteArray &addressType = s->recvall(2);
    if (addressType.size() < 2) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
    if (addressType.at(1) == S5_IP_V4) {
        const QByteArray &ipv4 = s->recvall(4);
        if (ipv4.size() < 4) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        HostAddress boundIp;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        boundIp.setAddress(qFromBigEndian<quint32>(reinterpret_cast<const void *>(ipv4.constData())));
#else
        boundIp.setAddress(qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(ipv4.constData())));
#endif
    } else if (addressType.at(1) == S5_IP_V6) {
        QByteArray ipv6 = s->recvall(16);
        if (ipv6.size() < 16) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        HostAddress boundIp;
        boundIp.setAddress(reinterpret_cast<quint8 *>(ipv6.data()));
    } else if (addressType.at(1) == S5_DOMAINNAME) {
        const QByteArray &len = s->recvall(1);
        if (len.isEmpty()) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
        const QByteArray &hostName = s->recvall(quint8(len.at(0)));
        if (hostName.size() < len.at(0)) {
            throw Socks5Exception(Socks5Exception::ProxyProtocolError);
        }
    } else {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    const QByteArray &portBytes = s->recvall(2);
    if (portBytes.size() < 2) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    quint16 port = qFromBigEndian<quint16>(reinterpret_cast<const void *>(portBytes.constData()));
#else
    quint16 port = qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(portBytes.constData()));
#endif

    Q_UNUSED(port);

    return s;
}

QSharedPointer<SocketLike> Socks5ProxyPrivate::connect(const QString &hostName, quint16 port) const
{
    QSharedPointer<Socket> s = getControlSocket();
    QByteArray connectRequest = makeConnectRequest();

    if (!qt_socks5_set_host_name_and_port(hostName, port, &connectRequest)) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    QSharedPointer<Socket> ret = sendConnectRequest(s, connectRequest);
    if (ret) {
        return asSocketLike(ret);
    }
    return QSharedPointer<SocketLike>();
}

QSharedPointer<SocketLike> Socks5ProxyPrivate::connect(const HostAddress &host, quint16 port) const
{
    QSharedPointer<Socket> s = getControlSocket();
    QByteArray connectRequest = makeConnectRequest();

    if (!qt_socks5_set_host_address_and_port(host, port, &connectRequest)) {
        throw Socks5Exception(Socks5Exception::ProxyProtocolError);
    }

    QSharedPointer<Socket> ret = sendConnectRequest(s, connectRequest);
    if (ret) {
        return asSocketLike(ret);
    }
    return QSharedPointer<SocketLike>();
}

QSharedPointer<SocketLike> Socks5ProxyPrivate::listen(quint16 port) const
{
    Q_UNIMPLEMENTED();
    Q_UNUSED(port);
    return QSharedPointer<SocketLike>();
}

Socks5Proxy::Socks5Proxy()
    : d_ptr(new Socks5ProxyPrivate)
{
}

Socks5Proxy::Socks5Proxy(const QString &hostName, quint16 port, const QString &user, const QString &password)
    : d_ptr(new Socks5ProxyPrivate(hostName, port, user, password))
{
}

Socks5Proxy::Socks5Proxy(const Socks5Proxy &other)
    : d_ptr(new Socks5ProxyPrivate(other.d_ptr->hostName, other.d_ptr->port, other.d_ptr->user, other.d_ptr->password))
{
}

Socks5Proxy::~Socks5Proxy()
{
    if (d_ptr)
        delete d_ptr;
}

Socks5Proxy &Socks5Proxy::operator=(const Socks5Proxy &other)
{
    delete d_ptr;
    d_ptr = new Socks5ProxyPrivate(other.hostName(), other.port(), other.user(), other.password());
    return *this;
}

Socks5Proxy &Socks5Proxy::operator=(Socks5Proxy &&other)
{
    delete d_ptr;
    d_ptr = nullptr;
    qSwap(d_ptr, other.d_ptr);
    return *this;
}

bool Socks5Proxy::isNull() const
{
    Q_D(const Socks5Proxy);
    return d->hostName.isEmpty() || d->port == 0;
}

Socks5Proxy::Capabilities Socks5Proxy::capabilities() const
{
    Q_D(const Socks5Proxy);
    return d->capabilities;
}

QString Socks5Proxy::hostName() const
{
    Q_D(const Socks5Proxy);
    return d->hostName;
}

quint16 Socks5Proxy::port() const
{
    Q_D(const Socks5Proxy);
    return d->port;
}

QString Socks5Proxy::user() const
{
    Q_D(const Socks5Proxy);
    return d->user;
}

QString Socks5Proxy::password() const
{
    Q_D(const Socks5Proxy);
    return d->password;
}

void Socks5Proxy::setCapabilities(Socks5Proxy::Capabilities capabilities)
{
    Q_D(Socks5Proxy);
    d->capabilities = capabilities;
}

void Socks5Proxy::setHostName(const QString &hostName)
{
    Q_D(Socks5Proxy);
    d->hostName = hostName;
}

void Socks5Proxy::setPort(quint16 port)
{
    Q_D(Socks5Proxy);
    d->port = port;
}

void Socks5Proxy::setUser(const QString &user)
{
    Q_D(Socks5Proxy);
    d->user = user;
}

void Socks5Proxy::setPassword(const QString &password)
{
    Q_D(Socks5Proxy);
    d->password = password;
}

QSharedPointer<SocketLike> Socks5Proxy::connect(const QString &hostName, quint16 port)
{
    Q_D(const Socks5Proxy);
    return d->connect(hostName, port);
}

QSharedPointer<SocketLike> Socks5Proxy::connect(const HostAddress &host, quint16 port)
{
    Q_D(const Socks5Proxy);
    return d->connect(host, port);
}

QSharedPointer<SocketLike> Socks5Proxy::listen(quint16 port)
{
    Q_D(const Socks5Proxy);
    return d->listen(port);
}

QTNETWORKNG_NAMESPACE_END
