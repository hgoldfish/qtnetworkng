#ifndef QTNG_SOCKS5PROXY_H
#define QTNG_SOCKS5PROXY_H

#include "socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


class Socks5Exception
{
public:
    enum Error
    {
        ProxyConnectionRefusedError,
        ProxyConnectionClosedError,
        ProxyConnectionTimeoutError,
        ProxyNotFoundError,
        ProxyProtocolError,
        ProxyAuthenticationRequiredError,

        SocksFailure,
        ConnectionNotAllowed,
        NetworkUnreachable,
        HostUnreachable,
        ConnectionRefused,
        TTLExpired,
        CommandNotSupported,
        AddressTypeNotSupported,
    };
public:
    Socks5Exception(Error err)
        :err(err) {}
public:
    Error error() const;
    QString errorString() const;
    QString what() const { return errorString(); }
private:
    Error err;
};

class Socks5ProxyPrivate;
class Socks5Proxy
{
public:
    enum Capability
    {
        TunnelingCapability = 0x0001,
        ListeningCapability = 0x0002,
        UdpTunnelingCapability = 0x0003,
        HostNameLookupCapability = 0x0010,
    };
    Q_DECLARE_FLAGS(Capabilities, Capability)
public:
    Socks5Proxy();
    Socks5Proxy(const QString &hostName, quint16 port,
                 const QString &user = QString(), const QString &password = QString());
    Socks5Proxy(const Socks5Proxy &other);
    Socks5Proxy(Socks5Proxy &&other) :d_ptr(nullptr) { qSwap(d_ptr, other.d_ptr); }
    ~Socks5Proxy();
public:
    QSharedPointer<Socket> connect(const QString &remoteHost, quint16 port);
    QSharedPointer<Socket> connect(const QHostAddress &remoteHost, quint16 port);
    QSharedPointer<SocketLike> listen(quint16 port);

    bool isNull() const;
    Capabilities capabilities() const;
    QString hostName() const;
    quint16 port() const;
    QString user() const;
    QString password() const;
    void setCapabilities(Capabilities capabilities);
    void setHostName(const QString &hostName);
    void setPort(quint16 port);
    void setUser(const QString &user);
    void setPassword(const QString &password);
public:
    void swap(Socks5Proxy &other) { qSwap(d_ptr, other.d_ptr); }
    bool operator!=(const Socks5Proxy &other) const { return !(*this == other); }
    Socks5Proxy &operator=(const Socks5Proxy &other);
    Socks5Proxy &operator=(Socks5Proxy &&other);
    bool operator==(const Socks5Proxy &other) const;
private:
    Socks5ProxyPrivate * d_ptr;
    Q_DECLARE_PRIVATE(Socks5Proxy)
};

QTNETWORKNG_NAMESPACE_END

Q_DECLARE_OPERATORS_FOR_FLAGS(QTNETWORKNG_NAMESPACE::Socks5Proxy::Capabilities)

#endif // QTNG_SOCKS5PROXY_H
