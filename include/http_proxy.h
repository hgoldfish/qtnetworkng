#ifndef QTNG_HTTP_PROXY_H
#define QTNG_HTTP_PROXY_H

#include <QtCore/qsharedpointer.h>
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpProxyPrivate;
class HttpProxy: public HttpHeaderManager
{
public:
    enum Capability
    {
        TunnelingCapability = 0x001,
        CachingCapability = 0x008,
    };
public:
    HttpProxy();
    HttpProxy(const QString &hostName, quint16 port = 0,
                 const QString &user = QString(), const QString &password = QString());
    HttpProxy(const HttpProxy &other);
    HttpProxy(HttpProxy &&other) :d_ptr(nullptr) { qSwap(d_ptr, other.d_ptr); }
    ~HttpProxy();
public:
    QSharedPointer<Socket> connect(const QString &remoteHost, quint16 port);
    QSharedPointer<Socket> connect(const QHostAddress &remoteHost, quint16 port);
public:
    QString hostName() const;
    quint16 port() const;
    QString user() const;
    QString password() const;
    void setHostName(const QString &hostName);
    void setPort(quint16 port);
    void setUser(const QString &user);
    void setPassword(const QString &password);
public:
    void swap(HttpProxy &other) { qSwap(d_ptr, other.d_ptr); }
    bool operator!=(const HttpProxy &other) const { return !(*this == other); }
    HttpProxy &operator=(const HttpProxy &other);
    HttpProxy &operator=(HttpProxy &&other);
    bool operator==(const HttpProxy &other) const;
private:
    HttpProxyPrivate * d_ptr;
    Q_DECLARE_PRIVATE(HttpProxy)
};


class Socks5Proxy;
class BaseProxySwitcher
{
public:
    BaseProxySwitcher();
    virtual ~BaseProxySwitcher();
public:
    virtual QSharedPointer<Socks5Proxy> selectSocks5Proxy(const QUrl &url) = 0;
    virtual QSharedPointer<HttpProxy> selectHttpProxy(const QUrl &url) = 0;
};


class SimpleProxySwitcher: public BaseProxySwitcher
{
public:
    virtual QSharedPointer<Socks5Proxy> selectSocks5Proxy(const QUrl &url) override;
    virtual QSharedPointer<HttpProxy> selectHttpProxy(const QUrl &url) override;
public:
    QList<QSharedPointer<Socks5Proxy>> socks5Proxies;
    QList<QSharedPointer<HttpProxy>> httpProxies;
};


void setProxySwitcher(class HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher);


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_PROXY_H
