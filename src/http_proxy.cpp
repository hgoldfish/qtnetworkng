#include "../include/http_proxy.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpProxyPrivate
{
public:
    HttpProxyPrivate() {}
    HttpProxyPrivate(const QString &hostName, quint16 port, const QString &user, const QString &password)
        :hostName(hostName), port(port), user(user), password(password) {}
public:
    QString hostName;
    quint16 port;
    QString user;
    QString password;
};


HttpProxy::HttpProxy()
    :d_ptr(new HttpProxyPrivate)
{
}

HttpProxy::HttpProxy(const QString &hostName, quint16 port, const QString &user, const QString &password)
    :d_ptr(new HttpProxyPrivate(hostName, port, user, password))
{
}

HttpProxy::HttpProxy(const HttpProxy &other)
    :d_ptr(new HttpProxyPrivate(other.d_ptr->hostName, other.d_ptr->port,
                                other.d_ptr->user, other.d_ptr->password))
{
}

HttpProxy &HttpProxy::operator=(HttpProxy &&other)
{
    delete d_ptr;
    d_ptr = new HttpProxyPrivate(other.hostName(), other.port(), other.user(), other.password());
    return *this;
}

QString HttpProxy::hostName() const
{
    Q_D(const HttpProxy);
    return d->hostName;
}

quint16 HttpProxy::port() const
{
    Q_D(const HttpProxy);
    return d->port;
}

QString HttpProxy::user() const
{
    Q_D(const HttpProxy);
    return d->user;
}

QString HttpProxy::password() const
{
    Q_D(const HttpProxy);
    return d->password;
}

void HttpProxy::setHostName(const QString &hostName)
{
    Q_D(HttpProxy);
    d->hostName = hostName;
}

void HttpProxy::setUser(const QString &user)
{
    Q_D(HttpProxy);
    d->user = user;
}

void HttpProxy::setPassword(const QString &password)
{
    Q_D(HttpProxy);
    d->password = password;
}


BaseProxySwitcher::BaseProxySwitcher() {}
BaseProxySwitcher::~BaseProxySwitcher() {}


QSharedPointer<Socks5Proxy> SimpleProxySwitcher::selectSocks5Proxy(const QUrl &url)
{
    Q_UNUSED(url);
    if(socks5Proxies.size() > 0) {
        return socks5Proxies.at(0);
    }
    return QSharedPointer<Socks5Proxy>();
}


QSharedPointer<HttpProxy> SimpleProxySwitcher::selectHttpProxy(const QUrl &url)
{
    Q_UNUSED(url);
    if(httpProxies.size() > 0) {
        return httpProxies.at(0);
    }
    return QSharedPointer<HttpProxy>();
}

//implemented in http.cpp
void setProxySwitcher(class HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher);

QTNETWORKNG_NAMESPACE_END
