#ifndef QTNG_HTTP_P_H
#define QTNG_HTTP_P_H

#include "../http.h"
#include "../locks.h"
#include "../socket.h"
#include "../socket_utils.h"
#include "../coroutine_utils.h"
#include "../http_proxy.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpProxy;
class Socks5Proxy;
class ConnectionPoolItem
{
public:
    ConnectionPoolItem() {}
public:
    QDateTime lastUsed;
    QSharedPointer<Semaphore> semaphore;
    QList<QSharedPointer<SocketLike>> connections;
};


class ConnectionPool
{
public:
    ConnectionPool();
    virtual ~ConnectionPool();
    QSharedPointer<Semaphore> getSemaphore(const QUrl &url);
    void recycle(const QUrl &url, QSharedPointer<SocketLike> connection);
    QSharedPointer<SocketLike> connectionForUrl(const QUrl &url, RequestError **error);
    void removeUnusedConnections();
    QSharedPointer<Socks5Proxy> socks5Proxy() const;
    QSharedPointer<HttpProxy> httpProxy() const;
    void setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy);
    void setHttpProxy(QSharedPointer<HttpProxy> proxy);
private:
    ConnectionPoolItem &getItem(const QUrl &url);
public:
    QMap<QUrl, ConnectionPoolItem> items;
    int maxConnectionsPerServer;
    int timeToLive;
    QSharedPointer<SocketDnsCache> dnsCache;
    CoroutineGroup *operations;
    QSharedPointer<BaseProxySwitcher> proxySwitcher;
};


class HttpSessionPrivate: public ConnectionPool
{
public:
    HttpSessionPrivate(HttpSession *q_ptr);
    virtual ~HttpSessionPrivate();
    QList<HttpHeader> makeHeaders(HttpRequest &request, const QUrl &url);
    void mergeCookies(HttpRequest &request, const QUrl &url);
    HttpResponse send(HttpRequest &req);
public:
    QNetworkCookieJar cookieJar;
    QString defaultUserAgent;
    HttpVersion defaultVersion;
    HttpSession *q_ptr;
    int debugLevel;
    friend void setProxySwitcher(HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher);
    static inline HttpSessionPrivate *getPrivateHelper(HttpSession *session) {return session->d_ptr; }
    Q_DECLARE_PUBLIC(HttpSession)
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_P_H
