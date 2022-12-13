#ifndef QTNG_HTTP_P_H
#define QTNG_HTTP_P_H

#include "../http.h"
#include "../locks.h"
#include "../socket.h"
#include "../socket_utils.h"
#include "../coroutine_utils.h"
#include "../http_proxy.h"
#include "../ssl.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpProxy;
class Socks5Proxy;
class ConnectionPoolItem
{
public:
    ConnectionPoolItem() { }
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
    QSharedPointer<SocketLike> oldConnectionForUrl(const QUrl &url);
    QSharedPointer<SocketLike> newConnectionForUrl(const QUrl &url, RequestError **error);
    void removeUnusedConnections();
    QSharedPointer<SocketProxy> socketProxy() const;
    QSharedPointer<HttpProxy> httpProxy() const;
    void setSocketProxy(QSharedPointer<SocketProxy> proxy);
    void setHttpProxy(QSharedPointer<HttpProxy> proxy);
private:
    ConnectionPoolItem &getItem(const QUrl &url);
public:
    QMap<QUrl, ConnectionPoolItem> items;
    QSharedPointer<SocketDnsCache> dnsCache;
    QSharedPointer<BaseProxySwitcher> proxySwitcher;
#ifndef QTNG_NO_CRYPTO
    SslConfiguration sslConfig;
#endif
    int maxConnectionsPerServer;
    int timeToLive;
    float defaultConnectionTimeout;
    float defaultTimeout;
    CoroutineGroup *operations;
};

class HttpSessionPrivate : public ConnectionPool
{
public:
    HttpSessionPrivate(HttpSession *q_ptr);
    virtual ~HttpSessionPrivate();
    QList<HttpHeader> makeHeaders(HttpRequest &request, const QUrl &url);
    void mergeCookies(HttpRequest &request, const QUrl &url);
    HttpResponse send(HttpRequest &req);
public:
    HttpCookieJar cookieJar;
    QSharedPointer<HttpCacheManager> cacheManager;
    QString defaultUserAgent;
    HttpVersion defaultVersion;
    HttpSession *q_ptr;
    int debugLevel;
    bool managingCookies;
    bool keepAlive;
    friend void setProxySwitcher(HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher);
    static inline HttpSessionPrivate *getPrivateHelper(HttpSession *session) { return session->d_ptr; }
    Q_DECLARE_PUBLIC(HttpSession)
};

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_HTTP_P_H
