#ifndef QTNG_HTTP_NG_P_H
#define QTNG_HTTP_NG_P_H

#include "http_ng.h"
#include "locks.h"
#include "socket_ng.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpSessionPrivate
{
public:
    HttpSessionPrivate(HttpSession *q_ptr);
    virtual ~HttpSessionPrivate();

    void setDefaultUserAgent(const QString &userAgent);
    QMap<QString, QByteArray> makeHeaders(HttpRequest &request, const QUrl &url);
    void mergeCookies(HttpRequest &request, const QUrl &url);
    HttpResponse send(HttpRequest &req);
    QNetworkCookieJar &getCookieJar() { return cookieJar; }
private:
    QNetworkCookieJar cookieJar;
    QString defaultUserAgent;
    HttpSession *q_ptr;
    int maxConnectionsPerServer;
    int debugLevel;
    QMap<QString, QSharedPointer<Semaphore>> connectionSemaphores;
    QSharedPointer<QSocketNgDnsCache> dnsCache;
    Q_DECLARE_PUBLIC(HttpSession)
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_NG_P_H
