#ifndef HTTP_NG_P_H
#define HTTP_NG_P_H

#include "http_ng.h"
#include "locks.h"
#include "socket_ng.h"

class SessionPrivate
{
public:
    SessionPrivate(Session *q_ptr);
    virtual ~SessionPrivate();

    void setDefaultUserAgent(const QString &userAgent);
    QMap<QString, QByteArray> makeHeaders(Request &request, const QUrl &url);
    void mergeCookies(Request &request, const QUrl &url);
    Response send(Request &req);
    QNetworkCookieJar &getCookieJar() { return cookieJar; }
private:
    QNetworkCookieJar cookieJar;
    QString defaultUserAgent;
    Session *q_ptr;
    int maxConnectionsPerServer;
    QMap<QString, QSharedPointer<Semaphore>> connectionSemaphores;
    QSharedPointer<QSocketNgDnsCache> dnsCache;
    Q_DECLARE_PUBLIC(Session)
};

#endif // HTTP_NG_P_H
