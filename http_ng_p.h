#ifndef HTTP_NG_P_H
#define HTTP_NG_P_H

#include "http_ng.h"

class SessionPrivate
{
public:
    SessionPrivate(Session *q_ptr);
    virtual ~SessionPrivate();

    void setDefaultUserAgent(const QString &userAgent);
    QMap<QString, QString> makeHeaders(Request &request, const QUrl &url);
    void mergeCookies(Request &request, const QUrl &url);
    Response send(Request &req);

private:
    QNetworkCookieJar cookie_jar;
    QString defaultUserAgent;
    Session *q_ptr;
    Q_DECLARE_PUBLIC(Session)
};

#endif // HTTP_NG_P_H
