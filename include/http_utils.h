#ifndef QTNG_HTTP_UTILS_H
#define QTNG_HTTP_UTILS_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qlist.h>
#include <QtCore/qurl.h>
#include <QtCore/qmap.h>
#include "config.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct HttpHeader {
    HttpHeader(const QString &name, const QByteArray &value) :name(name), value(value) {}
    QString name;
    QByteArray value;
};

class HeaderOperationMixin
{
public:
    enum KnownHeaders {
        ContentTypeHeader,
        ContentLengthHeader,
        LocationHeader,
        LastModifiedHeader,
        CookieHeader,
        SetCookieHeader,
        ContentDispositionHeader,  // added for QMultipartMessage
        UserAgentHeader,
        ServerHeader
    };

    void setContentType(const QString &contentType);
    QString getContentType() const;
    void setContentLength(qint64 contentLength);
    qint32 getContentLength() const;
    void setLocation(const QUrl &url);
    QUrl getLocation() const;
    void setLastModified(const QDateTime &lastModified);
    QDateTime getLastModified() const;
    void setModifiedSince(const QDateTime &modifiedSince);
    QDateTime getModifedSince() const;

    void setHeader(const QString &name, const QByteArray &value);
    void addHeader(const QString &name, const QByteArray &value);
    bool hasHeader(const QString &name) const;
    bool removeHeader(const QString &name);
    QByteArray header(const QString &name, const QByteArray &defaultValue = QByteArray()) const;
    QByteArrayList multiHeader(const QString &name) const;
    QList<HttpHeader> allHeaders() const { return headers; }
    void setHeaders(const QMap<QString, QByteArray> headers);

    static QDateTime fromHttpDate(const QByteArray &value);
    static QByteArray toHttpDate(const QDateTime &dt);
protected:
    QList<HttpHeader> headers;
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_UTILS_H
