#ifndef QTNG_HTTP_UTILS_H
#define QTNG_HTTP_UTILS_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qlist.h>
#include <QtCore/qurl.h>
#include <QtCore/qmap.h>
#include "socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

enum HttpVersion
{
    Unknown = 0,
    Http1_0 = 1,
    Http1_1 = 2,
    Http2_0 = 3,
    http3_0 = 4,
};


enum HttpStatus
{
    Continue = 100,
    SwitchProtocol = 101,
    Processing = 102,

    OK = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritative = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    IMUsed = 226,

    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,

    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    RequestEntityTooLarge = 413,
    RequestURITooLong = 414,
    UnsupportedMediaType = 415,
    RequestedRangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    ImaTeaport = 418,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequests = 429,
    RequestHeaderFieldsTooLarge = 441,

    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HTTPVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
};


bool toMessage(HttpStatus status, QString *shortMessage, QString *longMessage);


enum KnownHeader {
    ContentTypeHeader,
    ContentLengthHeader,
    ContentEncodingHeader,
    TransferEncodingHeader,
    LocationHeader,
    LastModifiedHeader,
    CookieHeader,
    SetCookieHeader,
    ContentDispositionHeader,  // added for QMultipartMessage
    ServerHeader,
    UserAgentHeader,
    AcceptHeader,
    AcceptLanguageHeader,
    AcceptEncodingHeader,
    PragmaHeader,
    CacheControlHeader,
    DateHeader,
    AllowHeader,
    VaryHeader,
    FrameOptionsHeader,
    MIMEVersionHeader,
    ConnectionHeader,
    UpgradeHeader,
    HostHeader,
};


QString normalizeHeaderName(const QString &headerName);
QDateTime fromHttpDate(const QByteArray &value);
QByteArray toHttpDate(const QDateTime &dt);
QString toString(KnownHeader knownHeader);


struct HttpHeader {
    HttpHeader(const QString &name, const QByteArray &value) :name(name), value(value) {}
    HttpHeader() {}
    bool isValid() const { return !name.isEmpty(); }
    QString name;
    QByteArray value;
};


QDataStream &operator >>(QDataStream &ds, HttpHeader &header);
QDataStream &operator <<(QDataStream &ds, const HttpHeader &header);

template<typename Base>
class WithHttpHeaders: public Base
{
public:
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
    void addHeader(const HttpHeader &header);
    bool hasHeader(const QString &name) const;
    bool removeHeader(const QString &name);
    void setHeader(KnownHeader header, const QByteArray &value);
    void addHeader(KnownHeader header, const QByteArray &value);
    bool hasHeader(KnownHeader header) const;
    bool removeHeader(KnownHeader header);
    QByteArray header(const QString &name, const QByteArray &defaultValue = QByteArray()) const;
    QByteArray header(KnownHeader header, const QByteArray &defaultValue = QByteArray()) const;
#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
    QByteArrayList multiHeader(const QString &name) const;
    QByteArrayList multiHeader(KnownHeader header) const;
#else
    QList<QByteArray> multiHeader(const QString &name) const;
    QList<QByteArray> multiHeader(KnownHeader header) const;
#endif
    QList<HttpHeader> allHeaders() const { return headers; }
    void setHeaders(const QMap<QString, QByteArray> headers);
    void setHeaders(const QList<HttpHeader> &headers) { this->headers = headers; }
protected:
    QList<HttpHeader> headers;
};
class EmptyClass {};
class HttpHeaderManager: public WithHttpHeaders<EmptyClass> {};


template<typename Base>
void WithHttpHeaders<Base>::setContentLength(qint64 contentLength)
{
    setHeader(QStringLiteral("Content-Length"), QString::number(contentLength).toLatin1());
}


template<typename Base>
qint32 WithHttpHeaders<Base>::getContentLength() const
{
    bool ok;
    QByteArray s = header(QStringLiteral("Content-Length"));
    qint32 l = s.toInt(&ok);
    if(ok) {
        if (l >= 0) {
            return l;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}


template<typename Base>
void WithHttpHeaders<Base>::setContentType(const QString &contentType)
{
    setHeader(QStringLiteral("Content-Type"), contentType.toUtf8());
}


template<typename Base>
QString WithHttpHeaders<Base>::getContentType() const
{
    return QString::fromUtf8(header(QStringLiteral("Content-Type"), "text/plain"));
}


template<typename Base>
QUrl WithHttpHeaders<Base>::getLocation() const
{
    const QByteArray &value = header(QStringLiteral("Location"));
    if(value.isEmpty()) {
        return QUrl();
    }
    QUrl result = QUrl::fromEncoded(value, QUrl::StrictMode);
    if (result.isValid()) {
        return result;
    } else {
        return QUrl();
    }
}


template<typename Base>
void WithHttpHeaders<Base>::setLocation(const QUrl &url)
{
    setHeader(QStringLiteral("Location"), url.toEncoded(QUrl::FullyEncoded));
}


template<typename Base>
QDateTime WithHttpHeaders<Base>::getLastModified() const
{
    const QByteArray &value = header(QStringLiteral("Last-Modified"));
    if(value.isEmpty()) {
        return QDateTime();
    }
    return fromHttpDate(value);
}


template<typename Base>
void WithHttpHeaders<Base>::setLastModified(const QDateTime &lastModified)
{
    setHeader(QStringLiteral("Last-Modified"), toHttpDate(lastModified));
}


template<typename Base>
void WithHttpHeaders<Base>::setModifiedSince(const QDateTime &modifiedSince)
{
    setHeader(QStringLiteral("Modified-Since"), toHttpDate(modifiedSince));
}


template<typename Base>
QDateTime WithHttpHeaders<Base>::getModifedSince() const
{
    const QByteArray &value = header(QStringLiteral("Modified-Since"));
    if(value.isEmpty()) {
        return QDateTime();
    }
    return fromHttpDate(value);
}


template<typename Base>
bool WithHttpHeaders<Base>::hasHeader(const QString &headerName) const
{
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}


template<typename Base>
bool WithHttpHeaders<Base>::removeHeader(const QString &headerName)
{
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            headers.removeAt(i);
            return true;
        }
    }
    return false;
}


template<typename Base>
void WithHttpHeaders<Base>::setHeader(const QString &name, const QByteArray &value)
{
    removeHeader(name);
    addHeader(name, value);
}


template<typename Base>
void WithHttpHeaders<Base>::addHeader(const QString &name, const QByteArray &value)
{
    headers.append(HttpHeader(normalizeHeaderName(name), value));
}


template<typename Base>
void WithHttpHeaders<Base>::addHeader(const HttpHeader &header)
{
    headers.append(header);
}


template<typename Base>
void WithHttpHeaders<Base>::setHeader(KnownHeader header, const QByteArray &value)
{
    setHeader(toString(header), value);
}


template<typename Base>
void WithHttpHeaders<Base>::addHeader(KnownHeader header, const QByteArray &value)
{
    addHeader(toString(header), value);
}


template<typename Base>
bool WithHttpHeaders<Base>::hasHeader(KnownHeader header) const
{
    return hasHeader(toString(header));
}


template<typename Base>
bool WithHttpHeaders<Base>::removeHeader(KnownHeader header)
{
    return removeHeader(toString(header));
}


template<typename Base>
QByteArray WithHttpHeaders<Base>::header(const QString &headerName, const QByteArray &defaultValue) const
{
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if (header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return header.value;
        }
    }
    return defaultValue;
}


template<typename Base>
QByteArray WithHttpHeaders<Base>::header(KnownHeader knownHeader, const QByteArray &defaultValue) const
{
    return header(toString(knownHeader), defaultValue);
}


#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
#define QBYTEARRAYLIST QByteArrayList
#else
#define QBYTEARRAYLIST QList<QByteArray>
#endif


template<typename Base>
QBYTEARRAYLIST WithHttpHeaders<Base>::multiHeader(const QString &headerName) const
{
    QBYTEARRAYLIST l;
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            l.append(header.value);
        }
    }
    return l;
}


template<typename Base>
QBYTEARRAYLIST WithHttpHeaders<Base>::multiHeader(KnownHeader header) const
{
    return multiHeader(toString(header));
}


#undef QBYTEARRAYLIST

template<typename Base>
void WithHttpHeaders<Base>::setHeaders(const QMap<QString, QByteArray> headers)
{
    this->headers.clear();
    for (QMap<QString, QByteArray>::const_iterator itor = headers.constBegin(); itor != headers.constEnd(); ++itor) {
        this->headers.append(HttpHeader(normalizeHeaderName(itor.key()), itor.value()));
    }
}


QList<QByteArray> splitBytes(const QByteArray &bs, char sep, int maxSplit = -1);


class HeaderSplitter
{
public:
    enum Error {
        NoError,
        EncodingError,
        ExhausedMaxLine,
        ConnectionError,
        LineTooLong,
    };
public:
    HeaderSplitter(QSharedPointer<SocketLike> connection, const QByteArray &buf, int debugLevel = 0)
        :connection(connection), buf(buf), debugLevel(debugLevel) {}
    HeaderSplitter(QSharedPointer<SocketLike> connection, int debugLevel = 0)
        :connection(connection), debugLevel(debugLevel) {}
    QByteArray nextLine(Error *error);
    HttpHeader nextHeader(Error *error);
    QList<HttpHeader> headers(int maxHeaders, Error *error);
public:
    QSharedPointer<SocketLike> connection;
    QByteArray buf;
    int debugLevel;
};


class ChunkedBlockReader
{
public:
    enum Error {
        NoError,
        ChunkedEncodingError,
        UnrewindableBodyError,
        ConnectionError,
    };
public:
    ChunkedBlockReader(QSharedPointer<SocketLike> connection, const QByteArray &buf)
        :connection(connection), buf(buf) {}
public:
    QByteArray nextBlock(qint64 leftBytes, Error *error);
public:
    int debugLevel;
    QSharedPointer<SocketLike> connection;
    QByteArray buf;
};


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_UTILS_H
