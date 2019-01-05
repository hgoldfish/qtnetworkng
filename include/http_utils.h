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
    Unknown,
    Http1_0,
    Http1_1,
    Http2_0,
    http3_0,
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


struct HttpHeader {
    HttpHeader(const QString &name, const QByteArray &value) :name(name), value(value) {}
    HttpHeader() {}
    bool isValid() const { return !name.isEmpty(); }
    QString name;
    QByteArray value;
};

class HeaderOperationMixin
{
public:
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
    QByteArray header(KnownHeader header, const QByteArray &defaultValue = QByteArray()) const;
    QByteArrayList multiHeader(const QString &name) const;
    QList<HttpHeader> allHeaders() const { return headers; }
    void setHeaders(const QMap<QString, QByteArray> headers);
    void setHeaders(const QList<HttpHeader> &headers) { this->headers = headers; }

    static QDateTime fromHttpDate(const QByteArray &value);
    static QByteArray toHttpDate(const QDateTime &dt);
protected:
    QList<HttpHeader> headers;
};

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
    HeaderSplitter(QSharedPointer<SocketLike> connection, const QByteArray &buf)
        :connection(connection), buf(buf) {}
    HeaderSplitter(QSharedPointer<SocketLike> connection)
        :connection(connection) {}
    QByteArray nextLine(Error *error);
    HttpHeader nextHeader(Error *error);
    QList<HttpHeader> headers(int maxHeaders, Error *error);
public:
    QSharedPointer<SocketLike> connection;
    QByteArray buf;
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
