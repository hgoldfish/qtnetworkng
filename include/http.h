#ifndef QTNG_HTTP_H
#define QTNG_HTTP_H

#include <QtCore/qstring.h>
#include <QtCore/qmap.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qmimedatabase.h>
#include <QtNetwork/qnetworkcookie.h>
#include <QtNetwork/qnetworkcookiejar.h>

#include "coroutine.h"
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


struct FormDataFile
{
    FormDataFile(const QString &filename, const QByteArray &data, const QString &contentType)
        :filename(filename), data(data), contentType(contentType) {}

    QString filename;
    QByteArray data;
    QString contentType;
};

class FormData
{
public:
    FormData();
    QByteArray toByteArray() const;

    void addFile(const QString &name, const QString &filename, const QByteArray &data, const QString &contentType = QString())
    {
        QString newContentType;
        if(contentType.isEmpty()) {
#ifndef Q_OS_ANDROID
            QMimeDatabase db;
            newContentType = db.mimeTypeForFileNameAndData(filename, data).name();
#endif
        } else {
            newContentType = contentType;
        }
        if (newContentType.isEmpty()) {
            newContentType = "application/octet-stream";
        }
        files.insert(name, FormDataFile(filename, data, newContentType));
    }

    void addQuery(const QString &key, const QString &value)
    {
        query.insert(key, value);
    }
public:
    QMap<QString, QString> query;
    QMap<QString, FormDataFile> files;
    QByteArray boundary;
};


class HttpRequestPrivate;
class HttpRequest: public HeaderOperationMixin
{
public:
    enum CacheLoadControl {
        AlwaysNetwork,
        PreferNetwork,
        PreferCache,
        AlwaysCache
    };
    enum Priority {
        HighPriority = 1,
        NormalPriority = 3,
        LowPriority = 5
    };

    HttpRequest();
    HttpRequest(const QString &url)
        :HttpRequest() { setUrl(url); }
    HttpRequest(const QString &method, const QString &url)
        :HttpRequest() { setMethod(method); setUrl(url); }
    virtual ~HttpRequest();
    HttpRequest(const HttpRequest &other);
    HttpRequest(HttpRequest &&other);
    HttpRequest &operator=(const HttpRequest &other);
public:
    QString method() const;
    void setMethod(const QString &method);
    QUrl url() const;
    void setUrl(const QUrl &url);
    void setUrl(const QString &url) {setUrl(QUrl::fromUserInput(url)); }
    QMap<QString, QString> query() const;
    void setQuery(const QMap<QString, QString> &query);
    QList<QNetworkCookie> cookies() const;
    void setCookies(const QList<QNetworkCookie> &cookies);
    QByteArray body() const;
    void setBody(const QByteArray &body);
    int maxBodySize() const;
    void setMaxBodySize(int maxBodySize);
    int maxRedirects() const;
    void setMaxRedirects(int maxRedirects);
    Priority priority() const;
    void setPriority(Priority priority);
    HttpVersion version() const;
    void setVersion(HttpVersion version);
    void setStreamResponse(bool streamResponse);
    bool streamResponse() const;
public:
    void setFormData(FormData &formData, const QString &method = QStringLiteral("post"));
    static HttpRequest fromFormData(const FormData &formData);
    static HttpRequest fromForm(const QUrlQuery &data);
    static HttpRequest fromForm(const QMap<QString, QString> &query);
    static HttpRequest fromJson(const QJsonDocument &json);
    static HttpRequest fromJson(const QJsonArray &json) { return fromJson(QJsonDocument(json)); }
    static HttpRequest fromJson(const QJsonObject &json) { return fromJson(QJsonDocument(json)); }
private:
    QSharedDataPointer<HttpRequestPrivate> d;
    friend class HttpSessionPrivate;
};


class RequestError
{
public:
    virtual ~RequestError();
    virtual QString what() const;
};


class HttpResponsePrivate;
class HttpResponse: public HeaderOperationMixin
{
public:
    HttpResponse();
    virtual ~HttpResponse();
    HttpResponse(const HttpResponse& other);
    HttpResponse(HttpResponse &&other);
    HttpResponse &operator=(const HttpResponse& other);
public:
    QUrl url() const;
    void setUrl(const QUrl &url);
    int statusCode() const;
    void setStatusCode(int statusCode);
    QString statusText() const;
    void setStatusText(const QString &statusText);
    QList<QNetworkCookie> cookies() const;
    void setCookies(const QList<QNetworkCookie> &cookies);
    HttpRequest request() const;
    void setRequest(const HttpRequest &request);
    qint64 elapsed() const;
    void setElapsed(qint64 elapsed);
    QList<HttpResponse> history() const;
    void setHistory(const QList<HttpResponse> &history);
    HttpVersion version() const;
    void setVersion(HttpVersion version);

    QSharedPointer<SocketLike> takeStream(QByteArray *readBytes);
    QByteArray body();
    void setBody(const QByteArray &body);
    QString text();
    QJsonDocument json();
    QString html();

    bool isOk() const;
    bool hasNetworkError() const;
    bool hasHttpError() const;
public:
    QSharedPointer<RequestError> error() const;
    void setError(QSharedPointer<RequestError> error);
    void setError(RequestError *error) { setError(QSharedPointer<RequestError>(error)); }
private:
    QSharedDataPointer<HttpResponsePrivate> d;
    friend class HttpSessionPrivate;
};


#define COMMON_PARAMETERS \
    const QMap<QString, QString> &query = QMap<QString, QString>(), \
    const QMap<QString, QByteArray> &headers = QMap<QString, QByteArray>(), \
    bool allowRedirects = true, \
    bool verify = false
#define COMMON_PARAMETERS_FORWARD query, headers, allowRedirects, verify

class Socks5Proxy;
class HttpProxy;
class HttpSessionPrivate;
class HttpSession
{
public:
    HttpSession();
    virtual ~HttpSession();
public:
    HttpResponse get(const QUrl &url, COMMON_PARAMETERS);
    HttpResponse head(const QUrl &url, COMMON_PARAMETERS);
    HttpResponse options(const QUrl &url, COMMON_PARAMETERS);
    HttpResponse delete_(const QUrl &url, COMMON_PARAMETERS);
    HttpResponse post(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    HttpResponse put(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    HttpResponse patch(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    HttpResponse post(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);
    HttpResponse put(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);
    HttpResponse patch(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);

    HttpResponse post(const QUrl &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return post(url, QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}
    HttpResponse put(const QUrl &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return put(url, QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}
    HttpResponse patch(const QUrl &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return patch(url, QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}

    HttpResponse get(const QString &url, COMMON_PARAMETERS) { return get(QUrl(url), COMMON_PARAMETERS_FORWARD); }
    HttpResponse head(const QString &url, COMMON_PARAMETERS) { return head(QUrl(url), COMMON_PARAMETERS_FORWARD); }
    HttpResponse options(const QString &url, COMMON_PARAMETERS) { return options(QUrl(url), COMMON_PARAMETERS_FORWARD); }
    HttpResponse delete_(const QString &url, COMMON_PARAMETERS) { return delete_(QUrl(url), COMMON_PARAMETERS_FORWARD); }
    HttpResponse post(const QString &url, const QByteArray &body, COMMON_PARAMETERS) { return post(QUrl(url), body, COMMON_PARAMETERS_FORWARD); }
    HttpResponse put(const QString &url, const QByteArray &body, COMMON_PARAMETERS) { return put(QUrl(url),  body, COMMON_PARAMETERS_FORWARD); }
    HttpResponse patch(const QString &url, const QByteArray &body, COMMON_PARAMETERS) { return patch(QUrl(url),  body, COMMON_PARAMETERS_FORWARD); }
    HttpResponse post(const QString &url, const QJsonDocument &json, COMMON_PARAMETERS) { return post(QUrl(url),  json, COMMON_PARAMETERS_FORWARD); }
    HttpResponse put(const QString &url, const QJsonDocument &json, COMMON_PARAMETERS) { return put(QUrl(url),  json, COMMON_PARAMETERS_FORWARD); }
    HttpResponse patch(const QString &url, const QJsonDocument &json, COMMON_PARAMETERS) { return patch(QUrl(url),  json, COMMON_PARAMETERS_FORWARD); }

    HttpResponse post(const QString &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return post(QUrl(url), QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}
    HttpResponse put(const QString &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return put(QUrl(url), QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}
    HttpResponse patch(const QString &url, const QJsonObject &json, COMMON_PARAMETERS)
        {return patch(QUrl(url), QJsonDocument(json), COMMON_PARAMETERS_FORWARD);}


    HttpResponse send(HttpRequest &request);
    QNetworkCookieJar &cookieJar();
    QNetworkCookie cookie(const QUrl &url, const QString &name);

    void setMaxConnectionsPerServer(int maxConnectionsPerServer);
    int maxConnectionsPerServer();

    void setDebugLevel(int level);
    void disableDebug();

    QString defaultUserAgent() const;
    void setDefaultUserAgent(const QString &userAgent);
    HttpVersion defaultVersion() const;
    void setDefaultVersion(HttpVersion defaultVersion);

    QSharedPointer<Socks5Proxy> socks5Proxy() const;
    void setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy);
    QSharedPointer<HttpProxy> httpProxy() const;
    void setHttpProxy(QSharedPointer<HttpProxy> proxy);
private:
    HttpSessionPrivate *d_ptr;
    Q_DECLARE_PRIVATE(HttpSession)
};


class HTTPError: public RequestError {
public:
    HTTPError(int statusCode): statusCode(statusCode) {}
    virtual QString what() const;
public:
    int statusCode;
};


class ConnectionError: public RequestError
{
public:
    virtual QString what() const;
};


class ProxyError: public ConnectionError
{
public:
    virtual QString what() const;
};


class SSLError: public ConnectionError
{
public:
    virtual QString what() const;
};


class RequestTimeout: public RequestError
{
public:
    virtual QString what() const;
};


class ConnectTimeout: public ConnectionError, RequestTimeout
{
public:
    virtual QString what() const;
};


class ReadTimeout: public RequestTimeout
{
public:
    virtual QString what() const;
};


class URLRequired: public RequestError
{
public:
    virtual QString what() const;
};


class TooManyRedirects: public RequestError
{
public:
    virtual QString what() const;
};


class MissingSchema: public RequestError
{
public:
    virtual QString what() const;
};


class InvalidScheme: public RequestError
{
public:
    virtual QString what() const;
};


class UnsupportedVersion: public RequestError
{
public:
    virtual QString what() const;
};

class InvalidURL: public RequestError
{
public:
    virtual QString what() const;
};


class InvalidHeader: public RequestError
{
public:
    virtual QString what() const;
};


class ChunkedEncodingError: public RequestError
{
public:
    virtual QString what() const;
};


class ContentDecodingError: public RequestError
{
public:
    virtual QString what() const;
};


class StreamConsumedError: public RequestError
{
public:
    virtual QString what() const;
};


class RetryError: public RequestError
{
public:
    virtual QString what() const;
};


class UnrewindableBodyError: public RequestError
{
public:
    virtual QString what() const;
};


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_HTTP_H
