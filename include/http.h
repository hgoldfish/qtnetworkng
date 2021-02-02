#ifndef QTNG_HTTP_H
#define QTNG_HTTP_H

#include <QtCore/qstring.h>
#include <QtCore/qmap.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qjsonarray.h>
#include <QtCore/qjsonobject.h>
#include <QtCore/qmimedatabase.h>
#include <QtCore/qdir.h>
#include <QtNetwork/qnetworkcookie.h>
#include <QtNetwork/qnetworkcookiejar.h>

#include "coroutine.h"
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


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
        files.append(File(name, filename, data, newContentType));
    }

    void addQuery(const QString &key, const QString &value)
    {
        queries.append(Query(key, value));
    }
public:
    struct Query
    {
        Query(const QString &name, const QString &value)
            : name(name), value(value) {}
        QString name;
        QString value;
    };
    struct File
    {
        File(const QString &name, const QString &filename, const QByteArray &data, const QString &contentType)
            : name(name), filename(filename), data(data), contentType(contentType) {}
        QString name;
        QString filename;
        QByteArray data;
        QString contentType;
    };

    QList<Query> queries;
    QList<File> files;
    QByteArray boundary;
};


class HttpRequestPrivate;
class HttpRequest: public HttpHeaderManager
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
    QUrlQuery query() const;
    void setQuery(const QMap<QString, QString> &query);
    void setQuery(const QUrlQuery &query);
    QList<QNetworkCookie> cookies() const;
    void setCookies(const QList<QNetworkCookie> &cookies);
    QSharedPointer<FileLike> body() const;
    void setBody(const QByteArray &body);
    void setBody(QSharedPointer<FileLike> body);
    QString userAgent() const;
    void setUserAgent(const QString &userAgent);
    int maxBodySize() const;
    void setMaxBodySize(int maxBodySize);
    int maxRedirects() const;
    void setMaxRedirects(int maxRedirects);
    inline void disableRedirects() { setMaxRedirects(0); }
    Priority priority() const;
    void setPriority(Priority priority);
    HttpVersion version() const;
    void setVersion(HttpVersion version);
    void setStreamResponse(bool streamResponse);
    bool streamResponse() const;
    float connectionTimeout() const;
    void setConnectionTimeout(float connectionTimeout);
    float timeout() const;
    void setTimeout(float timeout);
    QSharedPointer<SocketLike> connection() const;
    void useConnection(QSharedPointer<SocketLike> connection);
public:
    void setBody(const FormData &formData);
    void setBody(const QJsonDocument &json);
    void setBody(const QJsonObject &json);
    void setBody(const QJsonArray &json);
    void setBody(const QMap<QString, QString> form);
    void setBody(const QUrlQuery &form);
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
class HttpResponse: public HttpHeaderManager
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
    QByteArray body() const;
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


class Socks5Proxy;
class HttpProxy;
class HttpSessionPrivate;
class HttpCacheManager;
class HttpSession
{
public:
    HttpSession();
    virtual ~HttpSession();
public:
    HttpResponse get(const QUrl &url);
    HttpResponse get(const QUrl &url, const QMap<QString, QString> &query);
    HttpResponse get(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse get(const QUrl &url, const QUrlQuery &query);
    HttpResponse get(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
    HttpResponse get(const QString &url);
    HttpResponse get(const QString &url, const QMap<QString, QString> &query);
    HttpResponse get(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse get(const QString &url, const QUrlQuery &query);
    HttpResponse get(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);

    HttpResponse head(const QUrl &url);
    HttpResponse head(const QUrl &url, const QMap<QString, QString> &query);
    HttpResponse head(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse head(const QUrl &url, const QUrlQuery &query);
    HttpResponse head(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
    HttpResponse head(const QString &url);
    HttpResponse head(const QString &url, const QMap<QString, QString> &query);
    HttpResponse head(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse head(const QString &url, const QUrlQuery &query);
    HttpResponse head(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);


    HttpResponse options(const QUrl &url);
    HttpResponse options(const QUrl &url, const QMap<QString, QString> &query);
    HttpResponse options(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse options(const QUrl &url, const QUrlQuery &query);
    HttpResponse options(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
    HttpResponse options(const QString &url);
    HttpResponse options(const QString &url, const QMap<QString, QString> &query);
    HttpResponse options(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse options(const QString &url, const QUrlQuery &query);
    HttpResponse options(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);

    HttpResponse delete_(const QUrl &url);
    HttpResponse delete_(const QUrl &url, const QMap<QString, QString> &query);
    HttpResponse delete_(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse delete_(const QUrl &url, const QUrlQuery &query);
    HttpResponse delete_(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
    HttpResponse delete_(const QString &url);
    HttpResponse delete_(const QString &url, const QMap<QString, QString> &query);
    HttpResponse delete_(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
    HttpResponse delete_(const QString &url, const QUrlQuery &query);
    HttpResponse delete_(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);

    HttpResponse post(const QUrl &url, const QByteArray &body);
    HttpResponse post(const QUrl &url, const QJsonDocument &body);
    HttpResponse post(const QUrl &url, const QJsonObject &body);
    HttpResponse post(const QUrl &url, const QJsonArray &body);
    HttpResponse post(const QUrl &url, const QMap<QString, QString> &body);
    HttpResponse post(const QUrl &url, const QUrlQuery &body);
    HttpResponse post(const QUrl &url, const FormData &body);
    HttpResponse post(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QByteArray &body);
    HttpResponse post(const QString &url, const QJsonDocument &body);
    HttpResponse post(const QString &url, const QJsonObject &body);
    HttpResponse post(const QString &url, const QJsonArray &body);
    HttpResponse post(const QString &url, const QMap<QString, QString> &body);
    HttpResponse post(const QString &url, const QUrlQuery &body);
    HttpResponse post(const QString &url, const FormData &body);
    HttpResponse post(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse post(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);

    HttpResponse patch(const QUrl &url, const QByteArray &body);
    HttpResponse patch(const QUrl &url, const QJsonDocument &body);
    HttpResponse patch(const QUrl &url, const QJsonObject &body);
    HttpResponse patch(const QUrl &url, const QJsonArray &body);
    HttpResponse patch(const QUrl &url, const QMap<QString, QString> &body);
    HttpResponse patch(const QUrl &url, const QUrlQuery &body);
    HttpResponse patch(const QUrl &url, const FormData &body);
    HttpResponse patch(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QByteArray &body);
    HttpResponse patch(const QString &url, const QJsonDocument &body);
    HttpResponse patch(const QString &url, const QJsonObject &body);
    HttpResponse patch(const QString &url, const QJsonArray &body);
    HttpResponse patch(const QString &url, const QMap<QString, QString> &body);
    HttpResponse patch(const QString &url, const QUrlQuery &body);
    HttpResponse patch(const QString &url, const FormData &body);
    HttpResponse patch(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse patch(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);

    HttpResponse put(const QUrl &url, const QByteArray &body);
    HttpResponse put(const QUrl &url, const QJsonDocument &body);
    HttpResponse put(const QUrl &url, const QJsonObject &body);
    HttpResponse put(const QUrl &url, const QJsonArray &body);
    HttpResponse put(const QUrl &url, const QMap<QString, QString> &body);
    HttpResponse put(const QUrl &url, const QUrlQuery &body);
    HttpResponse put(const QUrl &url, const FormData &body);
    HttpResponse put(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QByteArray &body);
    HttpResponse put(const QString &url, const QJsonDocument &body);
    HttpResponse put(const QString &url, const QJsonObject &body);
    HttpResponse put(const QString &url, const QJsonArray &body);
    HttpResponse put(const QString &url, const QMap<QString, QString> &body);
    HttpResponse put(const QString &url, const QUrlQuery &body);
    HttpResponse put(const QString &url, const FormData &body);
    HttpResponse put(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
    HttpResponse put(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);

    HttpResponse send(HttpRequest &request);
    QNetworkCookieJar &cookieJar();
    QNetworkCookie cookie(const QUrl &url, const QString &name);
    void setManagingCookies(bool managingCookies);

    void setMaxConnectionsPerServer(int maxConnectionsPerServer);
    int maxConnectionsPerServer();

    void setDebugLevel(int level);
    void disableDebug();

    void setKeepalive(bool keepAlive);
    bool keepAlive() const;

    QString defaultUserAgent() const;
    void setDefaultUserAgent(const QString &userAgent);
    HttpVersion defaultVersion() const;
    void setDefaultVersion(HttpVersion defaultVersion);
    float defaultConnnectionTimeout() const;
    void setDefaultConnectionTimeout(float timeout);
    float defaultTimeout() const;
    void setDefaultTimeout(float defaultTimeout);
    void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache);
    QSharedPointer<SocketDnsCache> dnsCache() const;

    QSharedPointer<Socks5Proxy> socks5Proxy() const;
    void setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy);
    QSharedPointer<HttpProxy> httpProxy() const;
    void setHttpProxy(QSharedPointer<HttpProxy> proxy);
    QSharedPointer<HttpCacheManager> cacheManager() const;
    void setCacheManager(QSharedPointer<HttpCacheManager> cacheManager);
private:
    HttpSessionPrivate *d_ptr;
    Q_DECLARE_PRIVATE(HttpSession)
};


class HttpCacheManager
{
public:
    HttpCacheManager();
    virtual ~HttpCacheManager();
public:
    virtual bool addResponse(const HttpResponse &response);
    virtual bool getResponse(HttpResponse *response);
protected:
    virtual bool store(const QString &url, const QByteArray &data);
    virtual QByteArray load(const QString &url);
};


class HttpMemoryCacheManagerPrivate;
class HttpMemoryCacheManager: public HttpCacheManager
{
public:
    HttpMemoryCacheManager();
    virtual ~HttpMemoryCacheManager() override;
public:
    float expireTime() const;
    void setExpireTime(float expireTime);
protected:
    QMap<QString, QByteArray> &cache();
    virtual bool store(const QString &url, const QByteArray &data) override;
    virtual QByteArray load(const QString &url) override;
private:
    HttpMemoryCacheManagerPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(HttpMemoryCacheManager)
};


class HttpDiskCacheManager: public HttpCacheManager
{
public:
    HttpDiskCacheManager(const QDir &cacheDir)
        :cacheDir(cacheDir) {}
    HttpDiskCacheManager(const QString &cacheDir)
        :cacheDir(cacheDir) {}
protected:
    virtual bool store(const QString &url, const QByteArray &data);
    virtual QByteArray load(const QString &url);
protected:
    QDir cacheDir;
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
