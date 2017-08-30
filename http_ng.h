#ifndef HTTP_NG_H
#define HTTP_NG_H

#include <QString>
#include <QMap>
#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QJsonDocument>
#include <QMimeDatabase>

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
    qint64 getContentLength() const;
    void setLocation(const QUrl &url);
    QUrl getLocation() const;
    void setLastModified(const QDateTime &lastModified);
    QDateTime getLastModified() const;
    void setModifiedSince(const QDateTime &modifiedSince);
    QDateTime getModifedSince() const;

    void setHeader(const QString &name, const QByteArray &value);
    void addHeader(const QString &name, const QByteArray &value);
    QByteArray getHeader(const QString &name) const;
    QByteArrayList getMultiHeader(const QString &name) const;

    static QDateTime fromHttpDate(const QByteArray &value);
    static QByteArray toHttpDate(const QDateTime &dt);

public:
    QMap<QString, QByteArray> headers;
};

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
            QMimeDatabase db;
            newContentType = db.mimeTypeForFileNameAndData(filename, data).name();
        } else {
            newContentType = contentType;
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

class Request: public HeaderOperationMixin
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

    Request();
    virtual ~Request();
public:
    QString method;
    QUrl url;
    QMap<QString, QString> query;
    QList<QNetworkCookie> cookies;
    QByteArray body;
    int maxBodySize;
    int maxRedirects;
    Priority priority = NormalPriority;
public:
    void setFormData(FormData &formData, const QString &method = QString::fromUtf8("post"));
    static Request fromFormData(const FormData &formData);
    static Request fromForm(const QUrlQuery &data);
    static Request fromForm(const QMap<QString, QString> &query);
    static Request fromJson(const QJsonDocument &json);
    static Request fromJson(const QJsonArray &json) { return fromJson(QJsonDocument(json)); }
    static Request fromJson(const QJsonObject &json) { return fromJson(QJsonDocument(json)); }
};


class Response: public HeaderOperationMixin
{
public:
    QString text();
    QJsonDocument json();
    QString html();
public:
    QUrl url;
    int statusCode;
    QString statusText;
    QList<QNetworkCookie> cookies;
    Request request;
    QByteArray body;
    qint64 elapsed;
    QList<Response> history;
    bool isOk() { return statusCode == 200; }
};


#define COMMON_PARAMETERS \
    const QMap<QString, QString> &query = QMap<QString, QString>(), \
    const QMap<QString, QByteArray> &headers = QMap<QString, QByteArray>(), \
    bool allowRedirects = true, \
    bool verify = false \

class SessionPrivate;
class Session
{
public:
    Session();
    virtual ~Session();
public:
    Response get(const QUrl &url, COMMON_PARAMETERS);
    Response head(const QUrl &url, COMMON_PARAMETERS);
    Response options(const QUrl &url, COMMON_PARAMETERS);
    Response delete_(const QUrl &url, COMMON_PARAMETERS);
    Response post(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    Response put(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    Response patch(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS);
    Response post(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);
    Response put(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);
    Response patch(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS);

    Response send(Request &request);
    QNetworkCookieJar &getCookieJar();
    QNetworkCookie getCookie(const QUrl &url, const QString &name);

    void setMaxConnectionsPerServer(int maxConnectionsPerServer);
    int getMaxConnectionsPerServer();

private:
    SessionPrivate *d_ptr;
    Q_DECLARE_PRIVATE(Session)
};


class RequestException
{
public:
    virtual ~RequestException();
    virtual QString what() const throw ();
};


class HTTPError: public RequestException {
public:
    virtual QString what() const throw ();
};


class ConnectionError: public RequestException
{
public:
    virtual QString what() const throw ();
};


class ProxyError: public ConnectionError
{
public:
    virtual QString what() const throw ();
};


class SSLError: public ConnectionError
{
public:
    virtual QString what() const throw ();
};


class RequestTimeout: public RequestException
{
public:
    virtual QString what() const throw ();
};


class ConnectTimeout: public ConnectionError, RequestTimeout
{
public:
    virtual QString what() const throw ();
};


class ReadTimeout: public RequestTimeout
{
public:
    virtual QString what() const throw ();
};


class URLRequired: public RequestException
{
public:
    virtual QString what() const throw ();
};


class TooManyRedirects: public RequestException
{
public:
    virtual QString what() const throw ();
};


class MissingSchema: public RequestException
{
public:
    virtual QString what() const throw ();
};


class InvalidSchema: public RequestException
{
public:
    virtual QString what() const throw ();
};


class InvalidURL: public RequestException
{
public:
    virtual QString what() const throw ();
};


class InvalidHeader: public RequestException
{
public:
    virtual QString what() const throw ();
};


class ChunkedEncodingError: public RequestException
{
public:
    virtual QString what() const throw ();
};


class ContentDecodingError: public RequestException
{
public:
    virtual QString what() const throw ();
};


class StreamConsumedError: public RequestException
{
public:
    virtual QString what() const throw ();
};


class RetryError: public RequestException
{
public:
    virtual QString what() const throw ();
};


class UnrewindableBodyError: public RequestException
{
public:
    virtual QString what() const throw ();
};

#endif // HTTP_NG_H
