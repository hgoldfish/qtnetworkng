#ifndef HTTP_NG_H
#define HTTP_NG_H

#include <QString>
#include <QMap>
#include <QNetworkCookie>
#include <QNetworkCookieJar>
#include <QJsonDocument>


class HeaderOperationMixin
{
public:
    void setContentType(const QString &contentType);
    QString getContentType();
    void setContentLength(qint64 contentLength);
    qint64 getContentLength();
    void setHeader(const QString &name, const QString &value);
    QString getHeader(const QString &name);
public:
    QMap<QString, QString> headers;
};

class Request: public HeaderOperationMixin
{
public:
    Request();
    virtual ~Request();
public:
    QString method;
    QString url;
    QMap<QString, QString> query;
    QList<QNetworkCookie> cookies;
    QByteArray body;
    int maxBodySize;
};

class Response: public HeaderOperationMixin
{
public:
    QString text();
    QJsonDocument json();
    QString html();
public:
    int statusCode;
    QString statusText;
    QList<QNetworkCookie> cookies;
    Request request;
    QByteArray body;
    qint64 elapsed;
    bool isOk() { return statusCode == 200; }
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


#define COMMON_PARAMETERS \
    const QMap<QString, QString> &query = QMap<QString, QString>(), \
    const QMap<QString, QString> &headers = QMap<QString, QString>(), \
    bool allowRedirects = true, \
    bool verify = false \

#define COMMON_PARAMETERS_WITHOUT_DEFAULT \
    const QMap<QString, QString> &query,\
    const QMap<QString, QString> &headers, \
    bool allowRedirects, \
    bool verify \


class SessionPrivate;
class Session
{
public:
    Session();
    virtual ~Session();
public:
    Response get(const QString &url, COMMON_PARAMETERS);
    Response head(const QString &url, COMMON_PARAMETERS);
    Response options(const QString &url, COMMON_PARAMETERS);
    Response delete_(const QString &url, COMMON_PARAMETERS);
    Response post(const QString &url, const QByteArray &body, COMMON_PARAMETERS);
    Response put(const QString &url, const QByteArray &body, COMMON_PARAMETERS);
    Response patch(const QString &url, const QByteArray &body, COMMON_PARAMETERS);

    Response send(Request &request);
private:
    SessionPrivate *d_ptr;
    Q_DECLARE_PRIVATE(Session)
};

#endif // HTTP_NG_H
