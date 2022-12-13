#ifndef QTNG_HTTP_COOKIE_H
#define QTNG_HTTP_COOKIE_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qurl.h>
#include <QtCore/qmetatype.h>
#include <QtCore/qlist.h>
#include <QtCore/qshareddata.h>
#ifdef QT_NETWORK_LIB
#  include <QtNetwork/qnetworkcookie.h>
#endif
#include "config.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpCookiePrivate;
class HttpCookie
{
public:
    enum RawForm { NameAndValueOnly, Full };
    enum SameSite { Default, None, Lax, Strict };
public:
    explicit HttpCookie(const QByteArray &name = QByteArray(), const QByteArray &value = QByteArray());
    HttpCookie(const HttpCookie &other);
    ~HttpCookie();
#ifdef Q_COMPILER_RVALUE_REFS
    HttpCookie &operator=(HttpCookie &&other) noexcept
    {
        swap(other);
        return *this;
    }
#endif
    HttpCookie &operator=(const HttpCookie &other);
    void swap(HttpCookie &other) noexcept { qSwap(d, other.d); }
    bool operator==(const HttpCookie &other) const;
    inline bool operator!=(const HttpCookie &other) const { return !(*this == other); }
#ifdef QT_NETWORK_LIB
    HttpCookie(const QNetworkCookie &cookie)
        : HttpCookie(cookie.name(), cookie.value())
    {
        setExpirationDate(cookie.expirationDate());
        setDomain(cookie.domain());
        setPath(cookie.path());
        setSecure(cookie.isSecure());
#  if QT_VERSION >= QT_VERSION_CHECK(6, 1, 0)
        setSameSitePolicy(cookie.sameSitePolicy());
#  endif
    }
    operator QNetworkCookie() const
    {
        QNetworkCookie cookie(name(), value());
        cookie.setExpirationDate(expirationDate());
        cookie.setDomain(domain());
        cookie.setPath(path());
        cookie.setSecure(isSecure());
#  if QT_VERSION >= QT_VERSION_CHECK(6, 1, 0)
        cookie.setSameSitePolicy(sameSitePolicy());
#  endif
        return cookie;
    }
#endif
public:
    bool isSecure() const;
    void setSecure(bool enable);
    bool isHttpOnly() const;
    void setHttpOnly(bool enable);
    SameSite sameSitePolicy() const;
    void setSameSitePolicy(SameSite sameSite);
    bool isSessionCookie() const;
    QDateTime expirationDate() const;
    void setExpirationDate(const QDateTime &date);
    QString domain() const;
    void setDomain(const QString &domain);
    QString path() const;
    void setPath(const QString &path);
    QByteArray name() const;
    void setName(const QByteArray &cookieName);
    QByteArray value() const;
    void setValue(const QByteArray &value);
public:
    QByteArray toRawForm(RawForm form = Full) const;
    bool hasSameIdentifier(const HttpCookie &other) const;
    void normalize(const QUrl &url);
public:
    static QList<HttpCookie> parseCookies(const QByteArray &cookieString);
private:
    QSharedDataPointer<HttpCookiePrivate> d;
    friend class HttpCookiePrivate;
};

class HttpCookieJarPrivate;
class HttpCookieJar
{
public:
    HttpCookieJar();
    virtual ~HttpCookieJar();

    virtual QList<HttpCookie> cookiesForUrl(const QUrl &url) const;
    virtual bool setCookiesFromUrl(const QList<HttpCookie> &cookieList, const QUrl &url);

    virtual bool insertCookie(const HttpCookie &cookie);
    virtual bool updateCookie(const HttpCookie &cookie);
    virtual bool deleteCookie(const HttpCookie &cookie);
protected:
    QList<HttpCookie> allCookies() const;
    void setAllCookies(const QList<HttpCookie> &cookieList);
    virtual bool validateCookie(const HttpCookie &cookie, const QUrl &url) const;
private:
    Q_DECLARE_PRIVATE(HttpCookieJar)
    Q_DISABLE_COPY(HttpCookieJar)
    HttpCookieJarPrivate * const d_ptr;
};

QTNETWORKNG_NAMESPACE_END

QT_BEGIN_NAMESPACE
#ifndef QT_NO_DEBUG_STREAM
class QDebug;
QDebug operator<<(QDebug, const QTNETWORKNG_NAMESPACE::HttpCookie &);
#endif
QT_END_NAMESPACE

// Q_DECLARE_SHARED(QTNETWORKNG_NAMESPACE::HttpCookie);
Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::HttpCookie)

#endif  // QTNG_HTTP_COOKIE_H
