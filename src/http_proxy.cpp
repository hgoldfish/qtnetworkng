#include "../include/http_proxy.h"

QTNETWORKNG_NAMESPACE_BEGIN

class HttpProxyPrivate
{
public:
    HttpProxyPrivate() { }
    HttpProxyPrivate(const QString &hostName, quint16 port, const QString &user, const QString &password)
        : hostName(hostName)
        , user(user)
        , password(password)
        , port(port)
    {
    }
public:
    QString hostName;
    QString user;
    QString password;
    quint16 port;
};

HttpProxy::HttpProxy()
    : d_ptr(new HttpProxyPrivate)
{
}

HttpProxy::HttpProxy(const QString &hostName, quint16 port, const QString &user, const QString &password)
    : d_ptr(new HttpProxyPrivate(hostName, port, user, password))
{
}

HttpProxy::HttpProxy(const HttpProxy &other)
    : d_ptr(new HttpProxyPrivate(other.d_ptr->hostName, other.d_ptr->port, other.d_ptr->user, other.d_ptr->password))
{
}

HttpProxy::~HttpProxy()
{
    delete d_ptr;
}

HttpProxy &HttpProxy::operator=(const HttpProxy &other)
{
    Q_D(HttpProxy);
    d->user = other.d_ptr->user;
    d->hostName = other.d_ptr->hostName;
    d->password = other.d_ptr->password;
    d->port = other.d_ptr->port;
    return *this;
}

HttpProxy &HttpProxy::operator=(HttpProxy &&other)
{
    delete d_ptr;
    d_ptr = new HttpProxyPrivate(other.hostName(), other.port(), other.user(), other.password());
    return *this;
}

bool HttpProxy::operator==(const HttpProxy &other) const
{
    Q_D(const HttpProxy);
    return d->user == other.d_ptr->user && d->hostName == other.d_ptr->hostName && d->password == other.d_ptr->password
            && d->port == other.d_ptr->port;
}

#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
#  define QBYTEARRAYLIST QByteArrayList
inline static QByteArray join(const QByteArrayList &lines)
{
    return lines.join();
}
#else
#  define QBYTEARRAYLIST QList<QByteArray>
inline static QByteArray join(const QList<QByteArray> &lines)
{
    QByteArray buf;
    buf.reserve(1024 * 4 - 1);
    for (const QByteArray &line : lines) {
        buf.append(line);
    }
    return buf;
}
#endif

QSharedPointer<SocketLike> HttpProxy::connect(const QString &remoteHost, quint16 port)
{
    Q_D(HttpProxy);
    if (remoteHost.isEmpty()) {
        return QSharedPointer<SocketLike>();
    }
    QSharedPointer<Socket> connection(Socket::createConnection(d->hostName, d->port));
    if (connection.isNull()) {
        return QSharedPointer<SocketLike>();
    }

    QBYTEARRAYLIST lines;
    const QByteArray &firstLine = QByteArray("CONNECT ") + remoteHost.toLatin1() + QByteArray(":")
            + QByteArray::number(port) + QByteArray(" HTTP/1.1\r\n");
    const QByteArray &secondLine = QByteArray("Host: ") + remoteHost.toLatin1() + QByteArray("\r\n");
    lines.append(firstLine);
    lines.append(secondLine);
    lines.append("Proxy-Connection: keep-alive\r\n");
    lines.append("User-Agent: Mozilla/5.0\r\n");
    lines.append("\r\n");
    const QByteArray &headersBytes = join(lines);
    if (connection->sendall(headersBytes) != headersBytes.size()) {
        return QSharedPointer<SocketLike>();
    }

    HeaderSplitter headerSplitter(asSocketLike(connection), 3);
    HeaderSplitter::Error headerSplitterError;
    QByteArray statusLine = headerSplitter.nextLine(&headerSplitterError);
    if (statusLine.isEmpty() || headerSplitterError != HeaderSplitter::NoError) {
        return QSharedPointer<SocketLike>();
    }
    QStringList commands = QString::fromLatin1(statusLine).split(QRegExp(QString::fromLatin1("\\s+")));
    if (commands.size() < 3) {
        return QSharedPointer<SocketLike>();
    }
    if (commands.at(0) != QLatin1String("HTTP/1.0") && commands.at(0) != QLatin1String("HTTP/1.1")) {
        return QSharedPointer<SocketLike>();
    }
    if (commands.at(1).toInt() != 200) {
        return QSharedPointer<SocketLike>();
    }
    const int MaxHeaders = 64;
    headerSplitter.headers(MaxHeaders, &headerSplitterError);
    if (headerSplitterError != HeaderSplitter::NoError) {
        return QSharedPointer<SocketLike>();
    }
    return asSocketLike(connection);
}

QSharedPointer<SocketLike> HttpProxy::connect(const HostAddress &remoteHost, quint16 port)
{
    if (remoteHost.isNull()) {
        return QSharedPointer<SocketLike>();
    }
    QString hostName;
    if (remoteHost.protocol() == HostAddress::IPv6Protocol) {
        hostName = QString::fromLatin1("[%1]").arg(remoteHost.toString());
    } else {
        hostName = remoteHost.toString();
    }
    return connect(hostName, port);
}

QString HttpProxy::hostName() const
{
    Q_D(const HttpProxy);
    return d->hostName;
}

quint16 HttpProxy::port() const
{
    Q_D(const HttpProxy);
    return d->port;
}

QString HttpProxy::user() const
{
    Q_D(const HttpProxy);
    return d->user;
}

QString HttpProxy::password() const
{
    Q_D(const HttpProxy);
    return d->password;
}

void HttpProxy::setHostName(const QString &hostName)
{
    Q_D(HttpProxy);
    d->hostName = hostName;
}

void HttpProxy::setPort(quint16 port)
{
    Q_D(HttpProxy);
    d->port = port;
}

void HttpProxy::setUser(const QString &user)
{
    Q_D(HttpProxy);
    d->user = user;
}

void HttpProxy::setPassword(const QString &password)
{
    Q_D(HttpProxy);
    d->password = password;
}

BaseProxySwitcher::BaseProxySwitcher() { }
BaseProxySwitcher::~BaseProxySwitcher() { }

QSharedPointer<SocketProxy> SimpleProxySwitcher::selectSocketProxy(const QUrl &url)
{
    Q_UNUSED(url);
    if (!socketProxies.isEmpty()) {
        return socketProxies.first();
    } else if (!httpProxies.isEmpty()) {
        return httpProxies.first();
    }
    return QSharedPointer<SocketProxy>();
}

QSharedPointer<HttpProxy> SimpleProxySwitcher::selectHttpProxy(const QUrl &url)
{
    Q_UNUSED(url);
    if (httpProxies.size() > 0) {
        return httpProxies.at(0);
    }
    return QSharedPointer<HttpProxy>();
}

// implemented in http.cpp
void setProxySwitcher(class HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher);

QTNETWORKNG_NAMESPACE_END
