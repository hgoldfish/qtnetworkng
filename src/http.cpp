#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonParseError>
#include <QtCore/QDateTime>
#include <QtCore/QTextCodec>
#include "../include/http_p.h"
#include "../include/socks5_proxy.h"
#ifdef QTNETWOKRNG_USE_SSL
#include "../include/ssl.h"
#endif

QTNETWORKNG_NAMESPACE_BEGIN


FormData::FormData()
{
    const QByteArray possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    const int randomPartLength = 16;

    QByteArray randomPart;
    for(int i=0; i<randomPartLength; ++i) {
       int index = qrand() % possibleCharacters.length();
       char nextChar = possibleCharacters.at(index);
       randomPart.append(nextChar);
    }

    boundary = QByteArray("----WebKitFormBoundary") + randomPart;
}

QByteArray formatHeaderParam(const QString &name, const QString &value)
{
    QTextCodec *asciiCodec = QTextCodec::codecForName("latin1");
    if(!asciiCodec) {
        asciiCodec = QTextCodec::codecForName("ascii");
    }
    QByteArray data;
    if(asciiCodec && asciiCodec->canEncode(value)) {
        data.append(name.toUtf8());
        data.append("=\"");
        data.append(value.toUtf8());
        data.append("\"");
        return data;
    } else {
        data.append(name.toUtf8());
        data.append("*=UTF8''");
        data.append(QUrl::toPercentEncoding(value));
    }
    return data;
}

QByteArray FormData::toByteArray() const
{
    QByteArray body;
    for(QMap<QString, QString>::const_iterator itor = query.constBegin(); itor != query.constEnd(); ++itor) {
        body.append("--");
        body.append(boundary);
        body.append("\r\n");
        body.append("Content-Disposition: form-data;");
        body.append(formatHeaderParam(QStringLiteral("name"), itor.key()));
        body.append("\r\n\r\n");
        body.append(itor.value().toUtf8());
        body.append("\r\n");
    }
    for(QMap<QString, FormDataFile>::const_iterator itor = files.constBegin(); itor != files.constEnd(); ++itor) {
        body.append("--");
        body.append(boundary);
        body.append("\r\n");
        body.append("Content-Disposition: form-data;");
        body.append(formatHeaderParam(QStringLiteral("name"), itor.key()));
        body.append("; ");
        body.append(formatHeaderParam(QStringLiteral("filename"), itor.value().filename));
        body.append("\r\n");
        body.append("Content-Type: ");
        body.append(itor.value().contentType);
        body.append("\r\n\r\n");
        body.append(itor.value().data);
    }
    body.append("--");
    body.append(boundary);
    body.append("--");
    return body;
}

HttpRequest::HttpRequest()
    :method("GET"), maxBodySize(1024 * 1024 * 8), maxRedirects(8), priority(NormalPriority), version(Unknown)
{
}

HttpRequest::~HttpRequest()
{
}

void HttpRequest::setFormData(FormData &formData, const QString &method)
{
    this->method = method;
    QString contentType = QString::fromLatin1("multipart/form-data; boundary=%1").arg(QString::fromLatin1(formData.boundary));
    setHeader(QStringLiteral("Content-Type"), contentType.toLatin1());
    QString mimeHeader("MIME-Version");
    if(!hasHeader(mimeHeader)) {
        setHeader(mimeHeader, QByteArray("1.0"));
    }
    body = formData.toByteArray();
}

HttpRequest HttpRequest::fromFormData(const FormData &formData)
{
    HttpRequest request;
    request.method = "POST";
    request.body = formData.toByteArray();
    QString contentType = QString::fromLatin1("multipart/form-data; boundary=%1").arg(QString::fromLatin1(formData.boundary));
    request.setContentType(contentType);
    return request;
}

HttpRequest HttpRequest::fromForm(const QUrlQuery &data)
{
    HttpRequest request;
    request.setContentType(QStringLiteral("application/x-www-form-urlencoded"));
    request.body = data.toString(QUrl::FullyEncoded).toUtf8();
    request.method = "POST";
    return request;
}

HttpRequest HttpRequest::fromForm(const QMap<QString, QString> &query)
{
    QUrlQuery data;
    for(QMap<QString, QString>::const_iterator itor = query.constBegin(); itor != query.constEnd(); ++itor) {
        data.addQueryItem(itor.key(), itor.value());
    }
    return fromForm(data);
}

HttpRequest HttpRequest::fromJson(const QJsonDocument &json)
{
    HttpRequest request;
    request.setContentType("application/json");
    request.body = json.toJson();
    request.method = "POST";
    return request;
}

QString HttpResponse::text()
{
    return QString::fromUtf8(body);
}

QJsonDocument HttpResponse::json()
{
    QJsonParseError error;
    QJsonDocument jsonDocument = QJsonDocument::fromJson(body, &error);
    if(error.error != QJsonParseError::NoError) {
        return QJsonDocument();
    } else {
        return jsonDocument;
    }
}

QString HttpResponse::html()
{
    // TODO detect encoding;
    return QString::fromUtf8(body);
}


HttpSessionPrivate::HttpSessionPrivate(HttpSession *q_ptr)
    :defaultVersion(HttpVersion::Http1_1), q_ptr(q_ptr), debugLevel(0)
{
    defaultUserAgent = QStringLiteral("Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0");
}

HttpSessionPrivate::~HttpSessionPrivate()
{

}

struct HeaderSplitter
{
    QSharedPointer<SocketLike> connection;
    QByteArray buf;

    HeaderSplitter(QSharedPointer<SocketLike> connection)
        :connection(connection) {}

    QByteArray nextLine()
    {
        const int MaxLineLength = 1024;
        QByteArray line;
        bool expectingLineBreak = false;

        for(int i = 0; i < MaxLineLength; ++i) {
            if(buf.isEmpty()) {
                buf = connection->recv(1024);
                if(buf.isEmpty()) {
                    return QByteArray();
                }
            }
            int j = 0;
            for(; j < buf.size() && j < MaxLineLength; ++j) {
                char c = buf.at(j);
                if(c == '\n') {
                    if(!expectingLineBreak) {
                        throw InvalidHeader();
                    }
                    buf.remove(0, j + 1);
                    return line;
                } else if(c == '\r') {
                    if(expectingLineBreak) {
                        throw InvalidHeader();
                    }
                    expectingLineBreak = true;
                } else {
                    line.append(c);
                }
            }
            buf.remove(0, j + 1);
        }
        qDebug() << "exhaused max lines.";
        throw InvalidHeader();
    }
};

QList<QByteArray> splitBytes(const QByteArray &bs, char sep, int maxSplit = -1)
{
    QList<QByteArray> tokens;
    QByteArray token;
    for(int i = 0; i < bs.size(); ++i) {
        char c = bs.at(i);
        if(c == sep && (maxSplit < 0 || tokens.size() < maxSplit)) {
            tokens.append(token);
            token.clear();
        } else {
            token.append(c);
        }
    }
    if(!token.isEmpty()) {
        tokens.append(token);
    }
    return tokens;
}

static QUrl hostOnly(const QUrl &url)
{
    QUrl h;
    h.setScheme(url.scheme());
    h.setHost(url.host());
    h.setPort(url.port());
    return h;
}

ConnectionPool::ConnectionPool()
    :maxConnectionsPerServer(10), timeToLive(60 * 5), operations(new CoroutineGroup), proxySwitcher(new SimpleProxySwitcher)
{
    operations->spawn([this] {removeUnusedConnections();});
}

ConnectionPool::~ConnectionPool()
{
    delete operations;
}

void ConnectionPool::recycle(const QUrl &url, QSharedPointer<SocketLike> connection)
{
    const QUrl &h = hostOnly(url);
    ConnectionPoolItem &item = items[h];
    item.lastUsed = QDateTime::currentDateTimeUtc();
    if(item.semaphore.isNull()) {
        item.semaphore.reset(new Semaphore(maxConnectionsPerServer));
    }
    if(item.connections.size() < maxConnectionsPerServer) {
        item.connections.insert(connection);
    }
}

QSharedPointer<SocketLike> ConnectionPool::connectionForUrl(const QUrl &url)
{
    const QUrl &h = hostOnly(url);
    ConnectionPoolItem &item = items[h];

    item.lastUsed = QDateTime::currentDateTimeUtc();
    if(item.semaphore.isNull()) {
        item.semaphore.reset(new Semaphore(maxConnectionsPerServer));
    }

    ScopedLock<Semaphore> lock(*item.semaphore);Q_UNUSED(lock);

    QSharedPointer<Socket> rawSocket;
    int defaultPort = 80;
    if(url.scheme() == QStringLiteral("http")) {
    } else{
#ifdef QTNETWOKRNG_USE_SSL
        defaultPort = 443;
#else
        qDebug() << "invalid scheme";
        throw ConnectionError();
#endif
    }

    QSharedPointer<SocketLike> connection;

    QSharedPointer<Socks5Proxy> socks5Proxy = proxySwitcher->selectSocks5Proxy(url);
    if(socks5Proxy) {
        rawSocket = socks5Proxy->connect(url.host(), url.port(defaultPort));
        if(url.scheme() == QStringLiteral("http")) {
            connection = SocketLike::rawSocket(rawSocket);
        } else{
    #ifdef QTNETWOKRNG_USE_SSL
            QSharedPointer<SslSocket> ssl(new SslSocket(rawSocket));
            ssl->handshake(false);
            connection = SocketLike::sslSocket(ssl);
    #else
            qDebug() << "invalid scheme";
            throw ConnectionError();
    #endif
        }
    } else {
        rawSocket.reset(new Socket);
        rawSocket->setDnsCache(dnsCache);

        if(url.scheme() == QStringLiteral("http")) {
            connection = SocketLike::rawSocket(rawSocket);
        } else{
    #ifdef QTNETWOKRNG_USE_SSL
            connection = SocketLike::sslSocket(QSharedPointer<SslSocket>::create(rawSocket));
    #else
            qDebug() << "invalid scheme";
            throw ConnectionError();
    #endif
        }
        if(!connection->connect(url.host(), url.port(defaultPort))) {
            qDebug() << "can not connect to host: " << url.host() << connection->errorString();
            throw ConnectionError();
        }
    }

    return connection;
}


void ConnectionPool::removeUnusedConnections()
{
    while(true) {
        const QDateTime &now = QDateTime::currentDateTimeUtc();
        Coroutine::sleep(1000);
        QMap<QUrl, ConnectionPoolItem> newItems;
        for(QMap<QUrl, ConnectionPoolItem>::const_iterator itor = items.constBegin(); itor != items.constEnd(); ++itor) {
            if(itor.value().lastUsed.secsTo(now) < timeToLive) {
                newItems.insert(itor.key(), itor.value());
            }
        }
        items = newItems;
    }
}


QSharedPointer<Socks5Proxy> ConnectionPool::socks5Proxy() const
{
    if(proxySwitcher->socks5Proxies.size() > 0) {
        return proxySwitcher->socks5Proxies.at(0);
    }
    return QSharedPointer<Socks5Proxy>();
}


QSharedPointer<HttpProxy> ConnectionPool::httpProxy() const
{
    if(proxySwitcher->httpProxies.size() > 0) {
        return proxySwitcher->httpProxies.at(0);
    }
    return QSharedPointer<HttpProxy>();
}


void ConnectionPool::setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy)
{
    proxySwitcher->socks5Proxies.clear();
    proxySwitcher->socks5Proxies.append(proxy);
}

void ConnectionPool::setHttpProxy(QSharedPointer<HttpProxy> proxy)
{
    proxySwitcher->httpProxies.clear();
    proxySwitcher->httpProxies.append(proxy);
}


struct ChunkedBlockReader
{
    QSharedPointer<SocketLike> connection;
    QByteArray buf;
    int debugLevel;

    ChunkedBlockReader(QSharedPointer<SocketLike> connection)
        :connection(connection), debugLevel(0) {}

    QByteArray nextBlock(qint64 leftBytes)
    {
        const int MaxLineLength = 6; // ffff\r\n
        QByteArray numBytes;
        bool expectingLineBreak = false;
        if(buf.size() < MaxLineLength) {
            buf.append(connection->recv(1024 * 8));
            if(buf.size() < 3) { // 0\r\n
                throw ChunkedEncodingError();
            }
        }

        bool ok = false;
        for(int i = 0; i < buf.size() && i < MaxLineLength; ++i) {
            char c = buf.at(i);
            if(c == '\n') {
                if(!expectingLineBreak) {
                    throw ChunkedEncodingError();
                }
                buf.remove(0, i + 1);
                ok = true;
                break;
            } else if(c == '\r') {
                if(expectingLineBreak) {
                    throw ChunkedEncodingError();
                }
                expectingLineBreak = true;
            } else {
                numBytes.append(c);
            }
        }
        if(!ok) {
            throw ChunkedEncodingError();
        }

        qint64 bytesToRead = numBytes.toUInt(&ok, 16);
        if(!ok) {
            if(debugLevel > 0) {
                qDebug() << "got invalid chunked bytes:" << numBytes;
            }
            throw ChunkedEncodingError();
        }

        if(bytesToRead > leftBytes) {
            throw UnrewindableBodyError();
        }

        while(buf.size() < bytesToRead + 2) {
            const QByteArray t = connection->recv(1024 * 8);
            if(t.isEmpty()) {
                throw ConnectionError();
            }
            buf.append(t);
        }

        const QByteArray &result = buf.mid(0, bytesToRead);
        buf.remove(0, bytesToRead + 2);

        if(bytesToRead == 0 && !buf.isEmpty() && debugLevel > 0) {
            qDebug() << "bytesToRead == 0 but some bytes left.";
        }

        return result;
    }

};

HttpResponse HttpSessionPrivate::send(HttpRequest &request)
{
    QUrl &url = request.url;
    if(url.scheme() != QStringLiteral("http") && url.scheme() != QStringLiteral("https")) {
        throw InvalidSchema();
    }
    if(!request.query.isEmpty()) {
        QUrlQuery query(url);
        for(QMap<QString, QString>::const_iterator itor = request.query.constBegin(); itor != request.query.constEnd(); ++itor) {
            query.addQueryItem(itor.key(), itor.value());
        }
        url.setQuery(query);
        request.url = url.toString();
    }

    mergeCookies(request, url);
    QList<HttpHeader> allHeaders = makeHeaders(request, url);

    QSharedPointer<SocketLike> connection = connectionForUrl(url);

    if(request.version == HttpVersion::Unknown) {
        request.version = defaultVersion;
    }
    QByteArray versionBytes;
    if(request.version == HttpVersion::Http1_0) {
        versionBytes = "HTTP/1.0";
    } else if(request.version == HttpVersion::Http1_1) {
        versionBytes = "HTTP/1.1";
    } else if(request.version == HttpVersion::Http2_0) {
        versionBytes = "HTTP/2.0";
    } else {
        throw InvalidSchema();
    }

    QByteArrayList lines;
    QByteArray resourcePath = url.toEncoded(QUrl::RemoveAuthority | QUrl::RemoveFragment | QUrl::RemoveScheme);
    const QByteArray &commandLine = request.method.toUpper().toUtf8() + QByteArray(" ") +
            resourcePath + QByteArray(" ") + versionBytes + QByteArray("\r\n");
    lines.append(commandLine);
    for(int i = 0;i < allHeaders.size(); ++i) {
        const HttpHeader &header = allHeaders.at(i);
        lines.append(header.name.toUtf8() + QByteArray(": ") + header.value + QByteArray("\r\n"));
    }
    lines.append(QByteArray("\r\n"));
    if(debugLevel > 0) {
        qDebug() << "sending headers:" << lines.join();
    }
    connection->sendall(lines.join());

    if(!request.body.isEmpty()) {
        if(debugLevel > 1) {
            qDebug() << "sending body:" << request.body;
        }
        connection->sendall(request.body);
    }

    HttpResponse response;
    response.request = request;
    response.url = request.url;

    HeaderSplitter splitter(connection);

    QByteArray firstLine = splitter.nextLine();

    QList<QByteArray> commands = splitBytes(firstLine, ' ', 2);
    if(commands.size() != 3) {
        throw InvalidHeader();
    }
    if(commands.at(0) == QByteArray("HTTP/1.0")) {
        response.version = Http1_0;
    } else if(commands.at(0) == QByteArray("HTTP/1.1")) {
        response.version = Http1_1;
    } else {
        throw InvalidHeader();
    }
    bool ok;
    response.statusCode = commands.at(1).toInt(&ok);
    if(!ok) {
        throw InvalidHeader();
    }
    response.statusText = QString::fromLatin1(commands.at(2));

    const int MaxHeaders = 64;
    for(int i = 0; i < MaxHeaders; ++i) {
        QByteArray line = splitter.nextLine();
        if(line.isEmpty()) {
            break;
        }
        QByteArrayList headerParts = splitBytes(line, ':', 1);
        if(headerParts.size() != 2) {
            throw InvalidHeader();
        }
        QString headerName = QString::fromUtf8(headerParts[0]).trimmed();
        QByteArray headerValue = headerParts[1].trimmed();
        response.addHeader(headerName, headerValue);
        if(debugLevel > 0)  {
            qDebug() << "receiving header: " << headerName << headerValue;
        }
    }
    if(response.hasHeader(QStringLiteral("Set-Cookie"))) {
        foreach(const QByteArray &value, response.multiHeader("Set-Cookie")) {
            const QList<QNetworkCookie> &cookies = QNetworkCookie::parseCookies(value);
            if(debugLevel > 0 && !cookies.isEmpty()) {
                qDebug() << "receiving cookie:" << cookies[0].toRawForm();
            }
            response.cookies.append(cookies);
        }
        cookieJar.setCookiesFromUrl(response.cookies, response.url);
    }

    if(!splitter.buf.isEmpty()) {
        response.body = splitter.buf;
    }

    qint64 contentLength = response.getContentLength();
    if(contentLength > 0) {
        if(contentLength > request.maxBodySize) {
            throw UnrewindableBodyError();
        } else {
            while(response.body.size() < contentLength) {
                qint64 leftBytes = qMin((qint64) 1024 * 8, contentLength - response.body.size());
                const QByteArray &t = connection->recvall(leftBytes);
                if(t.isEmpty()) {
                    qDebug() << "no content!";
                    throw ConnectionError();
                }
                response.body.append(t);
            }
        }
    } else if(contentLength < 0) { // without `Content-Length` header.
        const QByteArray &transferEncodingHeader = response.header(QStringLiteral("Transfer-Encoding"));
        bool readTrunked = (transferEncodingHeader.toLower() == QByteArray("chunked"));
        if(readTrunked) {
            ChunkedBlockReader reader(connection);
            reader.buf = response.body;
            reader.debugLevel = debugLevel;
            response.body.clear();
            while(true) {
                qint64 leftBytes = request.maxBodySize - response.body.size();
                const QByteArray &block = reader.nextBlock(leftBytes);
                if(block.isEmpty()) {
                    break;
                }
                response.body.append(block);
            }
        } else {
            while(response.body.size() < request.maxBodySize) {
                const QByteArray &t = connection->recvall(1024 * 8);
                if(t.isEmpty()) {
                    break;
                }
                response.body.append(t);
            }
        }
    } else { // nothing to read. empty document.
        if(!response.body.isEmpty()) {
            // warning!
        }
    }
    const QByteArray &contentEncodingHeader = response.header("Content-Encoding");
    qDebug() << contentEncodingHeader;
    if(contentEncodingHeader.toLower() == QByteArray("deflate") && response.body.isEmpty()) {
        response.body = qUncompress(response.body);
        if(response.body.isEmpty()) {
            throw ContentDecodingError();
        }
    }
    if(debugLevel > 1 && !response.body.isEmpty()) {
        qDebug() << "receiving body:" << response.body;
    }
    recycle(response.url, connection);
    return response;
}


QList<HttpHeader> HttpSessionPrivate::makeHeaders(HttpRequest &request, const QUrl &url)
{
    QList<HttpHeader> allHeaders = request.allHeaders();

    if(!request.hasHeader(QStringLiteral("Connection"))) {
        allHeaders.prepend(HttpHeader(QStringLiteral("Connection"), QByteArray("keep-alive")));
    }
    if(!request.hasHeader(QStringLiteral("Content-Length")) && !request.body.isEmpty()) {
        allHeaders.prepend(HttpHeader(QStringLiteral("Content-Length"), QByteArray::number(request.body.size())));
    }
    if(!request.hasHeader(QStringLiteral("User-Agent"))) {
        allHeaders.prepend(HttpHeader(QStringLiteral("User-Agent"), defaultUserAgent.toUtf8()));
    }
    if(!request.hasHeader(QStringLiteral("Host"))) {
        QString httpHost = url.host();
        if(url.port() != -1) {
            httpHost += QStringLiteral(":") + QString::number(url.port());
        }
        allHeaders.prepend(HttpHeader(QStringLiteral("Host"), httpHost.toUtf8()));
    }
    if(!request.hasHeader(QStringLiteral("Accept"))) {
        allHeaders.append(HttpHeader(QStringLiteral("Accept"), QByteArray("*/*")));
    }
    if(!request.hasHeader(QStringLiteral("Accept-Language"))) {
        allHeaders.append(HttpHeader(QStringLiteral("Accept-Language"), QByteArray("en-US,en;q=0.5")));
    }
    if(!request.hasHeader(QStringLiteral("Accept-Encoding"))) {
        allHeaders.append(HttpHeader(QStringLiteral("Accept-Encoding"), QByteArray("deflate")));
    }
    if(!request.cookies.isEmpty() && !request.hasHeader(QStringLiteral("Cookies"))) {
        QByteArray result;
        bool first = true;
        foreach (const QNetworkCookie &cookie, request.cookies) {
            if (!first)
                result += "; ";
            first = false;
            result += cookie.toRawForm(QNetworkCookie::NameAndValueOnly);
        }
        allHeaders.append(HttpHeader(QStringLiteral("Cookie"), result));
    }
    return allHeaders;
}

void HttpSessionPrivate::mergeCookies(HttpRequest &request, const QUrl &url)
{
    QList<QNetworkCookie> cookies = cookieJar.cookiesForUrl(url);
    if(cookies.isEmpty()) {
        return;
    }
    cookies.append(request.cookies);
    request.cookies = cookies;
}

void setProxySwitcher(HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher)
{
    if(!switcher.isNull()) {
        HttpSessionPrivate::getPrivateHelper(session)->proxySwitcher = switcher;
    } else {
        HttpSessionPrivate::getPrivateHelper(session)->proxySwitcher.reset(new SimpleProxySwitcher());
    }
}

HttpSession::HttpSession()
    :d_ptr(new HttpSessionPrivate(this)) {}


HttpSession::~HttpSession()
{
    delete d_ptr;
}

#define COMMON_PARAMETERS_WITHOUT_DEFAULT \
    const QMap<QString, QString> &query,\
    const QMap<QString, QByteArray> &headers, \
    bool allowRedirects, \
    bool verify \

HttpResponse HttpSession::get(const QUrl &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("GET");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    return send(request);
}

HttpResponse HttpSession::head(const QUrl &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("HEAD");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    return send(request);
}

HttpResponse HttpSession::options(const QUrl &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("OPTIONS");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    return send(request);
}

HttpResponse HttpSession::delete_(const QUrl &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("DELETE");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    return send(request);
}

HttpResponse HttpSession::post(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("POST");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    request.body = body;
    return send(request);
}

HttpResponse HttpSession::put(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("PUT");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    request.body = body;
    return send(request);
}

HttpResponse HttpSession::patch(const QUrl &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    HttpRequest request;
    request.method = QString::fromLatin1("PATCH");
    request.url = url;
    request.setHeaders(headers);
    request.query = query;
    request.body = body;
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    QByteArray data = json.toJson();
    QMap<QString, QByteArray> newHeaders(headers);
    newHeaders.insert("Content-Type", "application/json");
    return post(url, data, query, newHeaders, allowRedirects, verify);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    QByteArray data = json.toJson();
    QMap<QString, QByteArray> newHeaders(headers);
    newHeaders.insert("Content-Type", "application/json");
    return put(url, data, query, newHeaders, allowRedirects, verify);
}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonDocument &json, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    QByteArray data = json.toJson();
    QMap<QString, QByteArray> newHeaders(headers);
    newHeaders.insert("Content-Type", "application/json");
    return patch(url, data, query, newHeaders, allowRedirects, verify);
}


HttpResponse HttpSession::send(HttpRequest &request)
{
    Q_D(HttpSession);
    HttpResponse response = d->send(request);
    QList<HttpResponse> history;

    if(request.maxRedirects > 0) {
        int tries = 0;
        while(response.statusCode == 301 || response.statusCode == 302 || response.statusCode == 303 || response.statusCode == 307) {
            if(tries > request.maxRedirects) {
                throw TooManyRedirects();
            }
            HttpRequest newRequest;
            if(response.statusCode == 303 || response.statusCode == 307) {
                newRequest = request;
            } else {
                newRequest.method = "GET"; // not rfc behavior, but many browser do this.
            }
            newRequest.url = request.url.resolved(response.getLocation());
            if(!newRequest.url.isValid()) {
                throw InvalidURL();
            }
            HttpResponse newResponse = d->send(newRequest);
            history.append(response);
            response = newResponse;
            ++tries;
        }
    }
    response.history = history;
    return response;
}

QNetworkCookieJar &HttpSession::cookieJar()
{
    Q_D(HttpSession);
    return d->cookieJar;
}


QNetworkCookie HttpSession::cookie(const QUrl &url, const QString &name)
{
    Q_D(HttpSession);
    const QNetworkCookieJar &jar = d->cookieJar;
    QList<QNetworkCookie> cookies = jar.cookiesForUrl(url);
    for(int i = 0; i < cookies.size(); ++i) {
        const QNetworkCookie &cookie = cookies.at(i);
        if(cookie.name() == name) {
            return cookie;
        }
    }
    return QNetworkCookie();
}


void HttpSession::setMaxConnectionsPerServer(int maxConnectionsPerServer)
{
    Q_D(HttpSession);
    if(maxConnectionsPerServer <= 0) {
        maxConnectionsPerServer = INT_MAX;
    }
    d->maxConnectionsPerServer = maxConnectionsPerServer;
    //TODO update semphores
}

int HttpSession::maxConnectionsPerServer()
{
    Q_D(HttpSession);
    return d->maxConnectionsPerServer;
}


void HttpSession::setDebugLevel(int level)
{
    Q_D(HttpSession);
    d->debugLevel = level;
}

void HttpSession::disableDebug()
{
    Q_D(HttpSession);
    d->debugLevel = 0;
}

QString HttpSession::defaultUserAgent() const
{
    Q_D(const HttpSession);
    return d->defaultUserAgent;
}

void HttpSession::setDefaultUserAgent(const QString &userAgent)
{
    Q_D(HttpSession);
    d->defaultUserAgent = userAgent;
}

HttpVersion HttpSession::defaultVersion() const
{
    Q_D(const HttpSession);
    return d->defaultVersion;
}

void HttpSession::setDefaultVersion(HttpVersion defaultVersion)
{
    Q_D(HttpSession);
    d->defaultVersion = defaultVersion;
}

QSharedPointer<Socks5Proxy> HttpSession::socks5Proxy() const
{
    Q_D(const HttpSession);
    return d->socks5Proxy();
}

void HttpSession::setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy)
{
    Q_D(HttpSession);
    d->setSocks5Proxy(proxy);
}

QSharedPointer<HttpProxy> HttpSession::httpProxy() const
{
    Q_D(const HttpSession);
    return d->httpProxy();
}

void HttpSession::setHttpProxy(QSharedPointer<HttpProxy> proxy)
{
    Q_D(HttpSession);
    d->setHttpProxy(proxy);
}

RequestException::~RequestException()
{}


QString RequestException::what() const throw()
{
    return QStringLiteral("An HTTP error occurred.");
}


QString HTTPError::what() const throw()
{
    return QStringLiteral("server respond error.");
}


QString ConnectionError::what() const throw()
{
    return QStringLiteral("A Connection error occurred.");
}


QString ProxyError::what() const throw()
{
    return QStringLiteral("A proxy error occurred.");
}


QString SSLError::what() const throw()
{
    return QStringLiteral("A SSL error occurred.");
}


QString RequestTimeout::what() const throw()
{
    return QStringLiteral("The request timed out.");
}


QString ConnectTimeout::what() const throw()
{
    return QStringLiteral("The request timed out while trying to connect to the remote server.");
}


QString ReadTimeout::what() const throw()
{
    return QStringLiteral("The server did not send any data in the allotted amount of time.");
}


QString URLRequired::what() const throw()
{
    return QStringLiteral("A valid URL is required to make a request.");
}


QString TooManyRedirects::what() const throw()
{
    return QStringLiteral("Too many redirects.");
}


QString MissingSchema::what() const throw()
{
    return QStringLiteral("The URL schema (e.g. http or https) is missing.");
}


QString InvalidSchema::what() const throw()
{
    return QStringLiteral("The URL schema can not be handled.");
}


QString InvalidURL::what() const throw()
{
    return QStringLiteral("The URL provided was somehow invalid.");
}


QString InvalidHeader::what() const throw()
{
    return QStringLiteral("Can not parse the http header.");
}

QString ChunkedEncodingError::what() const throw()
{
    return QStringLiteral("The server declared chunked encoding but sent an invalid chunk.");
}


QString ContentDecodingError::what() const throw()
{
    return QStringLiteral("Failed to decode response content");
}


QString StreamConsumedError::what() const throw()
{
    return QStringLiteral("The content for this response was already consumed");
}


QString RetryError::what() const throw()
{
    return QStringLiteral("Custom retries logic failed");
}


QString UnrewindableBodyError::what() const throw()
{
    return QStringLiteral("Requests encountered an error when trying to rewind a body");
}

QTNETWORKNG_NAMESPACE_END
