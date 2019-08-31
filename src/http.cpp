#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qtextcodec.h>
#include <QtCore/qendian.h>
#include <QtCore/qdatastream.h>
#include "../include/private/http_p.h"
#include "../include/socks5_proxy.h"
#ifndef QTNG_NO_CRYPTO
#include "../include/ssl.h"
#endif

QTNETWORKNG_NAMESPACE_BEGIN


FormData::FormData()
{
    const QByteArray possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    const int randomPartLength = 16;

    QByteArray randomPart;
    for (int i=0; i<randomPartLength; ++i) {
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
        data.append(name.toLatin1());
        data.append("=\"");
        data.append(value.toLatin1());
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
    for (QMap<QString, QString>::const_iterator itor = query.constBegin(); itor != query.constEnd(); ++itor) {
        body.append("--");
        body.append(boundary);
        body.append("\r\n");
        body.append("Content-Disposition: form-data;");
        body.append(formatHeaderParam(QStringLiteral("name"), itor.key()));
        body.append("\r\n\r\n");
        body.append(itor.value().toUtf8());
        body.append("\r\n");
    }
    for (QMap<QString, FormDataFile>::const_iterator itor = files.constBegin(); itor != files.constEnd(); ++itor) {
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

class HttpRequestPrivate: public QSharedData
{
public:
    HttpRequestPrivate();
    ~HttpRequestPrivate();
    HttpRequestPrivate(const HttpRequestPrivate& other);
public:
    QString method;
    QUrl url;
    QUrlQuery query;
    QList<QNetworkCookie> cookies;
    QByteArray body;
    QString userAgent;
    int maxBodySize;
    int maxRedirects;
    float timeout;
    HttpRequest::Priority priority;
    HttpVersion version;
    bool streamResponse;
};


HttpRequestPrivate::HttpRequestPrivate()
    :method("GET")
    , maxBodySize(0)
    , maxRedirects(8)
    , timeout(-1.0)
    , priority(HttpRequest::NormalPriority)
    , version(Http1_1)
    , streamResponse(false)
{}


HttpRequestPrivate::~HttpRequestPrivate() {}

HttpRequestPrivate::HttpRequestPrivate(const HttpRequestPrivate &other)
    :QSharedData(other)
    , method(other.method)
    , url(other.url)
    , query(other.query)
    , cookies(other.cookies)
    , body(other.body)
    , userAgent(other.userAgent)
    , maxBodySize(other.maxBodySize)
    , maxRedirects(other.maxRedirects)
    , timeout(other.timeout)
    , priority(other.priority)
    , version(other.version)
    , streamResponse(other.streamResponse)
{
}


HttpRequest::HttpRequest()
    :d(new HttpRequestPrivate())
{
}


HttpRequest::~HttpRequest()
{
}


HttpRequest::HttpRequest(const HttpRequest &other)
    :d(other.d)
{
    this->headers = other.headers;
}


HttpRequest::HttpRequest(HttpRequest &&other)
{
    qSwap(d, other.d);
    headers = std::move(other.headers);
}


HttpRequest &HttpRequest::operator=(const HttpRequest &other)
{
    this->headers = other.headers;
    this->d = other.d;
    return *this;
}


QString HttpRequest::method() const
{
    return d->method;
}


void HttpRequest::setMethod(const QString &method)
{
    d->method = method;
}


QUrl HttpRequest::url() const
{
    return d->url;
}


void HttpRequest::setUrl(const QUrl &url)
{
    d->url = url;
}


QMap<QString, QString> HttpRequest::query() const
{
    QMap<QString, QString> r;
    for (const QPair<QString, QString> &p: d->query.queryItems()) {
        r.insert(p.first, p.second);
    }
    return r;
}


void HttpRequest::setQuery(const QMap<QString, QString> &query)
{
    d->query.clear();
    for (QMap<QString, QString>::const_iterator itor = query.constBegin(); itor != query.constEnd(); ++itor) {
        d->query.addQueryItem(itor.key(), itor.value());
    }
}


void HttpRequest::setQuery(const QUrlQuery &query)
{
    d->query = query;
}


QList<QNetworkCookie> HttpRequest::cookies() const
{
    return d->cookies;
}


void HttpRequest::setCookies(const QList<QNetworkCookie> &cookies)
{
    d->cookies = cookies;
}


QByteArray HttpRequest::body() const
{
    return d->body;
}


void HttpRequest::setBody(const QByteArray &body)
{
    d->body = body;
}


QString HttpRequest::userAgent() const
{
    return d->userAgent;
}


void HttpRequest::setUserAgent(const QString &userAgent)
{
    d->userAgent = userAgent;
}

int HttpRequest::maxBodySize() const
{
    return d->maxBodySize;
}

void HttpRequest::setMaxBodySize(int maxBodySize)
{
    d->maxBodySize = maxBodySize;
}

int HttpRequest::maxRedirects() const
{
    return d->maxRedirects;
}

void HttpRequest::setMaxRedirects(int maxRedirects)
{
    d->maxRedirects =  maxRedirects;
}

HttpRequest::Priority HttpRequest::priority() const
{
    return d->priority;
}

void HttpRequest::setPriority(HttpRequest::Priority priority)
{
    d->priority = priority;
}

HttpVersion HttpRequest::version() const
{
    return d->version;
}

void HttpRequest::setVersion(HttpVersion version)
{
    d->version = version;
}

void HttpRequest::setStreamResponse(bool streamResponse)
{
    d->streamResponse = streamResponse;
}

bool HttpRequest::streamResponse() const
{
    return d->streamResponse;
}

float HttpRequest::tiemout() const
{
    return d->timeout;
}

void HttpRequest::setTimeout(float timeout)
{
    d->timeout = timeout;
}


void HttpRequest::setBody(const FormData &formData)
{
    QString contentType = QString::fromLatin1("multipart/form-data; boundary=%1").arg(QString::fromLatin1(formData.boundary));
    setHeader(QStringLiteral("Content-Type"), contentType.toLatin1());
    QString mimeHeader("MIME-Version");
    if (!hasHeader(mimeHeader)) {
        setHeader(mimeHeader, QByteArray("1.0"));
    }
    d->body = formData.toByteArray();
}


void HttpRequest::setBody(const QJsonDocument &json)
{
    setHeader(QStringLiteral("Content-Type"), "application/json");
    d->body = json.toJson();
}


void HttpRequest::setBody(const QJsonObject &json)
{
    setHeader(QStringLiteral("Content-Type"), "application/json");
    d->body = QJsonDocument(json).toJson();
}


void HttpRequest::setBody(const QJsonArray &json)
{
    setHeader(QStringLiteral("Content-Type"), "application/json");
    d->body = QJsonDocument(json).toJson();
}


void HttpRequest::setBody(const QMap<QString, QString> form)
{
    QUrlQuery query;
    for (QMap<QString, QString>::const_iterator itor = form.constBegin(); itor != form.constEnd(); ++itor) {
        query.addQueryItem(itor.key(), itor.value());
    }
    setBody(query);
}


void HttpRequest::setBody(const QUrlQuery &form)
{
    setHeader(QStringLiteral("Content-Type"), "application/x-www-form-urlencoded");
    d->body = form.toString(QUrl::FullyEncoded).toUtf8();
}


class HttpResponsePrivate: public QSharedData
{
public:
    HttpResponsePrivate();
    ~HttpResponsePrivate();
    HttpResponsePrivate(const HttpResponsePrivate &other);
public:
    QUrl url;
    QString statusText;
    QList<QNetworkCookie> cookies;
    HttpRequest request;
    QByteArray body;
    qint64 elapsed;
    QList<HttpResponse> history;
    QSharedPointer<RequestError> error;
    QSharedPointer<SocketLike> stream;
    int statusCode;
    HttpVersion version;
    bool consumed;
};


HttpResponsePrivate::HttpResponsePrivate()
    : elapsed(0), version(Http1_1), consumed(false)
{}

HttpResponsePrivate::~HttpResponsePrivate() {}

HttpResponsePrivate::HttpResponsePrivate(const HttpResponsePrivate &other)
    : QSharedData(other)
    , url(other.url)
    , statusText(other.statusText)
    , cookies(other.cookies)
    , request(other.request)
    , body(other.body)
    , elapsed(other.elapsed)
    , history(other.history)
    , statusCode(other.statusCode)
    , version(other.version)
    , consumed(other.consumed)
{}

HttpResponse::HttpResponse()
    :d(new HttpResponsePrivate())
{}


HttpResponse::~HttpResponse()
{}


HttpResponse::HttpResponse(const HttpResponse& other)
    :d(other.d)
{
    this->headers = other.headers;
}


HttpResponse::HttpResponse(HttpResponse &&other)
{
    qSwap(d, other.d);
    headers = std::move(other.headers);
}


HttpResponse &HttpResponse::operator=(const HttpResponse& other)
{
    d = other.d;
    headers = other.headers;
    return *this;
}


QUrl HttpResponse::url() const
{
    return d->url;
}


void HttpResponse::setUrl(const QUrl &url)
{
    d->url = url;
}


int HttpResponse::statusCode() const
{
    return d->statusCode;
}


void HttpResponse::setStatusCode(int statusCode)
{
    d->statusCode = statusCode;
}


QString HttpResponse::statusText() const
{
    return d->statusText;
}


void HttpResponse::setStatusText(const QString &statusText)
{
    d->statusText = statusText;
}


QList<QNetworkCookie> HttpResponse::cookies() const
{
    return d->cookies;
}


void HttpResponse::setCookies(const QList<QNetworkCookie> &cookies)
{
    d->cookies = cookies;
}


HttpRequest HttpResponse::request() const
{
    return d->request;
}


void HttpResponse::setRequest(const HttpRequest &request)
{
    d->request = request;
}

QSharedPointer<SocketLike> HttpResponse::takeStream(QByteArray *readBytes)
{
    if (d->consumed) {
//        qWarning() << "the stream is consumed. do you remember to set the streamResponse property of request to true?";
    }
    if (readBytes) {
        *readBytes = d->body;
    } else {
//        qWarning() << "you should take care the left bytes after parsing header. please pass a non-null byte array to takeStream()";
    }
    d->consumed = true;
    return d->stream;
}

RequestError *toRequestError(ChunkedBlockReader::Error error)
{
    switch (error) {
    case ChunkedBlockReader::ChunkedEncodingError:
        return new ChunkedEncodingError();
    case ChunkedBlockReader::UnrewindableBodyError:
        return new UnrewindableBodyError();
    case ChunkedBlockReader::ConnectionError:
        return new ConnectionError();
    default:
        return nullptr;
    }
}

QByteArray HttpResponse::body() const
{
    return d->body;
}

QByteArray HttpResponse::body()
{
    // special cases.
    if (d->consumed) {
        return d->body;
    }
    // XXX if not consumed and body is not empty, it must be the from the header splitter.
    // read it from stream
    qint32 contentLength = getContentLength();
    if (contentLength > 0) {
        if (d->request.maxBodySize() > 0 && contentLength > d->request.maxBodySize()) {
            d->error.reset(new UnrewindableBodyError());
            d->consumed = true;
            return QByteArray();
        } else {
            if (d->body.size() > contentLength) {
                qWarning() << "got too much bytes.";
            } else if (d->body.size() < contentLength){
                if (d->stream.isNull()) {
                    d->error.reset(new UnrewindableBodyError());
                    d->consumed = true;
                    return QByteArray();
                }
                qint32 leftBytes = contentLength - d->body.size();
                const QByteArray &t = d->stream->recvall(leftBytes);
                if (t.size() != leftBytes) {
                    d->error.reset(new ConnectionError());
                    d->consumed = true;
                    return QByteArray();
                }
                d->body.append(t);
            }
        }
    } else if (contentLength < 0) { // without `Content-Length` header.
        if (d->stream.isNull()) {
            d->error.reset(new UnrewindableBodyError());
            d->consumed = true;
            return QByteArray();
        }
        const QByteArray &transferEncodingHeader = header(QStringLiteral("Transfer-Encoding"));
        bool readTrunked = (transferEncodingHeader.toLower() == QByteArray("chunked"));
        if (readTrunked) {
            ChunkedBlockReader reader(d->stream, d->body);
            ChunkedBlockReader::Error readerError;
//            reader.debugLevel = debugLevel;
            d->body.clear();
            RequestError *error = nullptr;
            while (true) {
                qint64 leftBytes;
                if (d->request.maxBodySize() > 0) {
                    leftBytes = d->request.maxBodySize() - d->body.size();
                } else {
                    leftBytes = INT_MAX;
                }
                const QByteArray &block = reader.nextBlock(leftBytes, &readerError);
                error = toRequestError(readerError);
                if (error != nullptr) {
                    d->error.reset(error);
                    d->consumed = true;
                    return QByteArray();
                }
                if (block.isEmpty()) {
                    break;
                }
                d->body.append(block);
            }
        } else {
            while (d->request.maxBodySize() < 0 || d->body.size() < d->request.maxBodySize()) {
                const QByteArray &t = d->stream->recv(1024 * 8);
                if (t.isEmpty()) {
                    break;
                }
                d->body.append(t);
            }
        }
    } else { // nothing to read. empty document.
        if(!d->body.isEmpty()) {
            // warning!
            qWarning() << "the body is not empty but content length is set to 0.";
        }
    }
    // FIXME: not supported yet!
    const QByteArray &contentEncodingHeader = header("Content-Encoding");
    if (contentEncodingHeader.toLower() == QByteArray("deflate") && !d->body.isEmpty()) {
        uchar header[4];
        qToBigEndian<quint32>(static_cast<quint32>(d->body.size()), header);
        QByteArray t; t.reserve(d->body.size() + 4);
        t.append(reinterpret_cast<const char*>(header), 4);
        qDebug() << t;
        t.append(d->body);
        qDebug() << t;
        d->body = qUncompress(t);
        if(d->body.isEmpty()) {
            d->error.reset(new ContentDecodingError());
            d->consumed = true;
            return QByteArray();
        }
//    } else if (contentEncodingHeader.toLower() == QByteArray("gzip") && !d->body.isEmpty()) {
//        d->body = unzip(d->body);
//        if(d->body.isEmpty()) {
//            d->error.reset(new ContentDecodingError());
//            d->consumed = true;
//            return QByteArray();
//        }
    } else if (!contentEncodingHeader.isEmpty()){
        qWarning() << "unsupported content encoding." << contentEncodingHeader;
    }
    d->consumed = true;
    return d->body;
}


void HttpResponse::setBody(const QByteArray &body)
{
    d->body = body;
    d->consumed = true;
}


qint64 HttpResponse::elapsed() const
{
    return d->elapsed;
}


void HttpResponse::setElapsed(qint64 elapsed)
{
    d->elapsed = elapsed;
}


QList<HttpResponse> HttpResponse::history() const
{
    return d->history;
}


void HttpResponse::setHistory(const QList<HttpResponse> &history)
{
    d->history = history;
}


HttpVersion HttpResponse::version() const
{
    return d->version;
}


void HttpResponse::setVersion(HttpVersion version)
{
    d->version = version;
}

QString HttpResponse::text()
{
    return QString::fromUtf8(body());
}

QJsonDocument HttpResponse::json()
{
    QJsonParseError error;
    QJsonDocument jsonDocument = QJsonDocument::fromJson(body(), &error);
    if(error.error != QJsonParseError::NoError) {
        return QJsonDocument();
    } else {
        return jsonDocument;
    }
}

QString HttpResponse::html()
{
    // TODO detect encoding;
    return QString::fromUtf8(body());
}

bool HttpResponse::isOk() const
{
    return d->error.isNull() && d->statusCode < 300;
}

bool HttpResponse::hasNetworkError() const
{
    return !d->error.isNull() && d->error.dynamicCast<ConnectionError>() != nullptr;
}

bool HttpResponse::hasHttpError() const
{
    return !d->error.isNull() && d->error.dynamicCast<HTTPError>() != nullptr;
}


QSharedPointer<RequestError> HttpResponse::error() const
{
    return d->error;
}


void HttpResponse::setError(QSharedPointer<RequestError> error)
{
    d->error = error;
}


HttpSessionPrivate::HttpSessionPrivate(HttpSession *q_ptr)
    :defaultVersion(HttpVersion::Http1_1), q_ptr(q_ptr), debugLevel(0)
{
    defaultUserAgent = QStringLiteral("Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0");
}

HttpSessionPrivate::~HttpSessionPrivate()
{

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
    : maxConnectionsPerServer(10)
    , timeToLive(60)
    , defaultConnectionTimeout(10.0)
    , operations(new CoroutineGroup)
    , proxySwitcher(new SimpleProxySwitcher)
{
    operations->spawnWithName("removeUnusedConnections", [this] {removeUnusedConnections();});
}


ConnectionPool::~ConnectionPool()
{
    delete operations;
}


ConnectionPoolItem &ConnectionPool::getItem(const QUrl &url)
{
    const QUrl &h = hostOnly(url);
    ConnectionPoolItem &item = items[h];
    item.lastUsed = QDateTime::currentDateTimeUtc();
    if (item.semaphore.isNull()) {
        item.semaphore.reset(new Semaphore(maxConnectionsPerServer));
    }
    return item;
}


QSharedPointer<Semaphore> ConnectionPool::getSemaphore(const QUrl &url)
{
    ConnectionPoolItem &item = getItem(url);
    return item.semaphore;
}


void ConnectionPool::recycle(const QUrl &url, QSharedPointer<SocketLike> connection)
{
    ConnectionPoolItem &item = getItem(url);
    if (item.connections.size() < maxConnectionsPerServer) {
        item.connections.append(connection);
    }
}


QSharedPointer<SocketLike> ConnectionPool::connectionForUrl(const QUrl &url, RequestError **error)
{
    ConnectionPoolItem &item = getItem(url);
    QSharedPointer<SocketLike> connection;

    while (!item.connections.isEmpty()) {
        connection = item.connections.takeFirst();
        if (connection->isValid()) {
            return connection;
        }
    }

    QSharedPointer<Socket> rawSocket;
    quint16 defaultPort = 80;
    if (url.scheme() == QStringLiteral("http")) {
    } else {
#ifndef QTNG_NO_CRYPTO
        defaultPort = 443;
#else
        *error = new ConnectionError();
        return QSharedPointer<SocketLike>();
#endif
    }

    QSharedPointer<Socks5Proxy> socks5Proxy = proxySwitcher->selectSocks5Proxy(url);
    if (socks5Proxy) {
        rawSocket = socks5Proxy->connect(url.host(), static_cast<quint16>(url.port(defaultPort)));

        if (url.scheme() == QStringLiteral("http")) {
            connection = SocketLike::rawSocket(rawSocket);
        } else {
    #ifndef QTNG_NO_CRYPTO
            QSharedPointer<SslSocket> ssl(new SslSocket(rawSocket));
            ssl->handshake(false);
            connection = SocketLike::sslSocket(ssl);
    #else
            *error = new ConnectionError();
            return QSharedPointer<SocketLike>();
    #endif
        }
    } else {
        rawSocket.reset(new Socket);
        rawSocket->setDnsCache(dnsCache);

        if(url.scheme() == QStringLiteral("http")) {
            connection = SocketLike::rawSocket(rawSocket);
        } else{
    #ifndef QTNG_NO_CRYPTO
            connection = SocketLike::sslSocket(QSharedPointer<SslSocket>::create(rawSocket));
    #else
            *error = new ConnectionError();
            return QSharedPointer<SocketLike>();
    #endif
        }
        if (!connection->connect(url.host(), static_cast<quint16>(url.port(defaultPort)))) {
            *error = new ConnectionError();
            return QSharedPointer<SocketLike>();
        }
    }
    return connection;
}


void ConnectionPool::removeUnusedConnections()
{
    while (true) {
        try {
            Coroutine::sleep(1.0);
        } catch (CoroutineException &) {
            return;
        }
        const QDateTime &now = QDateTime::currentDateTimeUtc();
        QMap<QUrl, ConnectionPoolItem> newItems;
        for (QMap<QUrl, ConnectionPoolItem>::const_iterator itor = items.constBegin(); itor != items.constEnd(); ++itor) {
            if (itor.value().lastUsed.secsTo(now) < timeToLive || itor.value().semaphore->isUsed()) {
                newItems.insert(itor.key(), itor.value());
            } else {
                qDebug() << "remove connection:" << itor.value().lastUsed;
            }
        }
        items = newItems;
    }
}


QSharedPointer<Socks5Proxy> ConnectionPool::socks5Proxy() const
{
    if (proxySwitcher->socks5Proxies.size() > 0) {
        return proxySwitcher->socks5Proxies.at(0);
    }
    return QSharedPointer<Socks5Proxy>();
}


QSharedPointer<HttpProxy> ConnectionPool::httpProxy() const
{
    if (proxySwitcher->httpProxies.size() > 0) {
        return proxySwitcher->httpProxies.at(0);
    }
    return QSharedPointer<HttpProxy>();
}


void ConnectionPool::setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy)
{
    proxySwitcher->socks5Proxies.clear();
    if (!proxy.isNull()) {
        proxySwitcher->socks5Proxies.append(proxy);
    }
}


void ConnectionPool::setHttpProxy(QSharedPointer<HttpProxy> proxy)
{
    proxySwitcher->httpProxies.clear();
    if (!proxy.isNull()) {
        proxySwitcher->httpProxies.append(proxy);
    }
}


RequestError *toRequestError(HeaderSplitter::Error error)
{
    switch (error) {
    case HeaderSplitter::ConnectionError:
        return new ConnectionError();
    case HeaderSplitter::EncodingError:
        return new InvalidHeader();
    case HeaderSplitter::ExhausedMaxLine:
        return new InvalidHeader();
    case HeaderSplitter::LineTooLong:
        return new InvalidHeader();
    default:
        return nullptr;
    }
}

HttpResponse HttpSessionPrivate::send(HttpRequest &request)
{
    RequestError *error = nullptr;

    QUrl &url = request.d->url;
    HttpResponse response;
    response.d->url = url;
    response.d->request = request;
    if (url.scheme() != QStringLiteral("http") && url.scheme() != QStringLiteral("https")) {
        if (debugLevel > 0) {
            qDebug() << "invalid scheme" << url.scheme();
        }
        response.d->error.reset(new InvalidScheme());
        return response;
    }
    if (!request.d->query.isEmpty()) {
        QUrlQuery query(url);
        for (const QPair<QString, QString> &p: request.d->query.queryItems()) {
            query.addQueryItem(p.first, p.second);
        }
        url.setQuery(query);
        response.d->url = url;
    }

    if (!cacheManager.isNull() && (request.d->method == "GET"
                                   || request.d->method == "HEAD"
                                   || request.d->method == "OPTION")) {
        const QByteArray &cacheControlHeader = request.header(HttpRequest::CacheControlHeader);
        if (!cacheControlHeader.contains("no-cache")) {
            if (cacheManager->getResponse(&response)) {
                return response;
            }
        }
    }

    mergeCookies(request, url);
    QList<HttpHeader> allHeaders = makeHeaders(request, url);

    ScopedLock<Semaphore> lock(getSemaphore(url));
    if (!lock.isSuccess()) {
        response.d->error.reset(new ConnectionError());
        return response;
    }
    QSharedPointer<SocketLike> connection;
    float timeout = request.d->timeout < 0 ? defaultConnectionTimeout : request.d->timeout;
    try {
        Timeout t(timeout);
        connection = connectionForUrl(url, &error);
    } catch (TimeoutException &) {
        response.d->error.reset(new class RequestTimeout());
        return response;
    }
    if (error != nullptr) {
        response.d->error.reset(error);
        return response;
    }

    if (request.d->version == HttpVersion::Unknown) {
        request.d->version = defaultVersion;
    }
    QByteArray versionBytes;
    if (request.d->version == HttpVersion::Http1_0) {
        versionBytes = "HTTP/1.0";
    } else if (request.d->version == HttpVersion::Http1_1) {
        versionBytes = "HTTP/1.1";
//    } else if(request.d->version == HttpVersion::Http2_0) {
//        versionBytes = "HTTP/2.0";
    } else {
        if (debugLevel > 0) {
            qDebug() << "invalid http version." << request.d->version;
        }
        response.d->error.reset(new UnsupportedVersion());
        return response;
    }

    QByteArrayList lines;
    QByteArray resourcePath = url.toEncoded(QUrl::RemoveAuthority | QUrl::RemoveFragment | QUrl::RemoveScheme);
    if (resourcePath.isEmpty()) {
        resourcePath = "/";
    }
    const QByteArray &commandLine = request.d->method.toUpper().toUtf8() + QByteArray(" ") +
            resourcePath + QByteArray(" ") + versionBytes + QByteArray("\r\n");
    lines.append(commandLine);
    for (int i = 0;i < allHeaders.size(); ++i) {
        const HttpHeader &header = allHeaders.at(i);
        lines.append(header.name.toUtf8() + QByteArray(": ") + header.value + QByteArray("\r\n"));
    }
    lines.append(QByteArray("\r\n"));
    if (debugLevel > 0) {
        qDebug() << "sending headers:" << lines.join();
    }
    if (!connection->sendall(lines.join())) {
        response.d->error.reset(new ConnectionError());
        return response;
    }

    if (!request.d->body.isEmpty()) {
        if (debugLevel > 1) {
            qDebug() << "sending body:" << request.d->body;
        }
        if (!connection->sendall(request.d->body)) {
            response.d->error.reset(new ConnectionError());
            return response;
        }
    }

    HeaderSplitter headerSplitter(connection);
    HeaderSplitter::Error headerSplitterError;

    // parse first line.
    QByteArray firstLine = headerSplitter.nextLine(&headerSplitterError);
    error = toRequestError(headerSplitterError);
    if (error != nullptr) {
        response.d->error.reset(error);
        return response;
    }
    QStringList commands = QString::fromLatin1(firstLine).split(QRegExp("\\s+"));
    if (commands.size() < 3) {
        response.d->error.reset(new InvalidHeader());
        return response;
    }
    if (commands.at(0) == QStringLiteral("HTTP/1.0")) {
        response.d->version = Http1_0;
    } else if (commands.at(0) == QStringLiteral("HTTP/1.1")) {
        response.d->version = Http1_1;
    } else {
        response.d->error.reset(new InvalidHeader());
        return response;
    }
    bool ok;
    response.d->statusCode = commands.at(1).toInt(&ok);
    if (!ok) {
        response.d->error.reset(new InvalidHeader());
        return response;
    }
    response.d->statusText = commands.mid(2).join(' ');

    // parse headers.
    const int MaxHeaders = 64;
    QList<HttpHeader> headers = headerSplitter.headers(MaxHeaders, &headerSplitterError);
    if (headerSplitterError != HeaderSplitter::NoError) {
        response.d->error.reset(toRequestError(headerSplitterError));
        return response;
    } else {
        response.setHeaders(headers);
        if(debugLevel > 0)  {
            for (const HttpHeader &header: headers) {
                qDebug() << "receiving header: " << header.name << header.value;
            }
        }
    }

    // merge cookies.
    if (response.hasHeader(QStringLiteral("Set-Cookie"))) {
        for (const QByteArray &value: response.multiHeader(QStringLiteral("Set-Cookie"))) {
            const QList<QNetworkCookie> &cookies = QNetworkCookie::parseCookies(value);
            if(debugLevel > 0 && !cookies.isEmpty()) {
                qDebug() << "receiving cookie:" << cookies[0].toRawForm();
            }
            response.d->cookies.append(cookies);
        }
        cookieJar.setCookiesFromUrl(response.d->cookies, response.d->url);
    }

    // read body.
    response.d->body = headerSplitter.buf;
    response.d->stream = connection;
    if (!request.streamResponse()) {
        const QByteArray &body = response.body();
        if (!response.d->error.isNull()) {
            return response;
        }
        if(debugLevel > 1 && !body.isEmpty()) {
            qDebug() << "receiving body:" << body;
        }
        response.d->stream.clear();
        if (response.d->statusCode == 200 && response.header(HttpResponse::ConnectionHeader).toLower() == "keep-alive") {
            recycle(response.d->url, connection);
        }
    }

    // response.d->statusCode < 200 is not error.
    if (response.d->statusCode >= 400) {
        response.d->error.reset(new HTTPError(response.d->statusCode));
    } else {
        if ((request.method() == "GET"
             || request.method() == "HEAD"
             || request.method() == "OPTION")
                && !cacheManager.isNull()
                && !request.streamResponse()
                ) {
            bool doCache = true;
            const QByteArray &requestHeader = request.header(HttpResponse::CacheControlHeader);
            if (requestHeader.contains("no-cache") || requestHeader.contains("no-store")) {
                doCache = false;
            }
            const QByteArray &responseHeader = response.header(HttpResponse::CacheControlHeader);
            if (responseHeader.contains("no-cache") || responseHeader.contains("no-store")) {
                doCache = false;
            }
            if (doCache) {
                cacheManager->addResponse(response);
            }
        }
    }
    return response;
}


QList<HttpHeader> HttpSessionPrivate::makeHeaders(HttpRequest &request, const QUrl &url)
{
    QList<HttpHeader> allHeaders = request.allHeaders();

    if (!request.hasHeader(QStringLiteral("Connection")) && request.version() == Http1_1) {
        allHeaders.prepend(HttpHeader(QStringLiteral("Connection"), QByteArray("keep-alive")));
    }
    if (!request.hasHeader(QStringLiteral("Content-Length")) && !request.d->body.isEmpty()) {
        allHeaders.prepend(HttpHeader(QStringLiteral("Content-Length"), QByteArray::number(request.d->body.size())));
    }
    if (!request.hasHeader(QStringLiteral("User-Agent"))) {
        if (request.userAgent().isEmpty()) {
            allHeaders.prepend(HttpHeader(QStringLiteral("User-Agent"), defaultUserAgent.toUtf8()));
        } else {
            allHeaders.prepend(HttpHeader(QStringLiteral("User-Agent"), request.userAgent().toUtf8()));
        }
    }
    if (!request.hasHeader(QStringLiteral("Host"))) {
        QString httpHost = url.host();
        if(url.port() != -1) {
            httpHost += QStringLiteral(":") + QString::number(url.port());
        }
        allHeaders.prepend(HttpHeader(QStringLiteral("Host"), httpHost.toUtf8()));
    }
    if (!request.hasHeader(QStringLiteral("Accept"))) {
        allHeaders.append(HttpHeader(QStringLiteral("Accept"), QByteArray("*/*")));
    }
    if (!request.hasHeader(QStringLiteral("Accept-Language"))) {
        allHeaders.append(HttpHeader(QStringLiteral("Accept-Language"), QByteArray("en-US,en;q=0.5")));
    }
//    if(!request.hasHeader(QStringLiteral("Accept-Encoding"))) {
//        allHeaders.append(HttpHeader(QStringLiteral("Accept-Encoding"), QByteArray("deflate")));
//    }
    if (!request.d->cookies.isEmpty() && !request.hasHeader(QStringLiteral("Cookies"))) {
        QByteArray result;
        bool first = true;
        for (const QNetworkCookie &cookie: request.d->cookies) {
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
    if (cookies.isEmpty()) {
        return;
    }
    cookies.append(request.d->cookies);
    request.d->cookies = cookies;
}


void setProxySwitcher(HttpSession *session, QSharedPointer<BaseProxySwitcher> switcher)
{
    if (!switcher.isNull()) {
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


HttpResponse HttpSession::get(const QUrl &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::get(const QUrl &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::get(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setHeaders(headers);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::get(const QUrl &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::get(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::get(const QString &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::get(const QString &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::get(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::get(const QString &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::get(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("GET"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::head(const QUrl &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::head(const QUrl &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::head(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::head(const QUrl &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::head(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::head(const QString &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::head(const QString &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::head(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::head(const QString &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::head(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("HEAD"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::options(const QUrl &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::options(const QUrl &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::options(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::options(const QUrl &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::options(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::options(const QString &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::options(const QString &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::options(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::options(const QString &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::options(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("OPTIONS"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::delete_(const QUrl &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::delete_(const QUrl &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::delete_(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::delete_(const QUrl &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}

HttpResponse HttpSession::delete_(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::delete_(const QString &url)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    return send(request);
}


HttpResponse HttpSession::delete_(const QString &url, const QMap<QString, QString> &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::delete_(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::delete_(const QString &url, const QUrlQuery &query)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    return send(request);
}


HttpResponse HttpSession::delete_(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("DELETE"));
    request.setUrl(url);
    request.setQuery(query);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}



HttpResponse HttpSession::post(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}



HttpResponse HttpSession::post(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::post(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("POST"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);}


HttpResponse HttpSession::patch(const QUrl &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::patch(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PATCH"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}

HttpResponse HttpSession::put(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QByteArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonDocument &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonObject &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonArray &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QMap<QString, QString> &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QUrlQuery &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const FormData &body)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


HttpResponse HttpSession::put(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers)
{
    HttpRequest request;
    request.setMethod(QStringLiteral("PUT"));
    request.setUrl(url);
    request.setBody(body);
    request.setHeaders(headers);
    return send(request);
}


inline bool isRedirect(int httpCode)
{
    switch (httpCode)
    {
    case 300: // HTTP_MULT_CHOICE
    case 301: // HTTP_MOVED_PERM
    case 302: // HTTP_MOVED_TEMP
    case 303: // HTTP_SEE_OTHER
    case 307: // HTTP_TEMP_REDIRECT
    case 308: // HTTP_PERM_REDIRECT
        return true;
    default:
        return false;
    }
}


HttpResponse HttpSession::send(HttpRequest &request)
{
    Q_D(HttpSession);
    HttpResponse response = d->send(request);
    QList<HttpResponse> history;

    if (request.maxRedirects() > 0) {
        int tries = 0;
        while (isRedirect(response.statusCode())) {
            if (tries > request.maxRedirects()) {
                response.setError(new TooManyRedirects());
                return response;
            }
            HttpRequest newRequest;
            if (response.statusCode() == 303 || response.statusCode() == 307) {
                newRequest.setMethod(request.method());
            } else {
                newRequest.setMethod(QStringLiteral("GET")); // not rfc behavior, but many browser do this.
            }
            newRequest.setUrl(request.url().resolved(response.getLocation()));
            if (!newRequest.url().isValid()) {
                response.setError(new InvalidURL());
                return response;
            }
            HttpResponse newResponse = d->send(newRequest);
            history.append(response);
            response = newResponse;
            ++tries;
        }
    }
    response.setHistory(history);
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
    for (int i = 0; i < cookies.size(); ++i) {
        const QNetworkCookie &cookie = cookies.at(i);
        if (cookie.name() == name) {
            return cookie;
        }
    }
    return QNetworkCookie();
}


void HttpSession::setMaxConnectionsPerServer(int maxConnectionsPerServer)
{
    Q_D(HttpSession);
    if (maxConnectionsPerServer <= 0) {
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


float HttpSession::defaultConnnectionTimeout() const
{
    Q_D(const HttpSession);
    return d->defaultConnectionTimeout;
}


void HttpSession::setDefaultConnectionTimeout(float timeout)
{
    Q_D(HttpSession);
    d->defaultConnectionTimeout = timeout;
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


QSharedPointer<HttpCacheManager> HttpSession::cacheManager() const
{
    Q_D(const HttpSession);
    return d->cacheManager;
}


void HttpSession::setCacheManager(QSharedPointer<HttpCacheManager> cacheManager)
{
    Q_D(HttpSession);
    d->cacheManager = cacheManager;
}


HttpCacheManager::HttpCacheManager()
{
}


HttpCacheManager::~HttpCacheManager()
{
}


bool HttpCacheManager::addResponse(const HttpResponse &response)
{
    const QString &url = response.url().toString();
    int statusCode = response.statusCode();
    const QString &statusText = response.statusText();
    const QList<HttpHeader> headers = response.allHeaders();
    const QByteArray &body = response.body();
    QByteArray bs;
    QDataStream ds(&bs, QIODevice::WriteOnly);
    ds << statusCode << statusText << headers << body;
    if (ds.status() != QDataStream::Ok) {
        return false;
    }
    return store(url, bs);
}


bool HttpCacheManager::getResponse(HttpResponse *response)
{
    const QString &url = response->url().toString();
    if (url.isEmpty()) {
        return false;
    }
    const QByteArray &bs = load(url);
    if (bs.isEmpty()) {
        return false;
    }
    QDataStream ds(bs);
    int statusCode;
    QString statusText;
    QList<HttpHeader> headers;
    QByteArray body;
    ds >> statusCode >> statusText >> headers >> body;
    if (ds.status() != QDataStream::Ok) {
        return false;
    }
    response->setStatusCode(statusCode);
    response->setStatusText(statusText);
    response->setHeaders(headers);
    response->setBody(body);
    return true;
}


bool HttpCacheManager::store(const QString &, const QByteArray &)
{
    return false;
}


QByteArray HttpCacheManager::load(const QString &)
{
    return QByteArray();
}


class HttpMemoryCacheManagerPrivate
{
public:
    HttpMemoryCacheManagerPrivate()
        :expireTime(60 * 60 * 24) // one day
    {}
public:
    QMap<QString, QByteArray> cache;
    float expireTime;
};


HttpMemoryCacheManager::HttpMemoryCacheManager()
    :d_ptr(new HttpMemoryCacheManagerPrivate())
{

}


HttpMemoryCacheManager::~HttpMemoryCacheManager()
{
    delete d_ptr;
}


float HttpMemoryCacheManager::expireTime() const
{
    Q_D(const HttpMemoryCacheManager);
    return d->expireTime;
}


void HttpMemoryCacheManager::setExpireTime(float expireTime)
{
    Q_D(HttpMemoryCacheManager);
    d->expireTime = expireTime;
}


bool HttpMemoryCacheManager::store(const QString &url, const QByteArray &data)
{
    Q_D(HttpMemoryCacheManager);
    d->cache.insert(url, data);
    return true;
}


QByteArray HttpMemoryCacheManager::load(const QString &url)
{
    Q_D(HttpMemoryCacheManager);
    return d->cache.value(url);
}



RequestError::~RequestError()
{}


QString RequestError::what() const
{
    return QStringLiteral("An HTTP error occurred.");
}


QString HTTPError::what() const
{
    return QStringLiteral("server respond error.");
}


QString ConnectionError::what() const
{
    return QStringLiteral("A Connection error occurred.");
}


QString ProxyError::what() const
{
    return QStringLiteral("A proxy error occurred.");
}


QString SSLError::what() const
{
    return QStringLiteral("A SSL error occurred.");
}


QString RequestTimeout::what() const
{
    return QStringLiteral("The request timed out.");
}


QString ConnectTimeout::what() const
{
    return QStringLiteral("The request timed out while trying to connect to the remote server.");
}


QString ReadTimeout::what() const
{
    return QStringLiteral("The server did not send any data in the allotted amount of time.");
}


QString URLRequired::what() const
{
    return QStringLiteral("A valid URL is required to make a request.");
}


QString TooManyRedirects::what() const
{
    return QStringLiteral("Too many redirects.");
}


QString MissingSchema::what() const
{
    return QStringLiteral("The URL schema (e.g. http or https) is missing.");
}


QString InvalidScheme::what() const
{
    return QStringLiteral("The URL schema can not be handled.");
}


QString UnsupportedVersion::what() const
{
    return QStringLiteral("The HTTP version is not supported yet.");
}

QString InvalidURL::what() const
{
    return QStringLiteral("The URL provided was somehow invalid.");
}


QString InvalidHeader::what() const
{
    return QStringLiteral("Can not parse the http header.");
}

QString ChunkedEncodingError::what() const
{
    return QStringLiteral("The server declared chunked encoding but sent an invalid chunk.");
}


QString ContentDecodingError::what() const
{
    return QStringLiteral("Failed to decode response content");
}


QString StreamConsumedError::what() const
{
    return QStringLiteral("The content for this response was already consumed");
}


QString RetryError::what() const
{
    return QStringLiteral("Custom retries logic failed");
}


QString UnrewindableBodyError::what() const
{
    return QStringLiteral("Requests encountered an error when trying to rewind a body");
}

QTNETWORKNG_NAMESPACE_END
