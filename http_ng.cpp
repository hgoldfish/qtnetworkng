#include <QUrl>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonParseError>
#include "http_ng_p.h"
#include "socket_ng.h"


Request::Request()
    :maxBodySize(1024 * 1024 * 8)
{

}

Request::~Request()
{

}

void HeaderOperationMixin::setContentLength(qint64 contentLength)
{
    headers.insert(QString::fromUtf8("Content-Length"), QString::number(contentLength));
}

qint64 HeaderOperationMixin::getContentLength()
{
    bool ok;
    QString s = headers.value(QString::fromUtf8("Content-Length"));
    qint64 l = s.toULongLong(&ok);
    if(ok) {
        return l;
    } else {
        return -1;
    }
}

void HeaderOperationMixin::setContentType(const QString &contentType)
{
    headers.insert(QString::fromUtf8("Content-Type"), contentType);
}

QString HeaderOperationMixin::getContentType()
{
    return headers.value(QString::fromUtf8("Content-Type"), QString::fromUtf8("text/html"));
}

void HeaderOperationMixin::setHeader(const QString &name, const QString &value)
{
    headers.insert(name, value);
}

QString HeaderOperationMixin::getHeader(const QString &name)
{
    return headers.value(name);
}

QString Response::text()
{
    return QString::fromUtf8(body);
}

QJsonDocument Response::json()
{
    QJsonParseError error;
    QJsonDocument jsonDocument = QJsonDocument::fromJson(body, &error);
    if(error.error != QJsonParseError::NoError) {
        return QJsonDocument();
    } else {
        return jsonDocument;
    }
}

QString Response::html()
{
    return QString::fromUtf8(body);
}


SessionPrivate::SessionPrivate(Session *q_ptr)
    :q_ptr(q_ptr)
{
    defaultUserAgent = QString::fromUtf8("Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0");
}

SessionPrivate::~SessionPrivate()
{

}

void SessionPrivate::setDefaultUserAgent(const QString &userAgent)
{
    defaultUserAgent = userAgent;
}


struct HeaderSplitter
{
    QSocketNg *connection;
    QByteArray buf;

    HeaderSplitter(QSocketNg *connection)
        :connection(connection) {}

    QByteArray nextLine()
    {
        const int MaxLineLength = 1024;
        QByteArray line; line.reserve(MaxLineLength);
        bool expectingLineBreak = false;

        for(int i = 0; i < MaxLineLength; ++i) {
            if(buf.isEmpty()) {
                buf = connection->recv(64);
                if(buf.isEmpty()) {
                    throw InvalidHeader();
                }
            }
            int j = 0;
            for(; j < buf.size() && i < MaxLineLength; ++j, ++i) {
                char c = buf.at(j);
                if(c == '\n') {
                    if(!expectingLineBreak) {
                        throw InvalidHeader();
                    }
                    buf.remove(0, j + 1);
                    return line;
                } else if(c == '\r') {
                    expectingLineBreak = true;
                } else {
                    line.append(c);
                }
            }
            buf.remove(0, j + 1);
        }
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


Response SessionPrivate::send(Request &request)
{
    QUrl url(request.url);
    if(url.scheme() != "http") {
        throw ConnectionError();
    }
    if(!request.query.isEmpty()) {
        QUrlQuery query;
        for(auto itor = request.query.constBegin(); itor != request.query.constEnd(); ++itor) {
            query.addQueryItem(itor.key(), itor.value());
        }
        url.setQuery(query);
        request.url = url.toString();
    }

    mergeCookies(request, url);
    QMap<QString, QString> allHeaders = makeHeaders(request, url);

    QSocketNg connection;
    if(!connection.connect(url.host(), url.port(80))) {
        throw ConnectionError();
    }

    QByteArrayList lines;
    QByteArray resourcePath = url.toEncoded(QUrl::RemoveAuthority | QUrl::RemoveFragment | QUrl::RemoveScheme);
    qDebug() << resourcePath;
    lines.append(request.method.toUpper().toUtf8() + QByteArray(" ") + resourcePath + QByteArray(" HTTP/1.0\r\n"));
    for(auto itor = allHeaders.constBegin(); itor != allHeaders.constEnd(); ++itor) {
        lines.append(itor.key().toUtf8() + QByteArray(": ") + itor.value().toUtf8() + QByteArray("\r\n"));
    }
    lines.append(QByteArray("\r\n"));
    connection.sendall(lines.join());

    if(!request.body.isEmpty()) {
        connection.sendall(request.body);
    }

    Response response;
    response.request = request;

    HeaderSplitter splitter(&connection);

    QByteArray firstLine = splitter.nextLine();

    QList<QByteArray> commands = splitBytes(firstLine, ' ', 2);
    if(commands.size() != 3) {
        throw InvalidHeader();
    }
    if(commands.at(0) != QByteArray("HTTP/1.0") && commands.at(0) != QByteArray("HTTP/1.1")) {
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
        QString headerValue = QString::fromUtf8(headerParts[1]).trimmed();
//        if(response.headers.contains(headerName)) {
//            throw InvalidHeader();
//        }
        response.headers.insert(headerName, headerValue);
    }

    if(!splitter.buf.isEmpty()) {
        response.body = splitter.buf;
    }

    qint64 contentLength = response.getContentLength();
    if(contentLength > 0) {
        if(contentLength > request.maxBodySize) {
            // warning!
        } else {
            while(response.body.size() < contentLength) {
                qint64 leftBytes = qMin((qint64) 1024 * 8, contentLength - response.body.size());
                QByteArray t = connection.recv(leftBytes);
                if(t.isEmpty()) {
                    throw ConnectionError();
                }
                response.body.append(t);
            }
        }
    } else if(response.getContentLength() < 0){
        while(response.body.size() < request.maxBodySize) {
            QByteArray t = connection.recv(1024 * 8);
            if(t.isEmpty()) {
                break;
            }
            response.body.append(t);
        }
    } else {
        if(!response.body.isEmpty()) {
            // warning!
        }
    }
    return response;
}


QMap<QString, QString> SessionPrivate::makeHeaders(Request &request, const QUrl &url)
{
    QMap<QString, QString> allHeaders = request.headers;
    if(!allHeaders.contains(QString::fromUtf8("Host"))) {
        QString httpHost = url.host();
        if(url.port() != -1) {
            httpHost += QString(":") + QString::number(url.port());
        }
        allHeaders.insert(QString::fromUtf8("Host"), httpHost);
    }

    if(!allHeaders.contains(QString::fromUtf8("User-Agent"))) {
        allHeaders.insert(QString::fromUtf8("User-Agent"), defaultUserAgent);
    }

    if(!allHeaders.contains(QString::fromUtf8("Accept"))) {
        allHeaders.insert(QString::fromUtf8("Accept"), QString::fromUtf8("*/*"));
    }

    if(!allHeaders.contains(QString::fromUtf8("Content-Length")) && !request.body.isEmpty()) {
        allHeaders.insert(QString::fromUtf8("Content-Length"), QString::number(request.body.size()));
    }
    if(!allHeaders.contains(QString::fromUtf8("Accept-Language"))) {
        allHeaders.insert(QString::fromUtf8("Accept-Language"), QString::fromUtf8("en-US,en;q=0.5"));
    }
    return allHeaders;
}

void SessionPrivate::mergeCookies(Request &request, const QUrl &url)
{
    Q_UNUSED(request);
    Q_UNUSED(url);
}

Session::Session()
    :d_ptr(new SessionPrivate(this)) {}


Session::~Session()
{
    delete d_ptr;
}

Response Session::get(const QString &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("GET");
    request.url = url;
    request.headers = headers;
    request.query = query;
    return send(request);
}

Response Session::head(const QString &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("HEAD");
    request.url = url;
    request.headers = headers;
    request.query = query;
    return send(request);
}

Response Session::options(const QString &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("OPTIONS");
    request.url = url;
    request.headers = headers;
    request.query = query;
    return send(request);
}

Response Session::delete_(const QString &url, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("DELETE");
    request.url = url;
    request.headers = headers;
    request.query = query;
    return send(request);
}

Response Session::post(const QString &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("POST");
    request.url = url;
    request.headers = headers;
    request.query = query;
    request.body = body;
    return send(request);
}

Response Session::put(const QString &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("PUT");
    request.url = url;
    request.headers = headers;
    request.query = query;
    request.body = body;
    return send(request);
}

Response Session::patch(const QString &url, const QByteArray &body, COMMON_PARAMETERS_WITHOUT_DEFAULT)
{
    Q_UNUSED(allowRedirects);
    Q_UNUSED(verify);
    Request request;
    request.method = QString::fromLatin1("PATCH");
    request.url = url;
    request.headers = headers;
    request.query = query;
    request.body = body;
    return send(request);
}

Response Session::send(Request &request)
{
    Q_D(Session);
    return d->send(request);
}


RequestException::~RequestException()
{}


QString RequestException::what() const throw()
{
    return QString::fromUtf8("An HTTP error occurred.");
}


QString HTTPError::what() const throw()
{
    return QString::fromUtf8("server respond error.");
}


QString ConnectionError::what() const throw()
{
    return QString::fromUtf8("A Connection error occurred.");
}


QString ProxyError::what() const throw()
{
    return QString::fromUtf8("A proxy error occurred.");
}


QString SSLError::what() const throw()
{
    return QString::fromUtf8("A SSL error occurred.");
}


QString RequestTimeout::what() const throw()
{
    return QString::fromUtf8("The request timed out.");
}


QString ConnectTimeout::what() const throw()
{
    return QString::fromUtf8("The request timed out while trying to connect to the remote server.");
}


QString ReadTimeout::what() const throw()
{
    return QString::fromUtf8("The server did not send any data in the allotted amount of time.");
}


QString URLRequired::what() const throw()
{
    return QString::fromUtf8("A valid URL is required to make a request.");
}


QString TooManyRedirects::what() const throw()
{
    return QString::fromUtf8("Too many redirects.");
}


QString MissingSchema::what() const throw()
{
    return QString::fromUtf8("The URL schema (e.g. http or https) is missing.");
}


QString InvalidSchema::what() const throw()
{
    return QString::fromUtf8("The URL schema can not be handled.");
}


QString InvalidURL::what() const throw()
{
    return QString::fromUtf8("The URL provided was somehow invalid.");
}


QString InvalidHeader::what() const throw()
{
    return QString::fromUtf8("Can not parse the http header.");
}

QString ChunkedEncodingError::what() const throw()
{
    return QString::fromUtf8("The server declared chunked encoding but sent an invalid chunk.");
}


QString ContentDecodingError::what() const throw()
{
    return QString::fromUtf8("Failed to decode response content");
}


QString StreamConsumedError::what() const throw()
{
    return QString::fromUtf8("The content for this response was already consumed");
}


QString RetryError::what() const throw()
{
    return QString::fromUtf8("Custom retries logic failed");
}



