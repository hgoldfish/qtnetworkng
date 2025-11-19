#include <QtCore/qmimedatabase.h>
#include <QtCore/qcryptographichash.h>
#include <stdio.h>
#include "../include/httpd.h"
#ifdef QTNG_HAVE_ZLIB
#include "../include/gzip.h"
#endif
#include "debugger.h"

QTNG_LOGGER("qtng.httpd")

QTNETWORKNG_NAMESPACE_BEGIN

static const QString DEFAULT_ERROR_MESSAGE =
        QString::fromLatin1("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n"
                            "        \"http://www.w3.org/TR/html4/strict.dtd\">\n<html>\n"
                            "    <head>\n"
                            "        <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\n"
                            "        <title>Error response</title>\n"
                            "    </head>\n"
                            "    <body>\n"
                            "        <h1>Error response</h1>\n"
                            "        <p>Error code: %1</p>\n"
                            "        <p>Message: %2.</p>\n"
                            "        <p>Error code explanation: %1 - %3.</p>\n"
                            "    </body>\n"
                            "</html>\n");
static const QString DEFAULT_ERROR_CONTENT_TYPE = QString::fromLatin1("text/html;charset=utf-8");

//#define DEBUG_HTTP_PROTOCOL 1

BaseHttpRequestHandler::BaseHttpRequestHandler()
    : version(Http1_1)
    , serverVersion(Http1_1)
    , requestTimeout(60 * 60)
    , maxBodySize(1024 * 1024 * 32)
    , closeConnection(Maybe)
{
}

void BaseHttpRequestHandler::handle()
{
    do {
        closeConnection = Maybe;
        handleOneRequest();
    } while (closeConnection == No && !request.isNull());
    // do not close the request, because it can be keep by other module.
}

void BaseHttpRequestHandler::handleOneRequest()
{
    try {
        Timeout timeout(requestTimeout);
        if (!parseRequest()) {
            return;
        }
        doMethod();
    } catch (TimeoutException &) {
        QLatin1String message("HTTP request handler is timeout.");
        logError(HttpStatus::Gone, message, message);
        closeConnection = Yes;
    }
}

QString BaseHttpRequestHandler::normalizePath(const QString &path)
{
    QUrl url = QUrl::fromEncoded(path.toLatin1(), QUrl::StrictMode);
    return url.toString(QUrl::NormalizePathSegments);
}

bool BaseHttpRequestHandler::parseRequest()
{
    bool done = false;
    const QByteArray &buf = tryToHandleMagicCode(done);
    if (done) {
        return false;
    }
    HeaderSplitter headerSplitter(request, buf);
    HeaderSplitter::Error headerSplitterError;
    QByteArray firstLine = headerSplitter.nextLine(&headerSplitterError);
    if (firstLine.isEmpty() || headerSplitterError != HeaderSplitter::NoError) {
        return false;
    }
#ifdef DEBUG_HTTP_PROTOCOL
    qtng_debug << "first line is" << firstLine;
#endif

    const QString &commandLine = QString::fromLatin1(firstLine);
    const QStringList &words = commandLine.split(QRegExp(QLatin1String("\\s+")));
    if (words.isEmpty()) {
        return false;
    }
    if (words.size() == 3) {
        method = words.at(0);
        path = words.at(1);
        const QString &versionStr = words.at(2);
        if (versionStr == QLatin1String("HTTP/1.0")) {
            version = Http1_0;
        } else if (versionStr == QLatin1String("HTTP/1.1")) {
            version = Http1_1;
        } else {
            sendError(HttpStatus::BadRequest, QString::fromLatin1("Bad request version (%1").arg(versionStr));
            return false;
        }
    } else if (words.size() == 2) {
        method = words.at(0);
        path = words.at(1);
        version = Http1_0;
    } else if (words.isEmpty()) {
        return false;
    } else {
        sendError(HttpStatus::BadRequest, QString::fromLatin1("Bad request syntax (%1)").arg(commandLine));
        return false;
    }
    method = method.toUpper();
    if (path.isEmpty()) {
        sendError(HttpStatus::BadRequest, QString::fromLatin1("Bad request path (%1)").arg(path));
        return false;
    }

    const int MaxHeaders = 64;
    QList<HttpHeader> headers = headerSplitter.headers(MaxHeaders, &headerSplitterError);
    switch (headerSplitterError) {
    case HeaderSplitter::EncodingError:
        sendError(HttpStatus::BadRequest, QString::fromLatin1("Bad request invalid header"));
        return false;
    case HeaderSplitter::ConnectionError:
        return false;
    case HeaderSplitter::ExhausedMaxLine:
        sendError(HttpStatus::RequestHeaderFieldsTooLarge, QString::fromLatin1("Too much headers"));
        return false;
    case HeaderSplitter::LineTooLong:
        sendError(HttpStatus::RequestHeaderFieldsTooLarge, QString::fromLatin1("Line too long"));
        return false;
    default:
        break;
    }
    setHeaders(headers);
#ifdef DEBUG_HTTP_PROTOCOL
    for (const HttpHeader &header : headers) {
        qtng_debug << "header(" << header.name << ") = " << header.value;
    }
#endif
    const QByteArray &connectionType = header(ConnectionHeader);
    if (connectionType.toLower() == QByteArray("close") || method.toUpper() == QLatin1String("CONNECT")) {
        closeConnection = Yes;
    } else if (connectionType.toLower() == QByteArray("keep-alive") && version >= Http1_1 && serverVersion >= Http1_1) {
        closeConnection = Maybe;
    } else {
        closeConnection = Yes;
    }
    body = headerSplitter.buf;
    return true;
}

QByteArray BaseHttpRequestHandler::tryToHandleMagicCode(bool &done)
{
    done = false;
    return QByteArray();
}

void BaseHttpRequestHandler::doMethod()
{
    if (method == QLatin1String("GET")) {
        doGET();
    } else if (method == QLatin1String("POST")) {
        doPOST();
    } else if (method == QLatin1String("PUT")) {
        doPUT();
    } else if (method == QLatin1String("PATCH")) {
        doPATCH();
    } else if (method == QLatin1String("DELETE")) {
        doDELETE();
    } else if (method == QLatin1String("HEAD")) {
        doHEAD();
    } else if (method == QLatin1String("OPTIONS")) {
        doOPTIONS();
    } else if (method == QLatin1String("TRACE")) {
        doTRACE();
    } else if (method == QLatin1String("CONNECT")) {
        doCONNECT();
    } else {
        sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
    }
}

void BaseHttpRequestHandler::doGET()
{
    QByteArray body("hello, world!");
    sendResponse(HttpStatus::OK);
    if (!body.isEmpty()) {
        sendHeader("Content-Type", "text/html");
        sendHeader("Content-Length", QByteArray::number(body.size()));
    }
    if (!endHeader()) {
        return;
    }
    if (!body.isEmpty()) {
        request->sendall(body);
    }
}

void BaseHttpRequestHandler::doPOST()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doPUT()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doDELETE()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doPATCH()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doHEAD()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doOPTIONS()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doTRACE()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doCONNECT()
{
    sendError(HttpStatus::NotImplemented, QString::fromLatin1("Unsupported method %1").arg(method));
}

bool BaseHttpRequestHandler::sendError(HttpStatus status, const QString &message)
{
    QString shortMessage, longMessage;
    bool ok = toMessage(status, &shortMessage, &longMessage);
    if (!ok) {
        shortMessage = longMessage = QString::fromLatin1("???");
    }
    if (!message.isEmpty()) {
        longMessage = message;
    }
    logError(status, shortMessage, longMessage);
    sendCommandLine(status, shortMessage);
    sendHeader("Server", serverName().toUtf8());
    sendHeader("Date", dateTimeString().toUtf8());
    QByteArray body;
    if (status >= 200 && status != HttpStatus::NoContent && status != HttpStatus::ResetContent
        && status != HttpStatus::NotModified) {
        const QString &html = errorMessage(status, shortMessage, longMessage);
        body = html.toUtf8();
        sendHeader("Content-Length", QByteArray::number(body.size()));
        sendHeader("Content-Type", errorMessageContentType().toUtf8());
    }
    if (!endHeader()) {
        return false;
    }
    if (method.toUpper() != QLatin1String("HEAD") && !body.isEmpty()) {
        return request->sendall(body) == body.size();
    }
    return true;
}

bool BaseHttpRequestHandler::sendResponse(HttpStatus status, const QString &message)
{
    QString shortMessage, longMessage;
    bool ok = toMessage(status, &shortMessage, &longMessage);
    if (!ok) {
        shortMessage = longMessage = QString::fromLatin1("???");
    }
    if (!message.isEmpty()) {
        longMessage = message;
    }
    logRequest(status, 0);
    sendCommandLine(status, shortMessage);
    sendHeader(QByteArray("Server"), serverName().toUtf8());
    sendHeader(QByteArray("Date"), dateTimeString().toUtf8());
    return true;
}

QString BaseHttpRequestHandler::errorMessage(HttpStatus status, const QString &shortMessage, const QString &longMessage)
{
    return DEFAULT_ERROR_MESSAGE.arg(static_cast<int>(status)).arg(shortMessage).arg(longMessage);
}

QString BaseHttpRequestHandler::errorMessageContentType()
{
    return DEFAULT_ERROR_CONTENT_TYPE;
}

void BaseHttpRequestHandler::sendCommandLine(HttpStatus status, const QString &shortMessage)
{
    QString versionStr;
    if (serverVersion == Http1_0 || version == Http1_0) {
        versionStr = QString::fromLatin1("HTTP/1.0");
    } else {
        versionStr = QString::fromLatin1("HTTP/1.1");
    }
    const QString &firstLine =
            QString::fromLatin1("%1 %2 %3\r\n").arg(versionStr).arg(static_cast<int>(status)).arg(shortMessage);
    headerCache.prepend(firstLine.toUtf8());
}

void BaseHttpRequestHandler::sendHeader(const QByteArray &name, const QByteArray &value)
{
    const QByteArray &line = name + ": " + value + "\r\n";
    headerCache.append(line);
    if (name.toLower() == QByteArray("transfer-encoding") && value.toLower() == QByteArray("chunked")) {
        closeConnection = Yes;
    } else if (name.toLower() == QByteArray("connection")) {
        if (value.toLower() == "keep-alive" && closeConnection != Yes) {
            closeConnection = No;
        } else {
            closeConnection = Yes;
        }
    }
}

#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
inline static QByteArray join(const QByteArrayList &lines)
{
    return lines.join();
}
#else
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

bool BaseHttpRequestHandler::endHeader()
{
    if (closeConnection == Maybe) {
        closeConnection = No;
        headerCache.append(QByteArray("Connection: keep-alive\r\n"));
    }
    headerCache.append("\r\n");
    const QByteArray &data = join(headerCache);
    headerCache.clear();
    return request->sendall(data) == data.size();
}

QSharedPointer<FileLike> BaseHttpRequestHandler::bodyAsFile(bool processEncoding)
{
    qint64 contentLength = getContentLength();

    QSharedPointer<FileLike> bodyFile;
    if (contentLength >= 0) {
        if (contentLength >= INT_MAX || (maxBodySize >= 0 && contentLength > maxBodySize)) {
            closeConnection = Yes;
            sendError(HttpStatus::RequestEntityTooLarge);
            return QSharedPointer<FileLike>();
        } else {
            if (body.size() > contentLength) {
                qtng_warning << "request body got too much bytes.";
                bodyFile = FileLike::bytes(body);
            } else if (body.size() < contentLength) {
                bodyFile = QSharedPointer<PlainBodyFile>::create(contentLength, body, request);
            } else {
                bodyFile = FileLike::bytes(body);
            }
        }
    } else {  // if (contentLength < 0) without `Content-Length` header.
        const QByteArray &transferEncodingHeader = header(QString::fromLatin1("Transfer-Encoding"));
        bool isChunked = (transferEncodingHeader.toLower() == QByteArray("chunked"));
        if (isChunked && processEncoding) {
            removeHeader(QString::fromLatin1("Transfer-Encoding"));
            bodyFile = QSharedPointer<ChunkedBodyFile>::create(maxBodySize, body, request);
        } else {
            // if the client does not send content length, it mean no content.
            // this is not the same as client side.
            bodyFile = FileLike::bytes(QByteArray());
        }
    }
    body.clear();

    if (processEncoding) {
        const QByteArray &contentEncodingHeader = header(QString::fromLatin1("Content-Encoding"));
        const QByteArray &transferEncodingHeader = header(QString::fromLatin1("Transfer-Encoding"));
#ifdef QTNG_HAVE_ZLIB
        if (contentEncodingHeader.toLower() == QByteArray("gzip")
            || contentEncodingHeader.toLower() == QByteArray("deflate")) {
            removeHeader(QString::fromLatin1("Content-Encoding"));
            bodyFile = QSharedPointer<GzipFile>::create(bodyFile, GzipFile::Decompress);
        } else if (transferEncodingHeader.toLower() == QByteArray("gzip")
                   || transferEncodingHeader.toLower() == QByteArray("deflate")) {
            removeHeader(QString::fromLatin1("Transfer-Encoding"));
            bodyFile = QSharedPointer<GzipFile>::create(bodyFile, GzipFile::Decompress);
        } else if (transferEncodingHeader.toLower() == QByteArray("qt")) {
            bool ok;
            const QByteArray &compBody = bodyFile->readall(&ok);
            if (!ok) {
                closeConnection = Yes;
                return QSharedPointer<FileLike>();
            }
            removeHeader(QString::fromLatin1("Transfer-Encoding"));
            const QByteArray &decompBody = qUncompress(compBody);
            bodyFile = FileLike::bytes(decompBody);
        } else
#endif
                if (!contentEncodingHeader.isEmpty() || !transferEncodingHeader.isEmpty()) {
            qtng_warning << "unsupported content encoding." << contentEncodingHeader << transferEncodingHeader;
            closeConnection = Yes;
        }
    }
    return bodyFile;
}

bool BaseHttpRequestHandler::readBody()
{
    QSharedPointer<FileLike> bodyFile = bodyAsFile();
    if (bodyFile.isNull()) {
        return false;
    }
    bool ok;
    body = bodyFile->readall(&ok);
    return ok;
}

bool BaseHttpRequestHandler::switchToWebSocket()
{
    if (this->method != QString::fromUtf8("GET")) {
        return false;
    }
    const QByteArray &upgradeHeader = header(UpgradeHeader);
    const QByteArray &connectionHeader = header(ConnectionHeader);
    if (upgradeHeader.toLower() != "websocket" || connectionHeader.toLower() != "upgrade") {
        return false;
    }

    const QByteArray &itsKey = header(QString::fromUtf8("Sec-WebSocket-Key"));
    const QByteArray &itsVersion = header(QString::fromUtf8("Sec-WebSocket-Version"));
    if (itsKey.isEmpty() || itsVersion != "13") {
        return false;
    }

    const QByteArray uuid("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    const QByteArray &t = itsKey + uuid;
    const QByteArray &myKey = QCryptographicHash::hash(t, QCryptographicHash::Sha1).toBase64();

    sendResponse(HttpStatus::SwitchProtocol);
    sendHeader(UpgradeHeader, "websocket");
    sendHeader(ConnectionHeader, "Upgrade");
    sendHeader("Sec-WebSocket-Accept", myKey);

    // it's the responsibility of caller to call endHeader().
    return true;
}

QBYTEARRAYLIST BaseHttpRequestHandler::webSocketProtocols()
{
    const QBYTEARRAYLIST &lines = multiHeader(QString::fromUtf8("Sec-WebSocket-Protocol"));
    QBYTEARRAYLIST result;
    for (const QByteArray &line : lines) {
        const QList<QByteArray> &protocols = line.split(',');
        for (const QByteArray &protocol : protocols) {
            const QByteArray &t = protocol.trimmed();
            if (!t.isEmpty()) {
                result.append(t);
            }
        }
    }
    return result;
}

QString BaseHttpRequestHandler::serverName()
{
    return QString::fromLatin1("QtNetworkNg");
}

QString BaseHttpRequestHandler::dateTimeString()
{
    return QString::fromLatin1(toHttpDate(QDateTime::currentDateTimeUtc()));
}

void BaseHttpRequestHandler::logRequest(HttpStatus status, int bodySize)
{
    QString msg = QString::fromLatin1("%1 %2 %3 %4").arg(method).arg(path).arg(static_cast<int>(status)).arg(bodySize);
    msg = QString::fromLatin1("%1 -- %2 %3")
                  .arg(request->peerAddress().toString())
                  .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
                  .arg(msg);
    printf("%s\n", qPrintable(msg));
}

void BaseHttpRequestHandler::logError(HttpStatus status, const QString &shortMessage, const QString &)
{
    QString msg =
            QString::fromLatin1("%1 %2 %3 %4").arg(method).arg(path).arg(static_cast<int>(status)).arg(shortMessage);
    msg = QString::fromLatin1("%1 -- %2 %3")
                  .arg(request->peerAddress().toString())
                  .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
                  .arg(msg);
    printf("%s\n", qPrintable(msg));
}

Q_GLOBAL_STATIC(QMimeDatabase, mimeDatabase);

QSharedPointer<FileLike> StaticHttpRequestHandler::serveStaticFiles(const QDir &dir, const QString &subPath)
{
    QUrl url = QUrl::fromEncoded(subPath.toLatin1());
    QFileInfo fileInfo = safeJoinPath(dir, url.path()).first;
#ifdef DEBUG_HTTP_PROTOCOL
    qtng_debug << "serve path" << subPath << "from" << fileInfo.absoluteFilePath();
#endif
    if (!fileInfo.exists() && !loadMissingFile(fileInfo)) {
        sendError(HttpStatus::NotFound, QString::fromLatin1("File not found"));
        return QSharedPointer<FileLike>();
    }

    if (fileInfo.isDir()) {
        const QString &p = url.path();
        if (!p.endsWith(QLatin1String("/"))) {
            url.setPath(p + QLatin1String("/"));
            sendResponse(HttpStatus::MovedPermanently);
            sendHeader("Location", url.toEncoded(QUrl::FullyEncoded));
            endHeader();
            return QSharedPointer<FileLike>();
        } else {
            QDir dir(fileInfo.filePath());
            const QFileInfo &t = getIndexFile(dir);
            if (t.isFile()) {
                fileInfo = t;
            } else if (enableDirectoryListing) {
                return listDirectory(dir, p);
            } else {
                sendError(HttpStatus::NotFound, QString::fromLatin1("File Not Found"));
                return QSharedPointer<FileLike>();
            }
        }
    }

    QString contentType;

#ifdef Q_OS_ANDROID
    const QString &ext = fileInfo.completeSuffix().toLower();
    if (ext == QLatin1String("txt")) {
        contentType = QString::fromLatin1("text/plain");
    } else if (ext == QLatin1String("html") || ext == QLatin1String("htm")) {
        contentType = QString::fromLatin1("text/html");
    } else if (ext == QLatin1String("js")) {
        contentType = QString::fromLatin1("application/javascript");
    } else if (ext == QLatin1String("css")) {
        contentType = QString::fromLatin1("text/css");
    } else {
        contentType = QString::fromLatin1("application/octet-stream");
    }
#else
    const QMimeType &ctype = mimeDatabase->mimeTypeForFile(fileInfo);
    if (!ctype.isValid()) {
        contentType = QString::fromLatin1("application/octet-stream");
    } else {
        contentType = ctype.name();
    }
#endif
    QSharedPointer<QFile> f(new QFile(fileInfo.filePath()));
    if (!f->open(QIODevice::ReadOnly)) {
        sendError(HttpStatus::NotFound, QString::fromLatin1("File not found"));
        return QSharedPointer<FileLike>();
    }
    sendResponse(HttpStatus::OK);
    sendHeader(QByteArray("Content-Type"), contentType.toUtf8());
    sendHeader(QByteArray("Content-Length"), QByteArray::number(f->size()));
    sendHeader(QByteArray("Last-Modified"), fileInfo.lastModified().toString(Qt::RFC2822Date).toUtf8());
    if (!endHeader()) {
        return QSharedPointer<FileLike>();
    }
    return FileLike::rawFile(f);
}

QSharedPointer<FileLike> StaticHttpRequestHandler::listDirectory(const QDir &dir, const QString &displayDir)
{
    const QFileInfoList &list = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);
    const QString &title = QString::fromLatin1("Directory listing for ") + displayDir;
    QStringList html;
    html.append(QString::fromLatin1(
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">"));
    html.append(QString::fromLatin1("<html>\n<head>"));
    html.append(QString::fromLatin1("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">"));
    html.append(QString::fromLatin1("<title>%1</title>\n</head>").arg(title));
    html.append(QString::fromLatin1("<body>\n<h1>%1</h1>").arg(title));
    html.append(QString::fromLatin1("<hr>\n<ul>"));
    for (const QFileInfo &entry : list) {
        QString name = entry.fileName();
        QString link = entry.fileName();
        if (entry.isDir()) {
            name.append(QLatin1String("/"));
            link.append(QLatin1String("/"));
        }
        if (entry.isSymLink()) {
            name = entry.fileName() + QString::fromLatin1("@");
            // Note: a link to a directory displays with @ and links with /
        }
        const QString &htmlName = name.toHtmlEscaped();
        const QString &htmlLink = QString::fromLatin1(link.toUtf8().toPercentEncoding("/"));
        html.append(QString::fromLatin1("<li><a href=\"%1\">%2</a></li>").arg(htmlLink).arg(htmlName));
    }
    html.append(QString::fromLatin1("</ul>\n<hr>\n</body>\n</html>"));
    const QByteArray &data = html.join(QLatin1String("\n")).toUtf8();
    sendResponse(HttpStatus::OK);
    sendHeader(QByteArray("Content-Type"), QByteArray("text/html; charset=utf-8"));
    sendHeader(QByteArray("Content-Length"), QByteArray::number(data.size()));
    if (!endHeader()) {
        return QSharedPointer<FileLike>();
    }
    return FileLike::bytes(data);
}

bool StaticHttpRequestHandler::loadMissingFile(const QFileInfo &)
{
    return false;
}

QFileInfo StaticHttpRequestHandler::getIndexFile(const QDir &dir)
{
    if (dir.exists(QString::fromLatin1("index.html"))) {
        return dir.filePath(QString::fromLatin1("index.html"));
    } else if (dir.exists(QString::fromLatin1("index.htm"))) {
        return dir.filePath(QString::fromLatin1("index.htm"));
    } else {
        return QFileInfo();
    }
}

void SimpleHttpRequestHandler::doGET()
{
    QSharedPointer<FileLike> f = serveStaticFiles(rootDir, path);
    if (!f.isNull()) {
        if (!sendfile(f, request)) {
            request->close();
        }
        f->close();
    }
}

void SimpleHttpRequestHandler::doHEAD()
{
    QSharedPointer<FileLike> f = serveStaticFiles(rootDir, path);
    if (!f.isNull()) {
        f->close();
    }
}

QTNETWORKNG_NAMESPACE_END
