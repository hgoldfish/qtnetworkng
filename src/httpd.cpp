#include <QMimeDatabase>
#include <QTemporaryFile>
#include "../include/httpd.h"

QTNETWORKNG_NAMESPACE_BEGIN


static const QString DEFAULT_ERROR_MESSAGE = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n"
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
                                     "</html>";
static const QString DEFAULT_ERROR_CONTENT_TYPE = "text/html;charset=utf-8";


//#define DEBUG_HTTP_PROTOCOL 1


BaseHttpRequestHandler::BaseHttpRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server)
    :BaseRequestHandler(request, server), version(Http1_1), serverVersion(Http1_1), closeConnection(true)
{

}

void BaseHttpRequestHandler::handle()
{
    do {
        closeConnection = true;
        handleOneRequest();
    } while (!closeConnection);
}

void BaseHttpRequestHandler::handleOneRequest()
{
    if(!parseRequest()) {
        return;
    }
    doMethod();
}

class HttpHeaders: public HeaderOperationMixin {};


bool BaseHttpRequestHandler::parseRequest()
{
    bool done = false;
    const QByteArray &buf = tryToHandleMagicCode(&done);
    if (done) {
        return false;
    }
    HeaderSplitter headerSplitter(request, buf);
    HeaderSplitter::Error headerSpliiterError;
    QByteArray firstLine = headerSplitter.nextLine(&headerSpliiterError);
    if (firstLine.isEmpty() || headerSpliiterError != HeaderSplitter::NoError) {
        return false;
    }
#ifdef DEBUG_HTTP_PROTOCOL
    qDebug() << "first line is" << firstLine;
#endif

    const QString &commandLine = QString::fromLatin1(firstLine);
    QStringList words = commandLine.split(QRegExp("\\s+"));
    if (words.isEmpty()) {
        return false;
    }
    if (words.size() == 3) {
        method = words.at(0);
        path = words.at(1);
        const QString &versionStr = words.at(2);
        if (versionStr == "HTTP/1.0") {
            version = Http1_0;
        } else if(versionStr == "HTTP/1.1") {
            version = Http1_1;
            if (serverVersion == Http1_1) {
                closeConnection = false;
            }
        } else {
            sendError(HttpStatus::BadRequest, QStringLiteral("Bad request version (%1").arg(versionStr));
            return false;
        }
    } else if (words.size() == 2) {
        method = words.at(0);
        path = words.at(1);
        version = Http1_0;
    } else if (words.isEmpty()) {
        return false;
    } else {
        sendError(HttpStatus::BadRequest, QStringLiteral("Bad request syntax (%1)").arg(commandLine));
        return false;
    }

    const int MaxHeaders = 64;
    QList<HttpHeader> headers = headerSplitter.headers(MaxHeaders, &headerSpliiterError);
    switch (headerSpliiterError) {
    case HeaderSplitter::EncodingError:
        sendError(HttpStatus::BadRequest, QStringLiteral("Bad request invalid header"));
        return false;
    case HeaderSplitter::ConnectionError:
        return false;
    case HeaderSplitter::ExhausedMaxLine:
        sendError(HttpStatus::RequestHeaderFieldsTooLarge, QStringLiteral("Too much headers"));
        return false;
    case HeaderSplitter::LineTooLong:
        sendError(HttpStatus::RequestHeaderFieldsTooLarge, QStringLiteral("Line too long"));
        return false;
    default:
        break;
    }
    setHeaders(headers);
#ifdef DEBUG_HTTP_PROTOCOL
    for (const HttpHeader &header: headers) {
        qDebug() << "header(" << header.name << ") = " << header.value;
    }
#endif
    const QByteArray &connectionType = header(ConnectionHeader);
    if (connectionType.toLower() == "close") {
        closeConnection = true;
    } else if (connectionType.toLower() == "keep-alive" && version == Http1_1 && serverVersion == Http1_1) {
        closeConnection = false;
    }
    body = headerSplitter.buf;
    return true;
}

QByteArray BaseHttpRequestHandler::tryToHandleMagicCode(bool *done)
{
    *done = false;
    return QByteArray();
}

void BaseHttpRequestHandler::doMethod()
{
    if (method == "GET") {
        doGET();
    } else if (method == "POST") {
        doPOST();
    } else if (method == "PUT") {
        doPUT();
    } else if (method == "PATCH") {
        doPATCH();
    } else if (method == "DELETE") {
        doDELETE();
    } else if (method == "HEAD") {
        doHEAD();
    } else if (method == "OPTIONS") {
        doOPTIONS();
    } else if (method == "TRACE") {
        doTRACE();
    } else if (method == "CONNECT") {
        doCONNECT();
    } else {
        sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
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
    endHeader();
    if (!body.isEmpty()) {
        request->sendall(body);
    }
}

void BaseHttpRequestHandler::doPOST()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doPUT()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doDELETE()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doPATCH()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doHEAD()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doOPTIONS()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doTRACE()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}

void BaseHttpRequestHandler::doCONNECT()
{
    sendError(HttpStatus::NotImplemented, QStringLiteral("Unsupported method %1").arg(method));
}


bool BaseHttpRequestHandler::sendError(HttpStatus status, const QString &message)
{
    QString shortMessage, longMessage;
    bool ok = toMessage(status, &shortMessage, &longMessage);
    if (!ok) {
        shortMessage = longMessage = QStringLiteral("???");
    }
    if (!message.isEmpty()) {
        longMessage = message;
    }
    logError(status, shortMessage, longMessage);
    sendCommandLine(status, shortMessage);
    sendHeader("Connection", "close");
    QByteArray body;
    if (status >= 200 && status != HttpStatus::NoContent && status != HttpStatus::ResetContent && status != HttpStatus::NotModified) {
        const QString &html = errorMessage(status, shortMessage, longMessage);
        body = html.toUtf8();
        sendHeader("Content-Length", QByteArray::number(body.size()));
        sendHeader("Content-Type", errorMessageContentType().toUtf8());
    }
    if (!endHeader()) {
        return false;
    }
    if (method != "HEAD" && !body.isEmpty()) {
        return request->sendall(body);
    }
    return true;
}


bool BaseHttpRequestHandler::sendResponse(HttpStatus status, const QString &message)
{
    QString shortMessage, longMessage;
    bool ok = toMessage(HttpStatus::OK, &shortMessage, &longMessage);
    if (!ok) {
        shortMessage = longMessage = "???";
    }
    if (!message.isEmpty()) {
        longMessage = message;
    }
    logRequest(status, 0);
    sendCommandLine(status, shortMessage);
    sendHeader("Server", serverName().toUtf8());
    sendHeader("Date", dateTimeString().toUtf8());
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
    switch (serverVersion) {
    case Http1_0:
        versionStr = "HTTP/1.0";
        break;
    case Http1_1:
        versionStr = "HTTP/1.1";
        break;
    default:
        versionStr = "HTTP/1.1";
        break;
    }
    const QString &firstLine = QStringLiteral("%1 %2 %3\r\n").arg(versionStr).arg(static_cast<int>(status)).arg(shortMessage);
    headerCache.append(firstLine.toUtf8());
}


void BaseHttpRequestHandler::sendHeader(const QByteArray &name, const QByteArray &value)
{
    const QByteArray &line = name.trimmed() + ": " + value.trimmed() + "\r\n";
    headerCache.append(line);
    if (name.trimmed().toLower() == "connection") {
        if (value.trimmed().toLower() == "close") {

        } else if (value.trimmed().toLower() == "keep-alive") {
            closeConnection = false;
        }
    }
}

bool BaseHttpRequestHandler::endHeader()
{
    headerCache.append("\r\n");
    const QByteArray &data = headerCache.join();
    headerCache.clear();
    return request->sendall(data) == data.size();
}


QString BaseHttpRequestHandler::serverName()
{
    return "QtNetworkNg";
}


QString BaseHttpRequestHandler::dateTimeString()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::RFC2822Date);
}


void BaseHttpRequestHandler::logRequest(HttpStatus status, int bodySize)
{
    QString msg = QStringLiteral("%1 %2 %3 %4").arg(method).arg(path).arg(static_cast<int>(status)).arg(bodySize);
    qDebug() << request->peerAddress().toString() << "--" << QDateTime::currentDateTime().toString(Qt::ISODate) << msg;
}


void BaseHttpRequestHandler::logError(HttpStatus status, const QString &shortMessage, const QString &)
{
    QString msg = QStringLiteral("%1 %2 %3 %4").arg(method).arg(path).arg(static_cast<int>(status)).arg(shortMessage);
    qDebug() << request->peerAddress().toString() << "--" << QDateTime::currentDateTime().toString(Qt::ISODate) << msg;
}


void SimpleHttpRequestHandler::doGET()
{
    QSharedPointer<FileLike> f = serveStaticFiles();
    if (!f.isNull()) {
        sendFile(f);
        f->close();
    }
}

void SimpleHttpRequestHandler::doHEAD()
{
    QSharedPointer<FileLike> f = serveStaticFiles();
    if (!f.isNull()) {
        f->close();
    }
}


QSharedPointer<FileLike> SimpleHttpRequestHandler::serveStaticFiles()
{
    QUrl url = QUrl::fromEncoded(path.toLatin1());
    QFileInfo fileInfo = translatePath(url.path());
#ifdef DEBUG_HTTP_PROTOCOL
    qDebug() << "serve path" << url.path() << fileInfo.absoluteFilePath();
#endif
    if (!fileInfo.exists()) {
        sendError(HttpStatus::NotFound, "File not found");
        return QSharedPointer<FileLike>();
    }

    if (fileInfo.isDir()) {
        const QString &p = url.toString(QUrl::RemoveQuery | QUrl::RemoveFragment | QUrl::FullyDecoded);
        if (!p.endsWith("/")) {
            url.setPath(p + "/");
            sendResponse(HttpStatus::MovedPermanently);
            sendHeader("Location", url.toEncoded(QUrl::FullyEncoded));
            endHeader();
            return QSharedPointer<FileLike>();
        } else {
            QDir dir(fileInfo.filePath());
            if (dir.exists("index.html")) {
                fileInfo = dir.filePath("index.html");
            } else if (dir.exists("index.htm")) {
                fileInfo = dir.filePath("index.htm");
            } else {
                return listDirectory(dir, p);
            }
        }
    }

    QString contentType;

#ifdef Q_OS_ANDROID
    const QString &ext = fileInfo.completeSuffix().toLower();
    if (ext == "txt") {
        contentType = "text/plain";
    } else if (ext == "html" || ext == "htm") {
        contentType = "text/html";
    } else if (ext == "js") {
        contentType = "application/javascript";
    } else if (ext == "css") {
        contentType = "text/css";
    } else {
        contentType = "application/octet-stream";
    }
#else
    QMimeDatabase db;
    const QMimeType &ctype = db.mimeTypeForFile(fileInfo);
    if (!ctype.isValid()) {
        contentType = "application/octet-stream";
    } else {
        contentType = ctype.name();
    }
#endif
    QSharedPointer<QFile> f(new QFile(fileInfo.filePath()));
    if (!f->open(QIODevice::ReadOnly)) {
        sendError(HttpStatus::NotFound, "File not found");
        return QSharedPointer<FileLike>();
    }
    sendResponse(HttpStatus::OK);
    sendHeader("Content-Type", contentType.toUtf8());
    sendHeader("Content-Length", QByteArray::number(f->size()));
    sendHeader("Last-Modified", fileInfo.lastModified().toString(Qt::RFC2822Date).toUtf8());
    if (version == Http1_1 && !closeConnection) {
        sendHeader("Connection", "keep-alive");
    }
    endHeader();
    return FileLike::rawFile(f);
}


QSharedPointer<FileLike> SimpleHttpRequestHandler::listDirectory(const QDir &dir, const QString &displayDir)
{
    const QFileInfoList &list = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);
    const QString &title = QStringLiteral("Directory listing for ") + displayDir;
    QStringList html;
    html.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">");
    html.append("<html>\n<head>");
    html.append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">");
    html.append(QStringLiteral("<title>%1</title>\n</head>").arg(title));
    html.append(QStringLiteral("<body>\n<h1>%1</h1>").arg(title));
    html.append("<hr>\n<ul>");
    for (const QFileInfo &entry: list) {
        QString name = entry.fileName();
        QString link = entry.fileName();
        if (entry.isDir()) {
            name.append("/");
            link.append("/");
        }
        if (entry.isSymLink()) {
            name = entry.fileName() + "@";
            // Note: a link to a directory displays with @ and links with /
        }
        const QString &htmlName = name.toHtmlEscaped();
        const QString &htmlLink = link.toUtf8().toPercentEncoding("/");
        html.append(QStringLiteral("<li><a href=\"%1\">%2</a></li>").arg(htmlLink).arg(htmlName));
    }
    html.append("</ul>\n<hr>\n</body>\n</html>");
    const QByteArray &data = html.join("\n").toUtf8();
    sendResponse(HttpStatus::OK);
    sendHeader("Content-Type", "text/html; charset=utf-8");
    sendHeader("Content-Length", QByteArray::number(data.size()));
    endHeader();
    return FileLike::bytes(data);
}


void SimpleHttpRequestHandler::sendFile(QSharedPointer<FileLike> f)
{
    QByteArray buf(1024 * 8, Qt::Uninitialized);
    while (!f->atEnd()) {
        qint64 bs = f->read(buf.data(), buf.size());
        if (bs <= 0){
            break;
        }
        bool ok = request->sendall(buf.data(), static_cast<qint32>(bs));
        if (!ok) {
            return;
        }
    }
}


QFileInfo SimpleHttpRequestHandler::translatePath(const QString &path)
{
    // remove '.' && '.."
    const QStringList &list = path.split("/", QString::SkipEmptyParts);
    QStringList l;
    for (const QString &part: list) {
        if (part == ".") { // if part contains space, it is not dot dir.
            continue;
        } else if (part == "..") {
            if (!l.isEmpty()) {
                l.removeLast();
            }
        } else {
            l.append(part);
        }
    }
    QString normalPath = l.join("/");
    return QFileInfo(rootDir, normalPath);
}


void SimpleHttpServer::processRequest(QSharedPointer<SocketLike> request)
{
    SimpleHttpRequestHandler handler(request, this);
    handler.run();
}


#ifndef QTNG_NO_CRYPTO

void SimpleHttpsServer::processRequest(QSharedPointer<SocketLike> request)
{
    SimpleHttpRequestHandler handler(request, this);
    handler.run();
}

#endif

QTNETWORKNG_NAMESPACE_END
