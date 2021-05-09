#include "../include/httpd.h"
#include "../include/http.h"


QTNETWORKNG_NAMESPACE_BEGIN


BaseHttpProxyRequestHandler::BaseHttpProxyRequestHandler()
    : isExchanging(false)
{}


void BaseHttpProxyRequestHandler::finish()
{
    if (!isExchanging) {
        request->close();
    }
}


void BaseHttpProxyRequestHandler::logRequest(qtng::HttpStatus, int)
{}


void BaseHttpProxyRequestHandler::logError(qtng::HttpStatus, const QString &, const QString &)
{}


void BaseHttpProxyRequestHandler::doMethod()
{
    if (method.toUpper() == "CONNECT") {
        doCONNECT();
    } else {
        doProxy();
    }
}


void BaseHttpProxyRequestHandler::doCONNECT()
{
    QString host;
    quint16 port;

    const QStringList &l = path.split(':');
    if (l.size() != 2) {
        logProxy(QString(), 0, HostAddress(), false);
        sendError(HttpStatus::BadRequest, "Invalid host and port.");
        return;
    }
    host = l.at(0);
    bool ok;
    port = l.at(1).toUShort(&ok);
    if (!ok) {
        logProxy(host, port, HostAddress(), false);
        sendError(HttpStatus::BadRequest, "Invalid port.");
        return;
    }

    HostAddress forwardAddress;
    QSharedPointer<SocketLike> forward = makeConnection(host, port, &forwardAddress);
    if (forward.isNull()) {
        sendError(HttpStatus::BadGateway, "Can not connect to remote host.");
        logProxy(host, port, HostAddress(), false);
        return;
    }

    sendResponse(OK, "Connection established");
    endHeader();

    logProxy(host, port, forwardAddress, true);
    closeConnection = Yes;
    isExchanging = true;
    exchangeAsync(request, forward);
}


void BaseHttpProxyRequestHandler::doProxy()
{
    QString host;
    quint16 port;

    QUrl url = QUrl::fromEncoded(path.toLatin1());
    host = url.host();
    int t;
    if (url.scheme() == "https") {
        t = url.port(443);
    } else if (url.scheme() == "http") {
        t = url.port(80);
    } else {
        t = url.port();
    }
    if (t <= 0 || t > 65535){
        logProxy(host, 0, HostAddress(), false);
        sendError(HttpStatus::BadRequest, "Invalid port.");
        return;
    }
    port = static_cast<quint16>(t);
    HostAddress forwardAddress;
    QSharedPointer<SocketLike> forward = makeConnection(host, port, &forwardAddress);
    if (forward.isNull()) {
        sendError(HttpStatus::BadGateway, "Can not connect to remote host.");
        logProxy(host, port, HostAddress(), false);
        return;
    }

    HttpRequest newRequest;
    newRequest.setUrl(this->path);
    newRequest.setMethod(method);
    newRequest.setVersion(this->version);
    newRequest.useConnection(forward);
    newRequest.setStreamResponse(true);
    newRequest.disableRedirects();
    // ignore transfer-encoding and content-encoding header, pass it to remote host.
    QSharedPointer<FileLike> bodyFile = bodyAsFile(false);
    if (bodyFile.isNull()) {
        return;
    }
    newRequest.setBody(bodyFile);

    for (const HttpHeader &header: allHeaders()) {
        const QString &hn = header.name.toLower();
        if (hn.startsWith(QLatin1String("proxy-")) || hn == QLatin1String("connection")) {
            continue;
        }
        newRequest.addHeader(header);
    }

    QSharedPointer<HttpResponse> response = sendRequest(newRequest);
    if (!response || (!response->isOk() && !response->hasHttpError())) {
        sendError(HttpStatus::BadGateway, response->error()->what());
        logProxy(host, port, forwardAddress, false);
        return;
    }

    logProxy(host, port, forwardAddress, true);
    sendCommandLine(static_cast<HttpStatus>(response->statusCode()), response->statusText());

    for (const HttpHeader &header: response->allHeaders()) {
        const QString &hn = header.name.toLower();
        if (hn.startsWith(QLatin1String("proxy-")) || hn == QLatin1String("connection")) {
            continue;
        }
        sendHeader(header.name.toUtf8(), header.value);
    }
    if (!endHeader()) {
        return;
    }
    if (method.toUpper() != QString("HEAD")) {
        QSharedPointer<FileLike> f = response->bodyAsFile(false);
        if (!f.isNull()) {
            sendfile(f, this->request);
        }
    }
}


void BaseHttpProxyRequestHandler::logProxy(const QString &remoteHostName, quint16 remotePort, const HostAddress &forwardAddress, bool success)
{
    QString successStr;
    if (success) {
        successStr = "SUCC";
    } else {
        successStr = "FAIL";
    }
    const QString &msg = QString("[%1 %2] -- %3:%4 -> %5")
            .arg(successStr)
            .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
            .arg(remoteHostName)
            .arg(remotePort)
            .arg(forwardAddress.toString());
    qDebug("%s", qPrintable(msg));
}


QSharedPointer<SocketLike> BaseHttpProxyRequestHandler::makeConnection(const QString &remoteHostName, quint16 remotePort, HostAddress *forwardAddress)
{
    QSharedPointer<Socket> s(new Socket());
    if (s->connect(remoteHostName, remotePort)) {
        if (forwardAddress) {
            *forwardAddress = s->peerAddress();
        }
        return asSocketLike(s);
    } else {
        return QSharedPointer<SocketLike>();
    }
}


QTNETWORKNG_NAMESPACE_END
