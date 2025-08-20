#ifndef QTNG_HTTPD_H
#define QTNG_HTTPD_H
#include <QtCore/qfile.h>
#include <QtCore/qdir.h>
#include <QtCore/qfileinfo.h>
#include "socket_server.h"
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
#  define QBYTEARRAYLIST QByteArrayList
#else
#  define QBYTEARRAYLIST QList<QByteArray>
#endif

class BaseHttpRequestHandler : public WithHttpHeaders<BaseRequestHandler>
{
public:
    BaseHttpRequestHandler();
protected:  // most common methods to override
    virtual void doMethod();
    virtual void doGET();
    virtual void doPOST();
    virtual void doPUT();
    virtual void doDELETE();
    virtual void doPATCH();
    virtual void doHEAD();
    virtual void doOPTIONS();
    virtual void doTRACE();
    virtual void doCONNECT();
protected:  // many people also override these
    virtual QString serverName();
    virtual void logRequest(HttpStatus status, int bodySize);
    virtual void logError(HttpStatus status, const QString &shortMessage, const QString &longMessage);
protected:  // http protocol, parsing request and making response.
    virtual void handle();
    virtual void handleOneRequest();
    virtual bool parseRequest();
    virtual bool sendError(HttpStatus status, const QString &longMessage = QString());
    virtual bool sendResponse(HttpStatus status, const QString &longMessage = QString());
    virtual QString errorMessage(HttpStatus status, const QString &shortMessage, const QString &longMessage);
    virtual QString errorMessageContentType();
    virtual QString dateTimeString();
    virtual QSharedPointer<FileLike> bodyAsFile(bool processEncoding = true);
protected:  // support web socket.
    virtual bool switchToWebSocket();
    QBYTEARRAYLIST webSocketProtocols();
protected:  // util methods.
    void sendCommandLine(HttpStatus status, const QString &shortMessage);
    void sendHeader(KnownHeader name, const QByteArray &value) { sendHeader(toString(name).toLatin1(), value); }
    void sendHeader(const QByteArray &name, const QByteArray &value);
    bool endHeader();
    bool readBody();
protected:
    virtual QByteArray tryToHandleMagicCode(bool &done);
private:
    QBYTEARRAYLIST headerCache;  // used for sendHeader() & endHeader()
public:
    static QString normalizePath(const QString &path);
protected:
    QString method;  // sent by client.
    QString path;  // sent by client.
    QByteArray body;  // sent by client.
    HttpVersion version;  // sent by client.
protected:
    HttpVersion serverVersion;  // default to HTTP 1.1
    float requestTimeout;  // default to 1 hour.
    qint32 maxBodySize;  // default to 32MB, unlimited if -1
    enum CloseConnectionStatus { Yes, No, Maybe } closeConnection;  // determined by http version and connection header.
};

// we do a nginx.
class StaticHttpRequestHandler : public BaseHttpRequestHandler
{
public:
    StaticHttpRequestHandler()
        : enableDirectoryListing(false)
    {
    }
protected:
    virtual QSharedPointer<FileLike> serveStaticFiles(const QDir &dir, const QString &subPath);
    virtual QSharedPointer<FileLike> listDirectory(const QDir &dir, const QString &displayDir);
    virtual bool loadMissingFile(const QFileInfo &fileInfo);
    virtual QFileInfo getIndexFile(const QDir &dir);
protected:
    bool enableDirectoryListing;
};

class SimpleHttpRequestHandler : public StaticHttpRequestHandler
{
public:
    SimpleHttpRequestHandler()
        : StaticHttpRequestHandler()
        , rootDir(QDir::current())
    {
    }
public:
    void setRootDir(const QDir &rootDir) { this->rootDir = rootDir; }
protected:
    virtual void doGET() override;
    virtual void doHEAD() override;
protected:
    QDir rootDir;
};

class BaseHttpProxyRequestHandler : public BaseHttpRequestHandler
{
protected:
    virtual void logRequest(qtng::HttpStatus status, int bodySize) override;
    virtual void logError(qtng::HttpStatus status, const QString &shortMessage, const QString &longMessage) override;
    virtual void doMethod() override;
    virtual void doCONNECT() override;
protected:
    virtual void doProxy();
protected:
    virtual void logProxy(const QString &remoteHostName, quint16 remotePort, const HostAddress &forwardAddress,
                          bool success);
    virtual QSharedPointer<SocketLike> makeConnection(const QString &remoteHostName, quint16 remotePort,
                                                      HostAddress *forwardAddress);
protected:
    virtual QSharedPointer<class HttpResponse> sendRequest(class HttpRequest &request) = 0;
    virtual void exchangeAsync(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward) = 0;
    bool asReversed = false;
};

// static http(s) server serving current directory.
class SimpleHttpServer : public TcpServer<SimpleHttpRequestHandler>
{
public:
    SimpleHttpServer(const HostAddress &serverAddress, quint16 serverPort)
        : TcpServer(serverAddress, serverPort)
    {
    }
    SimpleHttpServer(quint16 serverPort)
        : TcpServer(HostAddress::Any, serverPort)
    {
    }
};

#ifndef QTNG_NO_CRYPTO
class SimpleHttpsServer : public SslServer<SimpleHttpRequestHandler>
{
public:
    SimpleHttpsServer(const HostAddress &serverAddress, quint16 serverPort)
        : SslServer(serverAddress, serverPort)
    {
    }
    SimpleHttpsServer(const HostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        : SslServer(serverAddress, serverPort, configuration)
    {
    }
    SimpleHttpsServer(quint16 serverPort)
        : SslServer(serverPort)
    {
    }
    SimpleHttpsServer(quint16 serverPort, const SslConfiguration &configuration)
        : SslServer(serverPort, configuration)
    {
    }
};
#endif

QTNETWORKNG_NAMESPACE_END

#endif
