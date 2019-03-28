#ifndef QTNG_HTTPD_H
#define QTNG_HTTPD_H
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include "socket_server.h"
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

class BaseHttpRequestHandler: public BaseRequestHandler, public HeaderOperationMixin
{
public:
    BaseHttpRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server);
protected:
    virtual void handle();
    virtual void handleOneRequest();
    virtual bool parseRequest();
    virtual void doMethod();
    virtual QByteArray tryToHandleMagicCode(bool *done);
    virtual bool sendError(HttpStatus status, const QString &longMessage = QString());
    virtual bool sendResponse(HttpStatus status);
    virtual QString errorMessage(HttpStatus status, const QString &shortMessage, const QString &longMessage);
    virtual QString errorMessageContentType();
    virtual void logRequest(HttpStatus status, int bodySize);
    virtual void logError(HttpStatus status, const QString &shortMessage, const QString &longMessage);
    virtual QString serverName();
    virtual QString dateTimeString();
    void sendCommandLine(HttpStatus status, const QString &shortMessage);
    void sendHeader(const QByteArray &name, const QByteArray &value);
    bool endHeader();
protected:
    virtual void doGET();
    virtual void doPOST();
    virtual void doPUT();
    virtual void doDELETE();
    virtual void doPATCH();
    virtual void doHEAD();
    virtual void doOPTIONS();
    virtual void doTRACE();
    virtual void doCONNECT();
private:
    QByteArrayList headerCache;
protected:
    QString method;
    QString path;
    QByteArray body;
    HttpVersion version;
    HttpVersion serverVersion;
    bool closeConnection;
};


class SimpleHttpRequestHandler: public BaseHttpRequestHandler
{
public:
    SimpleHttpRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server)
        :BaseHttpRequestHandler(request, server), rootDir(QDir::current()) {}
    SimpleHttpRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server,
                             const QDir &rootDir)
        :BaseHttpRequestHandler(request, server), rootDir(rootDir) {}
protected:
    virtual void doGET() override;
    virtual void doHEAD() override;
    virtual QSharedPointer<FileLike> serveStaticFiles();
    virtual QSharedPointer<FileLike> listDirectory(const QDir &dir, const QString &displayDir);
    void sendFile(QSharedPointer<FileLike> f);
    QFileInfo translatePath(const QString &path);
protected:
    QDir rootDir;
};


class SimpleHttpServer: public BaseStreamServer
{
public:
    SimpleHttpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseStreamServer(serverAddress, serverPort) {}
protected:
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};

#ifndef QTNG_NO_CRYPTO

class SimpleHttpsServer: public BaseSslStreamServer
{
public:
    SimpleHttpsServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseSslStreamServer(serverAddress, serverPort) {}
    SimpleHttpsServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        :BaseSslStreamServer(serverAddress, serverPort, configuration) {}
protected:
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};

#endif

QTNETWORKNG_NAMESPACE_END

#endif
