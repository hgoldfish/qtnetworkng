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
    BaseHttpRequestHandler();
protected:
    virtual void handle();
    virtual void handleOneRequest();
    virtual bool parseRequest();
    virtual void doMethod();
    virtual QByteArray tryToHandleMagicCode(bool *done);
    virtual bool sendError(HttpStatus status, const QString &longMessage = QString());
    virtual bool sendResponse(HttpStatus status, const QString &longMessage = QString());
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
    SimpleHttpRequestHandler()
        :BaseHttpRequestHandler(), rootDir(QDir::current()) {}
public:
    void setRootDir(const QDir &rootDir) { this->rootDir = rootDir; }
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


// static http(s) server serving current directory.
class SimpleHttpServer: public TcpServer<SimpleHttpRequestHandler>{};
#ifndef QTNG_NO_CRYPTO
class SimpleHttpsServer: public SslServer<SimpleHttpRequestHandler> {};
#endif

QTNETWORKNG_NAMESPACE_END

#endif
