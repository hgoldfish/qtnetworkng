#ifndef QTNG_HTTPD_H
#define QTNG_HTTPD_H
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include "socket_server.h"
#include "http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
    #define QBYTEARRAYLIST QByteArrayList
#else
    #define QBYTEARRAYLIST QList<QByteArray>
#endif


class BaseHttpRequestHandler: public HeaderOperationMixin<BaseRequestHandler>
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
    QBYTEARRAYLIST headerCache;
public:
    static QString normalizePath(const QString &path);
protected:
    QString method;              // sent by client.
    QString path;                // sent by client.
    QByteArray body;             // sent by client.
    HttpVersion version;         // sent by client.
    HttpVersion serverVersion;   // default to HTTP 1.1
    float requestTimeout;        // default to 1 hour.
    bool closeConnection;        // determined by http version and connection header.
};


// we do a nginx.
class StaticHttpRequestHandler: public BaseHttpRequestHandler
{
public:
    StaticHttpRequestHandler()
        : enableDirectoryListing(false) {}
protected:
    virtual QSharedPointer<FileLike> serveStaticFiles(const QDir &dir, const QString &subPath);
    virtual QSharedPointer<FileLike> listDirectory(const QDir &dir, const QString &displayDir);
    virtual void sendFile(QSharedPointer<FileLike> f);
    virtual QFileInfo translatePath(const QDir &dir, const QString &subPath);
    virtual bool loadMissingFile(const QFileInfo &fileInfo);
    virtual QFileInfo getIndexFile(const QDir &dir);
protected:
    bool enableDirectoryListing;
};


class SimpleHttpRequestHandler: public StaticHttpRequestHandler
{
public:
    SimpleHttpRequestHandler()
        : StaticHttpRequestHandler()
        , rootDir(QDir::current()) { enableDirectoryListing = true; }
public:
    void setRootDir(const QDir &rootDir) { this->rootDir = rootDir; }
protected:
    virtual void doGET() override;
    virtual void doHEAD() override;
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
