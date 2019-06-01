#ifndef QTNG_SOCKET_SERVER_H
#define QTNG_SOCKET_SERVER_H

#include "socket_utils.h"
#include "coroutine_utils.h"
#ifndef QTNG_NO_CRYPTO
#include "ssl.h"
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class BaseStreamServerPrivate;
class BaseStreamServer
{
public:
    BaseStreamServer(const QHostAddress &serverAddress, quint16 serverPort);
    virtual ~BaseStreamServer();
protected:
    // these two virtual functions should be overrided by subclass.
    virtual QSharedPointer<SocketLike> serverCreate() = 0;
    virtual void processRequest(QSharedPointer<SocketLike> request);
public:
    bool allowReuseAddress() const;                    // default to true,
    void setAllowReuseAddress(bool b);
    int requestQueueSize() const;                      // default to 100
    void setRequestQueueSize(int requestQueueSize);
    bool serveForever();                               // serve blocking
    bool start();                                      // serve in background
    void stop();                                       // stop serving
    virtual bool isSecure() const;                     // is this ssl?
public:
    quint16 serverPort() const;
    QHostAddress serverAddress() const;
public:
    QSharedPointer<Event> started;
    QSharedPointer<Event> stopped;
protected:
    virtual bool serverBind();                          // bind()
    virtual bool serverActivate();                      // listen()
    virtual void serverClose();                         // close()
    virtual bool serviceActions();                      // default to nothing, called before accept next request.
    virtual QSharedPointer<SocketLike> getRequest();    // accept();
    virtual bool verifyRequest(QSharedPointer<SocketLike> request);
    virtual void handleError(QSharedPointer<SocketLike> request);
    virtual void shutdownRequest(QSharedPointer<SocketLike> request);
    virtual void closeRequest(QSharedPointer<SocketLike> request);
protected:
    BaseStreamServerPrivate * const d_ptr;
    BaseStreamServer(BaseStreamServerPrivate *d);
private:
    Q_DECLARE_PRIVATE(BaseStreamServer)
};


class TcpServer: public BaseStreamServer
{
public:
    TcpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseStreamServer(serverAddress, serverPort) {}
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
};


class KcpServer: public BaseStreamServer
{
public:
    KcpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseStreamServer(serverAddress, serverPort) {}
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
};


#ifndef QTNG_NO_CRYPTO
class SslServerPrivate;
class SslServer: public BaseStreamServer
{
public:
    SslServer(const QHostAddress &serverAddress, quint16 serverPort);
    SslServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);
public:
    void setSslConfiguration(const SslConfiguration &configuration);
    SslConfiguration sslConfiguratino() const;
    virtual bool isSecure() const override;
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
private:
    Q_DECLARE_PRIVATE(SslServer)
};
#endif


class BaseRequestHandler
{
public:
    BaseRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server);
    virtual ~BaseRequestHandler();
public:
    void run();
protected:
    virtual void setup();
    virtual void handle();
    virtual void finish();
protected:
    QSharedPointer<SocketLike> request;
    BaseStreamServer *server;
};


class Socks5RequestHandlerPrivate;
class Socks5RequestHandler: public qtng::BaseRequestHandler
{
public:
    Socks5RequestHandler(QSharedPointer<qtng::SocketLike> request, qtng::BaseStreamServer *server);
    virtual ~Socks5RequestHandler() override;
protected:
    virtual void doConnect(const QString &hostName, const QHostAddress &hostAddress, quint16 port);
    bool sendConnectReply(const QHostAddress &hostAddress, quint16 port);
    virtual void doFailed(const QString &hostName, const QHostAddress &hostAddress, quint16 port);
    bool sendFailedReply();
    virtual void log(const QString &hostName, const QHostAddress &hostAddress, quint16 port, bool success);
protected:
    virtual void handle() override;
private:
    Socks5RequestHandlerPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Socks5RequestHandler)
};

QTNETWORKNG_NAMESPACE_END

#endif
