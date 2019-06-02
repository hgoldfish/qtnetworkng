#ifndef QTNG_SOCKET_SERVER_H
#define QTNG_SOCKET_SERVER_H

#include "kcp.h"
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
    void setUserData(void *data);
    void *userData() const;
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


template<typename RequestHandler>
class TcpServer: public BaseStreamServer
{
public:
    TcpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseStreamServer(serverAddress, serverPort) {}
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};


template<typename RequestHandler>
QSharedPointer<SocketLike> TcpServer<RequestHandler>::serverCreate()
{
    return SocketLike::rawSocket(new Socket());
}


template<typename RequestHandler>
void TcpServer<RequestHandler>::processRequest(QSharedPointer<SocketLike> request)
{
    RequestHandler handler;
    handler.request = request;
    handler.server = this;
    handler.run();
}


template<typename RequestHandler>
class KcpServer: public BaseStreamServer
{
public:
    KcpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseStreamServer(serverAddress, serverPort) {}
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};


template<typename RequestHandler>
QSharedPointer<SocketLike> KcpServer<RequestHandler>::serverCreate()
{
    return SocketLike::kcpSocket(new KcpSocket());
}


template<typename RequestHandler>
void KcpServer<RequestHandler>::processRequest(QSharedPointer<SocketLike> request)
{
    RequestHandler handler;
    handler.request = request;
    handler.server = this;
    handler.run();
}


#ifndef QTNG_NO_CRYPTO

class BaseSslServerPrivate;
class BaseSslServer: public BaseStreamServer
{
public:
    BaseSslServer(const QHostAddress &serverAddress, quint16 serverPort);
    BaseSslServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);
public:
    void setSslConfiguration(const SslConfiguration &configuration);
    SslConfiguration sslConfiguratino() const;
    virtual bool isSecure() const override;
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
private:
    Q_DECLARE_PRIVATE(BaseSslServer)
};


template<typename RequestHandler>
class SslServer: public BaseSslServer
{
public:
    SslServer(const QHostAddress &serverAddress, quint16 serverPort)
        :BaseSslServer(serverAddress, serverPort) {}
    SslServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        :BaseSslServer(serverAddress, serverPort, configuration) {}
protected:
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};


template<typename RequestHandler>
void SslServer<RequestHandler>::processRequest(QSharedPointer<SocketLike> request)
{
    RequestHandler handler;
    handler.request = request;
    handler.server = this;
    handler.run();
}

#endif


class BaseRequestHandler
{
public:
    BaseRequestHandler();
    virtual ~BaseRequestHandler();
public:
    void run();
protected:
    virtual bool setup();
    virtual void handle();
    virtual void finish();
    template<typename UserDataType> UserDataType *userData();
public:
    QSharedPointer<SocketLike> request;
    BaseStreamServer *server;
};


template<typename UserDataType>
UserDataType *BaseRequestHandler::userData()
{
    return static_cast<UserDataType*>(server->userData());
}


class Socks5RequestHandlerPrivate;
class Socks5RequestHandler: public qtng::BaseRequestHandler
{
public:
    Socks5RequestHandler();
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
