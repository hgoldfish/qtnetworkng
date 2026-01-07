#ifndef QTNG_SOCKET_SERVER_H
#define QTNG_SOCKET_SERVER_H

#include "kcp.h"
#include "kcp_base.h"
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
    BaseStreamServer(const HostAddress &serverAddress, quint16 serverPort);
    BaseStreamServer(quint16 serverPort)
        : BaseStreamServer(HostAddress::Any, serverPort)
    {
    }
    virtual ~BaseStreamServer();
protected:
    // these two virtual functions should be overrided by subclass.
    virtual QSharedPointer<SocketLike> serverCreate() = 0;
    virtual void processRequest(QSharedPointer<SocketLike> request) = 0;
public:
    bool allowReuseAddress() const;  // default to true,
    void setAllowReuseAddress(bool b);
    int requestQueueSize() const;  // default to 100
    void setRequestQueueSize(int requestQueueSize);
    bool serveForever();  // serve blocking
    bool start();  // serve in background
    void stop();  // stop serving
    bool wait();  // wait for server stopped
    virtual bool isSecure() const;  // is this ssl?
    QSharedPointer<SocketLike> createServer() { return serverSocket(); }
public:
    void setUserData(void *data);  // the owner of data is not changed.
    void *userData() const;
public:
    quint16 serverPort() const;
    HostAddress serverAddress() const;
    QSharedPointer<SocketLike> serverSocket();
public:
    QSharedPointer<Event> started();
    QSharedPointer<Event> stopped();
protected:
    virtual bool serverBind();  // bind()
    virtual bool serverActivate();  // listen()
    virtual void serverClose();  // close()
    virtual bool serviceActions();  // default to nothing, called before accept next request.
    virtual QSharedPointer<SocketLike> getRequest();  // accept();
    virtual QSharedPointer<SocketLike>
    prepareRequest(QSharedPointer<SocketLike> request);  // ssl handshake, default to nothing for tcp
    virtual bool verifyRequest(QSharedPointer<SocketLike> request);
    virtual void handleError(QSharedPointer<SocketLike> request);
    virtual void closeRequest(QSharedPointer<SocketLike> request);
protected:
    BaseStreamServerPrivate * const d_ptr;
private:
    Q_DECLARE_PRIVATE(BaseStreamServer)
};

template<typename RequestHandler>
class TcpServer : public BaseStreamServer
{
public:
    TcpServer(const HostAddress &serverAddress, quint16 serverPort)
        : BaseStreamServer(serverAddress, serverPort)
    {
    }
    TcpServer(quint16 serverPort)
        : BaseStreamServer(HostAddress::Any, serverPort)
    {
    }
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};

template<typename RequestHandler>
QSharedPointer<SocketLike> TcpServer<RequestHandler>::serverCreate()
{
    return asSocketLike(Socket::createServer(serverAddress(), serverPort(), 0));
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
class KcpServer : public BaseStreamServer
{
public:
    KcpServer(const HostAddress &serverAddress, quint16 serverPort)
        : BaseStreamServer(serverAddress, serverPort)
    {
    }
    KcpServer(quint16 serverPort)
        : BaseStreamServer(HostAddress::Any, serverPort)
    {
    }
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};

template<typename RequestHandler>
QSharedPointer<SocketLike> KcpServer<RequestHandler>::serverCreate()
{
    return asSocketLike(KcpSocket::createServer(serverAddress(), serverPort(), 0));
}

template<typename RequestHandler>
void KcpServer<RequestHandler>::processRequest(QSharedPointer<SocketLike> request)
{
    RequestHandler handler;
    handler.request = request;
    handler.server = this;
    handler.run();
}

template<typename RequestHandler>
class KcpServerV2 : public BaseStreamServer
{
public:
    KcpServerV2(const HostAddress &serverAddress, quint16 serverPort)
        : BaseStreamServer(serverAddress, serverPort)
    {
    }
    KcpServerV2(quint16 serverPort)
        : BaseStreamServer(HostAddress::Any, serverPort)
    {
    }
protected:
    virtual QSharedPointer<SocketLike> serverCreate() override;
    virtual void processRequest(QSharedPointer<SocketLike> request) override;
};

template<typename RequestHandler>
QSharedPointer<SocketLike> KcpServerV2<RequestHandler>::serverCreate()
{
    return createKcpServer(serverAddress(), serverPort(), 0);
}

template<typename RequestHandler>
void KcpServerV2<RequestHandler>::processRequest(QSharedPointer<SocketLike> request)
{
    RequestHandler handler;
    handler.request = request;
    handler.server = this;
    handler.run();
}

#ifndef QTNG_NO_CRYPTO

template<typename ServerType>
class WithSsl : public ServerType
{
public:
    WithSsl(const HostAddress &serverAddress, quint16 serverPort);
    WithSsl(const HostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);
    WithSsl(quint16 serverPort);
    WithSsl(quint16 serverPort, const SslConfiguration &configuration);
public:
    void setSslConfiguration(const SslConfiguration &configuration);
    SslConfiguration sslConfiguration() const;
    void setSslHandshakeTimeout(float sslHandshakeTimeout);
    float sslHandshakeTimeout() const;
    virtual bool isSecure() const override;
protected:
    virtual QSharedPointer<SocketLike> prepareRequest(QSharedPointer<SocketLike> request) override;
private:
    SslConfiguration _configuration;
    float _sslHandshakeTimeout;
};

template<typename ServerType>
WithSsl<ServerType>::WithSsl(const HostAddress &serverAddress, quint16 serverPort)
    : ServerType(serverAddress, serverPort)
    , _sslHandshakeTimeout(5.0)
{
    _configuration = SslConfiguration::testPurpose(QString::fromLatin1("SslServer"), QString::fromLatin1("CN"),
                                                   QString::fromLatin1("QtNetworkNg"));
}

template<typename ServerType>
WithSsl<ServerType>::WithSsl(const HostAddress &serverAddress, quint16 serverPort,
                             const SslConfiguration &configuration)
    : ServerType(serverAddress, serverPort)
    , _configuration(configuration)
    , _sslHandshakeTimeout(5.0)
{
}

template<typename ServerType>
WithSsl<ServerType>::WithSsl(quint16 serverPort)
    : ServerType(HostAddress::Any, serverPort)
    , _sslHandshakeTimeout(5.0)
{
    _configuration = SslConfiguration::testPurpose(QString::fromLatin1("SslServer"), QString::fromLatin1("CN"),
                                                   QString::fromLatin1("QtNetworkNg"));
}

template<typename ServerType>
WithSsl<ServerType>::WithSsl(quint16 serverPort, const SslConfiguration &configuration)
    : ServerType(HostAddress::Any, serverPort)
    , _configuration(configuration)
    , _sslHandshakeTimeout(5.0)
{
}

template<typename ServerType>
void WithSsl<ServerType>::setSslConfiguration(const SslConfiguration &configuration)
{
    this->_configuration = configuration;
}

template<typename ServerType>
SslConfiguration WithSsl<ServerType>::sslConfiguration() const
{
    return this->_configuration;
}

template<typename ServerType>
void WithSsl<ServerType>::setSslHandshakeTimeout(float sslHandshakeTimeout)
{
    this->_sslHandshakeTimeout = sslHandshakeTimeout;
}

template<typename ServerType>
float WithSsl<ServerType>::sslHandshakeTimeout() const
{
    return this->_sslHandshakeTimeout;
}

template<typename ServerType>
bool WithSsl<ServerType>::isSecure() const
{
    return true;
}

template<typename ServerType>
QSharedPointer<SocketLike> WithSsl<ServerType>::prepareRequest(QSharedPointer<SocketLike> request)
{
    try {
        Timeout timeout(_sslHandshakeTimeout);
        QSharedPointer<SslSocket> s = QSharedPointer<SslSocket>::create(request, _configuration);
        if (s->handshake(true, QString())) {
            return asSocketLike(s);
        }
    } catch (TimeoutException &) {
        //
    }
    return QSharedPointer<SocketLike>();
}

template<typename RequestHandler>
class SslServer : public WithSsl<TcpServer<RequestHandler>>
{
public:
    SslServer(const HostAddress &serverAddress, quint16 serverPort);
    SslServer(const HostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);
    SslServer(quint16 serverPort);
    SslServer(quint16 serverPort, const SslConfiguration &configuration);
};

template<typename RequestHandler>
SslServer<RequestHandler>::SslServer(const HostAddress &serverAddress, quint16 serverPort)
    : WithSsl<TcpServer<RequestHandler>>(serverAddress, serverPort)
{
}

template<typename RequestHandler>
SslServer<RequestHandler>::SslServer(const HostAddress &serverAddress, quint16 serverPort,
                                     const SslConfiguration &configuration)
    : WithSsl<TcpServer<RequestHandler>>(serverAddress, serverPort, configuration)
{
}

template<typename RequestHandler>
SslServer<RequestHandler>::SslServer(quint16 serverPort)
    : WithSsl<TcpServer<RequestHandler>>(serverPort)
{
}

template<typename RequestHandler>
SslServer<RequestHandler>::SslServer(quint16 serverPort, const SslConfiguration &configuration)
    : WithSsl<TcpServer<RequestHandler>>(serverPort, configuration)
{
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
    template<typename UserDataType>
    UserDataType *userData() const;
public:
    QSharedPointer<SocketLike> request;
    BaseStreamServer *server;
};

template<typename UserDataType>
UserDataType *BaseRequestHandler::userData() const
{
    return static_cast<UserDataType *>(server->userData());
}

class Socks5RequestHandlerPrivate;
class Socks5RequestHandler : public BaseRequestHandler
{
protected:
    virtual void handle() override;
protected:
    virtual void doConnect(const QString &hostName, const HostAddress &hostAddress, quint16 port);
    virtual void doFailed(const QString &hostName, const HostAddress &hostAddress, quint16 port);
    virtual QSharedPointer<SocketLike> makeConnection(const QString &hostName, const HostAddress &hostAddress,
                                                      quint16 port, HostAddress *forwardAddress);
    virtual void logProxy(const QString &hostName, const HostAddress &hostAddress, quint16 port,
                          const HostAddress &forwardAddress, bool success);
    virtual void exchange(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward);
protected:
    bool sendConnectReply(const HostAddress &hostAddress, quint16 port);
    bool sendFailedReply();
private:
    bool handshake();
    bool parseAddress(QString *hostName, HostAddress *addr, quint16 *port);
};

QTNETWORKNG_NAMESPACE_END

#endif
