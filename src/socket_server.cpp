#include <QtCore/qloggingcategory.h>
#include "../include/socket_server.h"
#include "../include/kcp.h"

static Q_LOGGING_CATEGORY(logger, "qtng.socket_server")

QTNETWORKNG_NAMESPACE_BEGIN

class BaseStreamServerPrivate
{
public:
    BaseStreamServerPrivate(BaseStreamServer *q, const QHostAddress &serverAddress, quint16 serverPort)
        : operations(new CoroutineGroup)
        , serverAddress(serverAddress)
        , requestQueueSize(100)
        , serverPort(serverPort)
        , allowReuseAddress(true)
        , q_ptr(q)
    {}
    ~BaseStreamServerPrivate() { delete operations; }
    void serveForever();
    void handleRequest(QSharedPointer<SocketLike> request);
public:
    QSharedPointer<SocketLike> serverSocket;
    CoroutineGroup *operations;
    QHostAddress serverAddress;
    int requestQueueSize;
    quint16 serverPort;
    bool allowReuseAddress;
private:
    BaseStreamServer * const q_ptr;
    Q_DECLARE_PUBLIC(BaseStreamServer)
};


BaseStreamServer::BaseStreamServer(const QHostAddress &serverAddress, quint16 serverPort)
    :started(new Event()), stopped(new Event()), d_ptr(new BaseStreamServerPrivate(this, serverAddress, serverPort))
{
    Q_D(BaseStreamServer);
    started->clear();
    stopped->set();
}


BaseStreamServer::BaseStreamServer(BaseStreamServerPrivate *d)
    :started(new Event()), stopped(new Event()), d_ptr(d)
{
    started->clear();
    stopped->set();
}


BaseStreamServer::~BaseStreamServer()
{
    delete d_ptr;
}


bool BaseStreamServer::allowReuseAddress() const
{
    Q_D(const BaseStreamServer);
    return d->allowReuseAddress;
}


void BaseStreamServer::setAllowReuseAddress(bool b)
{
    Q_D(BaseStreamServer);
    d->allowReuseAddress = b;
}


int BaseStreamServer::requestQueueSize() const
{
    Q_D(const BaseStreamServer);
    return d->requestQueueSize;
}


void BaseStreamServer::setRequestQueueSize(int requestQueueSize)
{
    Q_D(BaseStreamServer);
    d->requestQueueSize = requestQueueSize;
}


bool BaseStreamServer::serverBind()
{
    Q_D(BaseStreamServer);
    Socket::BindMode mode;
    if (d->allowReuseAddress) {
        mode = Socket::ReuseAddressHint;
    } else {
        mode = Socket::DefaultForPlatform;
    }
    bool ok = d->serverSocket->bind(d->serverAddress, d->serverPort, mode);
    if (!ok) {
        qCInfo(logger) << "server can not bind to" << d->serverAddress.toString() << ":" << d->serverPort;
    }
    return ok;
}


bool BaseStreamServer::serverActivate()
{
    Q_D(BaseStreamServer);
    bool ok = d->serverSocket->listen(d->requestQueueSize);
    if (!ok) {
        qCInfo(logger) << "server can not listen to" << d->serverAddress.toString() << ":" << d->serverPort;
    }
    return ok;
}


void BaseStreamServer::serverClose()
{
    Q_D(BaseStreamServer);
    d->serverSocket->close();
}


void BaseStreamServerPrivate::serveForever()
{
    Q_Q(BaseStreamServer);
    q->started->set();
    q->stopped->clear();
    while (true) {
        QSharedPointer<SocketLike> request = q->getRequest();
        if (request.isNull()) {
            break;
        }
        if (q->verifyRequest(request)) {
            operations->spawn([this, request] {
                handleRequest(request);
            });
        } else {
            q->shutdownRequest(request);
            q->closeRequest(request);
        }
        if (!q->serviceActions()) {
            break;
        }
    }
    q->serverClose();
    q->started->clear();
    q->stopped->set();
}


void BaseStreamServerPrivate::handleRequest(QSharedPointer<SocketLike> request)
{
    Q_Q(BaseStreamServer);
    try {
        q->processRequest(request); // close request.
    } catch (CoroutineExitException &) {
        q->shutdownRequest(request);
        q->closeRequest(request);
    } catch (...) {
        q->handleError(request);
        q->shutdownRequest(request);
        q->closeRequest(request);
    }
}


bool BaseStreamServer::serveForever()
{
    Q_D(BaseStreamServer);
    d->serverSocket = serverCreate();
    if (d->serverSocket.isNull()) {
        return false;
    }
    if (!serverBind()) {
        serverClose();
        return false;
    }
    if (!serverActivate()) {
        serverClose();
        return false;
    }
    d->serveForever();
    return true;
}


bool BaseStreamServer::start()
{
    Q_D(BaseStreamServer);

    if (started->isSet() || d->operations->has("serve")) {
        return true;
    }
    d->serverSocket = serverCreate();
    if (d->serverSocket.isNull()) {
        return false;
    }
    if (!serverBind()) {
        serverClose();
        return false;
    }
    if (!serverActivate()) {
        serverClose();
        return false;
    }
    d->operations->spawnWithName("serve", [d] { d->serveForever(); });
    return true;
}


void BaseStreamServer::stop()
{
    Q_D(BaseStreamServer);
    if (!d->serverSocket.isNull()) {
        serverClose();
    }
}


bool BaseStreamServer::isSecure() const
{
    return false;
}


quint16 BaseStreamServer::serverPort() const
{
    Q_D(const BaseStreamServer);
    return d->serverPort;
}


QHostAddress BaseStreamServer::serverAddress() const
{
    Q_D(const BaseStreamServer);
    return d->serverAddress;
}


bool BaseStreamServer::serviceActions()
{
    return true;
}


bool BaseStreamServer::verifyRequest(QSharedPointer<SocketLike>)
{
    return true;
}


void BaseStreamServer::processRequest(QSharedPointer<SocketLike>)
{

}


QSharedPointer<SocketLike> BaseStreamServer::getRequest()
{
    Q_D(BaseStreamServer);
    return d->serverSocket->accept();
}


void BaseStreamServer::handleError(QSharedPointer<SocketLike>)
{
}


void BaseStreamServer::shutdownRequest(QSharedPointer<SocketLike>)
{
}


void BaseStreamServer::closeRequest(QSharedPointer<SocketLike> request)
{
    request->close();
}


QSharedPointer<SocketLike> TcpServer::serverCreate()
{
    return SocketLike::rawSocket(new Socket());
}


QSharedPointer<SocketLike> KcpServer::serverCreate()
{
    return SocketLike::kcpSocket(new KcpSocket());
}



#ifndef QTNG_NO_CRYPTO

class SslServerPrivate: public BaseStreamServerPrivate
{
public:
    SslServerPrivate(SslServer *q, const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        :BaseStreamServerPrivate(q, serverAddress, serverPort), configuration(configuration) {}
public:
    SslConfiguration configuration;
};


SslServer::SslServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
    :BaseStreamServer (new SslServerPrivate(this, serverAddress, serverPort, configuration))
{
}


SslServer::SslServer(const QHostAddress &serverAddress, quint16 serverPort)
    :BaseStreamServer (new SslServerPrivate(this, serverAddress, serverPort, SslConfiguration()))
{
    Q_D(SslServer);
    d->configuration = SslConfiguration::testPurpose("SslServer", "CN", "QtNetworkNg");
}


void SslServer::setSslConfiguration(const SslConfiguration &configuration)
{
    Q_D(SslServer);
    d->configuration = configuration;
}


SslConfiguration SslServer::sslConfiguratino() const
{
    Q_D(const SslServer);
    return d->configuration;
}


bool SslServer::isSecure() const
{
    return true;
}


QSharedPointer<SocketLike> SslServer::serverCreate()
{
    Q_D(SslServer);
    return SocketLike::sslSocket(QSharedPointer<SslSocket>::create(d->configuration));
}

#endif  // QTNG_NO_CRYPTO


BaseRequestHandler::BaseRequestHandler(QSharedPointer<SocketLike> request, BaseStreamServer *server)
    :request(request), server(server)
{

}


BaseRequestHandler::~BaseRequestHandler()
{

}


void BaseRequestHandler::run()
{
    setup();
    try {
        handle();
        finish();
    } catch (...) {
        finish();
    }
}


void BaseRequestHandler::setup()
{

}


void BaseRequestHandler::handle()
{

}


void BaseRequestHandler::finish()
{
    request->close();
}


QTNETWORKNG_NAMESPACE_END
