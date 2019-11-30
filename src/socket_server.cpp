#include <QtCore/qloggingcategory.h>
#include "../include/socket_server.h"

// #define DEBUG_PROTOCOL 1

#ifdef DEBUG_PROTOCOL
static Q_LOGGING_CATEGORY(logger, "qtng.socket_server")
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class BaseStreamServerPrivate
{
public:
    BaseStreamServerPrivate(BaseStreamServer *q, const QHostAddress &serverAddress, quint16 serverPort)
        : operations(new CoroutineGroup)
        , serverAddress(serverAddress)
        , userData(nullptr)
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
    void *userData;
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
#ifdef DEBUG_PROTOCOL
    if (!ok) {
        qCInfo(logger) << "server can not bind to" << d->serverAddress.toString() << ":" << d->serverPort;
    }
#endif
    return ok;
}


bool BaseStreamServer::serverActivate()
{
    Q_D(BaseStreamServer);
    bool ok = d->serverSocket->listen(d->requestQueueSize);
#ifdef DEBUG_PROTOCOL
    if (!ok) {
        qCInfo(logger) << "server can not listen to" << d->serverAddress.toString() << ":" << d->serverPort;
    }
#endif
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


void BaseStreamServer::setUserData(void *data)
{
    Q_D(BaseStreamServer);
    d->userData = data;
}


void *BaseStreamServer::userData() const
{
    Q_D(const BaseStreamServer);
    return d->userData;
}


quint16 BaseStreamServer::serverPort() const
{
    Q_D(const BaseStreamServer);
    if (d->serverPort) {
        return d->serverPort;
    } else if (!d->serverSocket.isNull() && d->serverSocket->isValid()) {
        return d->serverSocket->localPort();
    } else {
        return 0;
    }
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


#ifndef QTNG_NO_CRYPTO

class BaseSslServerPrivate: public BaseStreamServerPrivate
{
public:
    BaseSslServerPrivate(BaseSslServer *q, const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        :BaseStreamServerPrivate(q, serverAddress, serverPort), configuration(configuration) {}
public:
    SslConfiguration configuration;
};


BaseSslServer::BaseSslServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
    :BaseStreamServer (new BaseSslServerPrivate(this, serverAddress, serverPort, configuration))
{
}


BaseSslServer::BaseSslServer(const QHostAddress &serverAddress, quint16 serverPort)
    :BaseStreamServer (new BaseSslServerPrivate(this, serverAddress, serverPort, SslConfiguration()))
{
    Q_D(BaseSslServer);
    d->configuration = SslConfiguration::testPurpose("SslServer", "CN", "QtNetworkNg");
}


void BaseSslServer::setSslConfiguration(const SslConfiguration &configuration)
{
    Q_D(BaseSslServer);
    d->configuration = configuration;
}


SslConfiguration BaseSslServer::sslConfiguratino() const
{
    Q_D(const BaseSslServer);
    return d->configuration;
}


bool BaseSslServer::isSecure() const
{
    return true;
}


QSharedPointer<SocketLike> BaseSslServer::serverCreate()
{
    Q_D(BaseSslServer);
    return asSocketLike(QSharedPointer<SslSocket>::create(d->configuration));
}


#endif  // QTNG_NO_CRYPTO


BaseRequestHandler::BaseRequestHandler()
{

}


BaseRequestHandler::~BaseRequestHandler()
{

}


void BaseRequestHandler::run()
{
    if (!setup()) {
        return;
    }
    try {
        handle();
        finish();
    } catch (...) {
        finish();
    }
}


bool BaseRequestHandler::setup()
{
    return true;
}


void BaseRequestHandler::handle()
{

}


void BaseRequestHandler::finish()
{
    request->close();
}


QTNETWORKNG_NAMESPACE_END
