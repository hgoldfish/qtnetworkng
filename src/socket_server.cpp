#include <QtCore/qloggingcategory.h>
#include "../include/socket_server.h"

// #define DEBUG_PROTOCOL 1

#ifdef DEBUG_PROTOCOL
static Q_LOGGING_CATEGORY(logger, "qtng.socket_server");
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class BaseStreamServerPrivate
{
public:
    BaseStreamServerPrivate(BaseStreamServer *q, const HostAddress &serverAddress, quint16 serverPort)
        : operations(new CoroutineGroup)
        , serverAddress(serverAddress)
        , userData(nullptr)
        , requestQueueSize(100)
        , serverPort(serverPort)
        , allowReuseAddress(true)
        , bound(false)
        , q_ptr(q)
    {
    }
    ~BaseStreamServerPrivate() { delete operations; }
    void serveForever();
public:
    QSharedPointer<SocketLike> serverSocket;
    CoroutineGroup *operations;
    HostAddress serverAddress;
    void *userData;
    int requestQueueSize;
    quint16 serverPort;
    bool allowReuseAddress;
    bool bound;
private:
    BaseStreamServer * const q_ptr;
    Q_DECLARE_PUBLIC(BaseStreamServer)
};

BaseStreamServer::BaseStreamServer(const HostAddress &serverAddress, quint16 serverPort)
    : started(new Event())
    , stopped(new Event())
    , d_ptr(new BaseStreamServerPrivate(this, serverAddress, serverPort))
{
    started->clear();
    stopped->set();
}

BaseStreamServer::BaseStreamServer(BaseStreamServerPrivate *d)
    : d_ptr(d)
{
    started->clear();
    stopped->set();
}

BaseStreamServer::~BaseStreamServer()
{
    stop();
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
    if (d->bound) {
        Socket::SocketState state = d->serverSocket->state();
        return state == Socket::BoundState || state == Socket::ListeningState;
    }

    Socket::BindMode mode;
    if (d->allowReuseAddress) {
        mode = Socket::ReuseAddressHint;
    } else {
        mode = Socket::DefaultForPlatform;
    }
    d->bound = d->serverSocket->bind(d->serverAddress, d->serverPort, mode);
#ifdef DEBUG_PROTOCOL
    if (!ok) {
        qCInfo(logger) << "server can not bind to" << d->serverAddress.toString() << ":" << d->serverPort;
    }
#endif
    return d->bound;
}

bool BaseStreamServer::serverActivate()
{
    Q_D(BaseStreamServer);
    if (!d->bound) {
        return false;
    }
    if (d->serverSocket->state() == Socket::ListeningState) {
        return true;
    }
    if (d->serverSocket->state() != Socket::BoundState) {
        return false;
    }
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
                Q_Q(BaseStreamServer);
                QSharedPointer<SocketLike> sslRequest = q->prepareRequest(request);
                if (!sslRequest.isNull()) {
                    try {
                        q->processRequest(sslRequest);  // close request.
                        return;
                    } catch (CoroutineExitException &) {
                    } catch (...) {
                        q->handleError(sslRequest);
                    }
                    q->closeRequest(sslRequest);
                }
            });
        } else {
            request->close();
        }
        if (!q->serviceActions()) {
            break;
        }
    }
    q->serverClose();
    q->started->clear();
    q->stopped->set();
}

bool BaseStreamServer::serveForever()
{
    Q_D(BaseStreamServer);
    if (d->serverSocket.isNull()) {
        d->serverSocket = serverCreate();
    }
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

    if (started->isSet() || d->operations->has(QString::fromLatin1("serve"))) {
        return true;
    }
    if (d->serverSocket.isNull()) {
        d->serverSocket = serverCreate();
    }
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
    d->operations->spawnWithName(QString::fromLatin1("serve"), [d] { d->serveForever(); });
    return true;
}

void BaseStreamServer::stop()
{
    Q_D(BaseStreamServer);
    if (!d->serverSocket.isNull()) {
        serverClose();
    }
}

bool BaseStreamServer::wait()
{
    Q_D(BaseStreamServer);
    QSharedPointer<Coroutine> coroutine = d->operations->get(QString::fromLatin1("serve"));
    if (coroutine.isNull()) {
        return true;
    }
    if (coroutine->isFinished() || stopped->isSet()) {
        return true;
    }
    return coroutine->join();
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

HostAddress BaseStreamServer::serverAddress() const
{
    Q_D(const BaseStreamServer);
    return d->serverAddress;
}

QSharedPointer<SocketLike> BaseStreamServer::serverSocket()
{
    Q_D(const BaseStreamServer);
    if (d->serverSocket.isNull()) {
        serverCreate();
    }
    return d->serverSocket;
}

bool BaseStreamServer::serviceActions()
{
    return true;
}

QSharedPointer<SocketLike> BaseStreamServer::prepareRequest(QSharedPointer<SocketLike> request)
{
    return request;
}

bool BaseStreamServer::verifyRequest(QSharedPointer<SocketLike>)
{
    return true;
}

QSharedPointer<SocketLike> BaseStreamServer::getRequest()
{
    Q_D(BaseStreamServer);
    return d->serverSocket->accept();
}

void BaseStreamServer::handleError(QSharedPointer<SocketLike>) { }

void BaseStreamServer::closeRequest(QSharedPointer<SocketLike> request)
{
    request->close();
}

BaseRequestHandler::BaseRequestHandler() { }

BaseRequestHandler::~BaseRequestHandler() { }

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

void BaseRequestHandler::handle() { }

void BaseRequestHandler::finish()
{
    if (!request.isNull()) {
        request->close();
    }
}

QTNETWORKNG_NAMESPACE_END
