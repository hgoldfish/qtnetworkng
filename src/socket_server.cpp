#include <QtCore/qloggingcategory.h>
#include "../include/socket_server.h"

static Q_LOGGING_CATEGORY(logger, "qtng.socket_server")

QTNETWORKNG_NAMESPACE_BEGIN

class BaseStreamServerPrivate
{
public:
    BaseStreamServerPrivate(const QHostAddress &serverAddress, quint16 serverPort)
        :serverAddress(serverAddress),
          serverSocket(new Socket()),
          operations(new CoroutineGroup),
          requestQueueSize(100),
          serverPort(serverPort),
          allowReuseAddress(true)
    {}

    ~BaseStreamServerPrivate() { delete operations; }
public:
    QHostAddress serverAddress;
    QSharedPointer<Socket> serverSocket;
    CoroutineGroup *operations;
    int requestQueueSize;
    quint16 serverPort;
    bool allowReuseAddress;
};

BaseStreamServer::BaseStreamServer(const QHostAddress &serverAddress, quint16 serverPort)
    :started(new Event()), stopped(new Event()), d_ptr(new BaseStreamServerPrivate(serverAddress, serverPort))
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


bool BaseStreamServer::serveForever()
{
    Q_D(BaseStreamServer);
    if (!serverBind()) {
        serverClose();
        return false;
    }
    if (!serverActivate()) {
        serverClose();
        return false;
    }

    started->set();
    stopped->clear();
    while(true) {
        QSharedPointer<SocketLike> request = getRequest();
        if (request.isNull()) {
            break;
        }
        if (verifyRequest(request)) {
            d->operations->spawn([this, request] {
                try {
                    processRequest(request); // close request.
                } catch (CoroutineExitException &) {
                    shutdownRequest(request);
                    closeRequest(request);
                } catch (...) {
                    handleError(request);
                    shutdownRequest(request);
                    closeRequest(request);
                }
            });
        } else {
            shutdownRequest(request);
            closeRequest(request);
        }
        if (!serviceActions()) {
            break;
        }
    }
    serverClose();
    started->clear();
    stopped->set();
    return true;
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
    Socket *request = d->serverSocket->accept();
    if (request) {
        return SocketLike::rawSocket(request);
    } else {
        return QSharedPointer<SocketLike>();
    }
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
class BaseSslStreamServerPrivate: public BaseStreamServerPrivate
{
public:
    BaseSslStreamServerPrivate(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
        :BaseStreamServerPrivate(serverAddress, serverPort), configuration(configuration) {}
public:
    SslConfiguration configuration;
};


BaseSslStreamServer::BaseSslStreamServer(const QHostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration)
    :BaseStreamServer (new BaseSslStreamServerPrivate(serverAddress, serverPort, configuration))
{
}

BaseSslStreamServer::BaseSslStreamServer(const QHostAddress &serverAddress, quint16 serverPort)
    :BaseStreamServer (new BaseSslStreamServerPrivate(serverAddress, serverPort, SslConfiguration()))
{
    Q_D(BaseSslStreamServer);
    d->configuration = SslConfiguration::testPurpose("SslServer", "CN", "QtNetworkNg");
}

void BaseSslStreamServer::setSslConfiguration(const SslConfiguration &configuration)
{
    Q_D(BaseSslStreamServer);
    d->configuration = configuration;
}

SslConfiguration BaseSslStreamServer::sslConfiguratino() const
{
    Q_D(const BaseSslStreamServer);
    return d->configuration;
}

QSharedPointer<SocketLike> BaseSslStreamServer::getRequest()
{
    Q_D(BaseSslStreamServer);
    while(true) {
        Socket *request = d->serverSocket->accept();
        if (request) {
            QSharedPointer<SslSocket> sslSocket(new SslSocket(QSharedPointer<Socket>(request), d->configuration));
            if (!sslSocket->handshake(true)) {
                continue;
            }
            return SocketLike::sslSocket(sslSocket);
        } else {
            return QSharedPointer<SocketLike>();
        }
    }
}

bool BaseSslStreamServer::isSecure() const
{
    return true;
}

#endif

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
