#include <QtCore/qendian.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qurl.h>
#include "../include/socket_server.h"


#define S5_VERSION_5 0x05
#define S5_CONNECT 0x01
#define S5_BIND 0x02
#define S5_UDP_ASSOCIATE 0x03
#define S5_IP_V4 0x01
#define S5_DOMAINNAME 0x03
#define S5_IP_V6 0x04
#define S5_SUCCESS 0x00
#define S5_R_ERROR_SOCKS_FAILURE 0x01
#define S5_R_ERROR_CON_NOT_ALLOWED 0x02
#define S5_R_ERROR_NET_UNREACH 0x03
#define S5_R_ERROR_HOST_UNREACH 0x04
#define S5_R_ERROR_CONN_REFUSED 0x05
#define S5_R_ERROR_TTL 0x06
#define S5_R_ERROR_CMD_NOT_SUPPORTED 0x07
#define S5_R_ERROR_ADD_TYPE_NOT_SUPORTED 0x08

#define S5_AUTHMETHOD_NONE 0x00
#define S5_AUTHMETHOD_PASSWORD 0x02
#define S5_AUTHMETHOD_NOTACCEPTABLE 0xFF

#define S5_PASSWORDAUTH_VERSION 0x01

QTNETWORKNG_NAMESPACE_BEGIN

class Socks5RequestHandlerPrivate
{
public:
    Socks5RequestHandlerPrivate(Socks5RequestHandler *q);
public:
    void handleRequest();
    bool handshake();
    bool parseAddress(QString *hostName, QHostAddress *addr, quint16 *port);
    void handleConnectCommand(const QString &hostName, const QHostAddress &addr, quint16 port);
private:
    Socks5RequestHandler * const q_ptr;
    Q_DECLARE_PUBLIC(Socks5RequestHandler)
};


Socks5RequestHandlerPrivate::Socks5RequestHandlerPrivate(Socks5RequestHandler *q)
    :q_ptr(q)
{

}


void Socks5RequestHandlerPrivate::handleRequest()
{
    Q_Q(Socks5RequestHandler);
    if (!handshake()) {
        return;
    }

    // parse command.
    const QByteArray &commandHeader = q->request->recvall(2);
    if (commandHeader.size() < 2 || commandHeader.at(0) != S5_VERSION_5){
        q->log(QString(), QHostAddress(), 0, false);
        return;
    }

    QString hostName;
    QHostAddress addr;
    quint16 port;

    if (!parseAddress(&hostName, &addr, &port)) {
        q->log(QString(), QHostAddress(), 0, false);
        return;
    }

    if ((hostName.isEmpty() && addr.isNull()) || port == 0) {
        q->log(QString(), QHostAddress(), 0, false);
        return;
    }

    switch (commandHeader.at(1)) {
    case S5_CONNECT:
        q->doConnect(hostName, addr, port);
        break;
    default:
        qDebug() << "unsupported command: " << commandHeader.at(1);
        q->doFailed(hostName, addr, port);
        break;
    }
}


bool Socks5RequestHandlerPrivate::handshake()
{
    Q_Q(Socks5RequestHandler);
    const QByteArray &header = q->request->recvall(2);
    if (header.size() != 2) {
        return false;
    }
    if (header.at(0) != S5_VERSION_5) {
        return false;
    }
    uchar methods = static_cast<uchar>(header.at(1));
    bool ok = true;
    if (methods == 0) {
        ok = true;
    } else {
        QByteArray authMethods = q->request->recvall(methods);
        if (authMethods.size() != methods) {
            return false;
        }
        if (authMethods.indexOf(static_cast<char>(S5_AUTHMETHOD_NONE)) < 0) {
            ok = false;
        }
    }
    QByteArray replyHeader(2, Qt::Uninitialized);
    replyHeader[0] = S5_VERSION_5;
    if (ok) {
        replyHeader[1] = S5_AUTHMETHOD_NONE;
    } else {
        replyHeader[1] = static_cast<char>(S5_AUTHMETHOD_NOTACCEPTABLE);
    }
    qint32 sentBytes = q->request->sendall(replyHeader);
    if (sentBytes != replyHeader.size()) {
        qDebug() << "can not send reply header.";
        return false;
    }
    return ok;
}


bool Socks5RequestHandlerPrivate::parseAddress(QString *hostName, QHostAddress *addr, quint16 *port)
{
    Q_Q(Socks5RequestHandler);
    const QByteArray &addressType = q->request->recvall(2);
    if (addressType.size() < 2 || addressType.at(0) != 0x00) {
        return false;
    }

    if (addressType.at(1) == S5_IP_V4) {
        const QByteArray &ipv4 = q->request->recvall(4);
        if(ipv4.size() < 4) {
            return false;
        }
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        addr->setAddress(qFromBigEndian<quint32>(ipv4.constData()));
#else
        addr->setAddress(qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(ipv4.constData())));
#endif
    } else if(addressType.at(1) == S5_IP_V6){
        QByteArray ipv6 = q->request->recvall(16);
        if(ipv6.size() < 16) {
            return false;
        }
        addr->setAddress(reinterpret_cast<quint8*>(ipv6.data()));
    } else if(addressType.at(1) == S5_DOMAINNAME) {
        const QByteArray &len = q->request->recvall(1);
        if(len.isEmpty()) {
            return false;
        }

        const QByteArray &buf = q->request->recvall(quint8(len.at(0)));
        if(buf.size() < len.at(0)) {
            return false;
        }
        *hostName = QUrl::fromAce(buf);
    } else {
        return false;
    }

    const QByteArray &portBytes = q->request->recvall(2);
    if(portBytes.size() < 2) {
        return false;
    }
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    *port = qFromBigEndian<quint16>(portBytes.constData());
#else
    *port = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(portBytes.constData()));
#endif
    return true;
}


void Socks5RequestHandlerPrivate::handleConnectCommand(const QString &hostName, const QHostAddress &addr, quint16 port)
{
    Q_Q(Socks5RequestHandler);
    QSharedPointer<Socket> forward(new Socket);
    if (!hostName.isEmpty()) {
        bool ok = forward->connect(hostName, port);
        if (!ok) {
            q->sendFailedReply();
            q->log(hostName, addr, port, false);
            return;
        }
    } else if (!addr.isNull()) {
        bool ok = forward->connect(addr, port);
        if (!ok) {
            q->sendFailedReply();
            q->log(hostName, addr, port, false);
            return;
        }
    } else {
        q->sendFailedReply();
        q->log(hostName, addr, port, false);
        return;
    }
    Q_ASSERT(forward->state() == Socket::ConnectedState);
    if (!q->sendConnectReply(forward->peerAddress(), port)) {
        q->log(hostName, forward->peerAddress(), port, false);
        return;
    } else {
        q->log(hostName, forward->peerAddress(), port, true);
    }
    Exchanger exchanger(q->request, asSocketLike(forward));
    exchanger.exchange();
}



Socks5RequestHandler::Socks5RequestHandler()
    :BaseRequestHandler(), d_ptr(new Socks5RequestHandlerPrivate(this))
{

}


Socks5RequestHandler::~Socks5RequestHandler() {}


void Socks5RequestHandler::doConnect(const QString &hostName, const QHostAddress &hostAddress, quint16 port)
{
    Q_D(Socks5RequestHandler);
    d->handleConnectCommand(hostName, hostAddress, port);
}


bool Socks5RequestHandler::sendConnectReply(const QHostAddress &hostAddress, quint16 port)
{
    bool ok;
    if (hostAddress.isNull()) {
        return false;
    }
    QByteArray reply;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    quint32 ipv4 = hostAddress.toIPv4Address(&ok);
#else
    quint32 ipv4 = hostAddress.toIPv4Address();
    ok = (ipv4 != 0);
#endif
    if (!ok && hostAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return false;
    }
    if (ok && ipv4) {
        reply.resize(10);
        reply[0] = S5_VERSION_5;
        reply[1] = S5_SUCCESS;
        reply[2] = 0x00;
        reply[3] = S5_IP_V4;
    #if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        qToBigEndian<quint32>(ipv4, reply.data() + 4);
        qToBigEndian<quint16>(port, reply.data() + 4 + 4);
    #else
        qToBigEndian<quint32>(ipv4, reinterpret_cast<uchar*>(reply.data() + 4));
        qToBigEndian<quint16>(port, reinterpret_cast<uchar*>(reply.data() + 4 + 4));
    #endif
    } else if (hostAddress.protocol() == QAbstractSocket::IPv6Protocol) {
        reply.resize(22);
        Q_IPV6ADDR ipv6 = hostAddress.toIPv6Address();
        reply[0] = S5_VERSION_5;
        reply[1] = S5_SUCCESS;
        reply[2] = 0x00;
        reply[3] = S5_IP_V6;
        memcpy(reply.data() + 4, reinterpret_cast<char*>(ipv6.c), 16);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        qToBigEndian<quint16>(port, reply.data() + 4 + 16);
#else
        qToBigEndian<quint16>(port, reinterpret_cast<uchar*>(reply.data() + 4 + 16));
#endif
    }

    return request->sendall(reply) == reply.size();
}


void Socks5RequestHandler::log(const QString &hostName, const QHostAddress &hostAddress, quint16 port, bool success)
{
    QString status = success? QStringLiteral("OK"): QStringLiteral("FAIL");
    const QDateTime &now = QDateTime::currentDateTime();
    QString message = QStringLiteral("%1 -- %2 CONNECT %3 -> %4:%5 %6")
            .arg(request->peerAddress().toString())
            .arg(now.toString(Qt::ISODate))
            .arg(hostName)
            .arg(hostAddress.toString())
            .arg(port)
            .arg(status);
    printf("%s\n", qPrintable(message));
}


void Socks5RequestHandler::doFailed(const QString &hostName, const QHostAddress &hostAddress, quint16 port)
{
    QByteArray reply(3, Qt::Uninitialized);
    reply[0] = S5_VERSION_5;
    reply[1] = S5_R_ERROR_CMD_NOT_SUPPORTED;
    reply[3] = 0x00;
    request->sendall(reply);
    log(hostName, hostAddress, port, false);
}


bool Socks5RequestHandler::sendFailedReply()
{
    QByteArray reply(3, Qt::Uninitialized);
    reply[0] = S5_VERSION_5;
    reply[1] = S5_R_ERROR_SOCKS_FAILURE;
    reply[3] = 0x00;
    return request->sendall(reply) == 3;
}


void Socks5RequestHandler::handle()
{
    Q_D(Socks5RequestHandler);
    d->handleRequest();
}

QTNETWORKNG_NAMESPACE_END
