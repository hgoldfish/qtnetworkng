#include <QtCore/qendian.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qurl.h>
#include "../include/socket_server.h"
#include "debugger.h"

QTNG_LOGGER("qtng.socks5server");


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


void Socks5RequestHandler::doConnect(const QString &hostName, const HostAddress &hostAddress, quint16 port)
{
    HostAddress forwardAddress;
    QSharedPointer<SocketLike> forward = makeConnection(hostName, hostAddress, port, &forwardAddress);
    if (forward.isNull()) {
        sendFailedReply();
        logProxy(hostName, hostAddress, port, forwardAddress, false);
        return;
    }
    if (!sendConnectReply(forwardAddress, port)) {
        logProxy(hostName, forwardAddress, port, forwardAddress, false);
        return;
    } else {
        logProxy(hostName, forwardAddress, port, forwardAddress, true);
    }
    exchange(request, forward);
}


bool Socks5RequestHandler::sendConnectReply(const HostAddress &hostAddress, quint16 port)
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
    if (!ok && hostAddress.protocol() == HostAddress::IPv4Protocol) {
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
    } else if (hostAddress.protocol() == HostAddress::IPv6Protocol) {
        reply.resize(22);
        IPv6Address ipv6 = hostAddress.toIPv6Address();
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


void Socks5RequestHandler::logProxy(const QString &hostName, const HostAddress &hostAddress, quint16 port,
                                    const HostAddress &forwardAddress, bool success)
{
    const QString &status = success? QLatin1String("OK"): QLatin1String("FAIL");
    const QDateTime &now = QDateTime::currentDateTime();
    QString host;
    if (hostName.isEmpty()) {
        host = hostAddress.toString();
    } else {
        host = hostName;
    }
    const QString &message = QString::fromLatin1("%1 -- %2 CONNECT %3 -> %4:%5 %6")
            .arg(request->peerAddress().toString())
            .arg(now.toString(Qt::ISODate))
            .arg(host)
            .arg(forwardAddress.toString())
            .arg(port)
            .arg(status);
    printf("%s\n", qPrintable(message));
}


void Socks5RequestHandler::exchange(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward)
{
    Exchanger exchanger(request, forward);
    exchanger.exchange();
}


void Socks5RequestHandler::doFailed(const QString &hostName, const HostAddress &hostAddress, quint16 port)
{
    QByteArray reply(3, Qt::Uninitialized);
    reply[0] = S5_VERSION_5;
    reply[1] = S5_R_ERROR_CMD_NOT_SUPPORTED;
    reply[2] = 0x00;
    request->sendall(reply);
    logProxy(hostName, hostAddress, port, HostAddress(), false);
}


QSharedPointer<SocketLike> Socks5RequestHandler::makeConnection(const QString &hostName, const HostAddress &hostAddress,
                                                                quint16 port, HostAddress *forwardAddress)
{
    QScopedPointer<Socket> s;
    if (!hostName.isEmpty()) {
        s.reset(Socket::createConnection(hostName, port));
    } else if (!hostAddress.isNull()) {
        s.reset(Socket::createConnection(hostAddress, port));
    }
    if (!s.isNull()) {
        if (forwardAddress) {
            *forwardAddress = s->peerAddress();
        }
        return asSocketLike(s.take());
    } else {
        return QSharedPointer<SocketLike>();
    }
}


bool Socks5RequestHandler::sendFailedReply()
{
    QByteArray reply(3, Qt::Uninitialized);
    reply[0] = S5_VERSION_5;
    reply[1] = S5_R_ERROR_SOCKS_FAILURE;
    reply[2] = 0x00;
    return request->sendall(reply) == 3;
}


void Socks5RequestHandler::handle()
{
    if (!handshake()) {
        return;
    }
    // parse command.
    const QByteArray &commandHeader = request->recvall(2);
    if (commandHeader.size() < 2 || commandHeader.at(0) != S5_VERSION_5){
        logProxy(QString(), HostAddress(), 0, HostAddress(), false);
        return;
    }

    QString hostName;
    HostAddress addr;
    quint16 port;

    if (!parseAddress(&hostName, &addr, &port)) {
        logProxy(QString(), HostAddress(), 0, HostAddress(), false);
        return;
    }

    if ((hostName.isEmpty() && addr.isNull()) || port == 0) {
        logProxy(QString(), HostAddress(), 0, HostAddress(), false);
        return;
    }

    switch (commandHeader.at(1)) {
    case S5_CONNECT:
        doConnect(hostName, addr, port);
        break;
    default:
        qtng_debug << "unsupported command: " << commandHeader.at(1);
        doFailed(hostName, addr, port);
        break;
    }
}


bool Socks5RequestHandler::handshake()
{
    const QByteArray &header = request->recvall(2);
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
        QByteArray authMethods = request->recvall(methods);
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
        replyHeader[1] = std::numeric_limits<char>::is_signed ? -1 : S5_AUTHMETHOD_NOTACCEPTABLE;
    }
    qint32 sentBytes = request->sendall(replyHeader);
    if (sentBytes != replyHeader.size()) {
        qtng_debug << "can not send reply header.";
        return false;
    }
    return ok;
}


bool Socks5RequestHandler::parseAddress(QString *hostName, HostAddress *addr, quint16 *port)
{
    const QByteArray &addressType = request->recvall(2);
    if (addressType.size() < 2 || addressType.at(0) != 0x00) {
        return false;
    }

    if (addressType.at(1) == S5_IP_V4) {
        const QByteArray &ipv4 = request->recvall(4);
        if(ipv4.size() < 4) {
            return false;
        }
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        addr->setAddress(qFromBigEndian<quint32>(ipv4.constData()));
#else
        addr->setAddress(qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(ipv4.constData())));
#endif
    } else if(addressType.at(1) == S5_IP_V6){
        QByteArray ipv6 = request->recvall(16);
        if(ipv6.size() < 16) {
            return false;
        }
        addr->setAddress(reinterpret_cast<quint8*>(ipv6.data()));
    } else if(addressType.at(1) == S5_DOMAINNAME) {
        const QByteArray &len = request->recvall(1);
        if(len.isEmpty()) {
            return false;
        }

        const QByteArray &buf = request->recvall(quint8(len.at(0)));
        if(buf.size() < len.at(0)) {
            return false;
        }
        *hostName = QUrl::fromAce(buf);
    } else {
        return false;
    }

    const QByteArray &portBytes = request->recvall(2);
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


QTNETWORKNG_NAMESPACE_END
