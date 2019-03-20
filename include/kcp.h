#ifndef QTNG_KCP_H
#define QTNG_KCP_H

#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN

class KcpSocketPrivate;
class KcpSocket
{
public:
    enum Mode {
        Internet,
        Ethernet,
        Loopback,
    };
public:
    KcpSocket(Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol);
    KcpSocket(qintptr socketDescriptor);
    KcpSocket(QSharedPointer<Socket> rawSocket);
    ~KcpSocket();
public:
    void setMode(Mode mode);
    Mode mode() const;
    void setCompression(bool compress);
    bool compression() const;
public:
    Socket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    QHostAddress localAddress() const;
    quint16 localPort() const;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    Socket::SocketType type() const;
    Socket::SocketState state() const;
    Socket::NetworkLayerProtocol protocol() const;

    QSharedPointer<KcpSocket> accept();
    bool bind(QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol);
    bool close();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    QByteArray recv(qint32 size);
    QByteArray recvall(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);
private:
    KcpSocket(KcpSocketPrivate *d);
private:
    KcpSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KcpSocket)
};

QSharedPointer<KcpSocket> convertSocketLikeToKcpSocket(QSharedPointer<class SocketLike> socket);

QTNETWORKNG_NAMESPACE_END
#endif
