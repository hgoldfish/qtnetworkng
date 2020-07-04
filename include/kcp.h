#ifndef QTNG_KCP_H
#define QTNG_KCP_H

#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN


class KcpSocketPrivate;
class KcpSocket
{
public:
    enum Mode {
        LargeDelayInternet,
        Internet,
        FastInternet,
        Ethernet,
        Loopback,
    };
public:
    explicit KcpSocket(Socket::NetworkLayerProtocol protocol=Socket::IPv4Protocol);
    explicit KcpSocket(qintptr socketDescriptor);
    explicit KcpSocket(QSharedPointer<Socket> rawSocket);
    virtual ~KcpSocket();
public:
    void setMode(Mode mode);
    Mode mode() const;
    void setSendQueueSize(quint32 sendQueueSize);
    quint32 sendQueueSize() const;
    void setUdpPacketSize(quint32 udpPacketSize);
    quint32 udpPacketSize() const;
    quint32 payloadSizeHint() const;
    QSharedPointer<Event> busy;
    QSharedPointer<Event> notBusy;
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
    QSharedPointer<KcpSocket> accept(const QHostAddress &addr, quint16 port);
    QSharedPointer<KcpSocket> accept(const QString &hostName, quint16 port,
                                     QSharedPointer<SocketDnsCache> dnsCache=QSharedPointer<SocketDnsCache>());

    bool bind(const QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const QHostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache=QSharedPointer<SocketDnsCache>());
    void close();
    void abort();
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

    virtual bool filter(char *data, qint32 *len, QHostAddress *addr, quint16 *port);
    qint32 udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port);
    qint32 udpSend(const QByteArray &packet, const QHostAddress &addr, quint16 port)
        { return udpSend(packet.constData(), packet.size(), addr, port); }

    static QSharedPointer<KcpSocket> createConnection(const QHostAddress &host, quint16 port, Socket::SocketError *error = nullptr,
                                      int allowProtocol = Socket::IPv4Protocol | Socket::IPv6Protocol);
    static QSharedPointer<KcpSocket> createConnection(const QString &hostName, quint16 port, Socket::SocketError *error = nullptr,
                                  QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                                  int allowProtocol = Socket::IPv4Protocol | Socket::IPv6Protocol);
    static QSharedPointer<KcpSocket> createServer(const QHostAddress &host, quint16 port, int backlog = 50);
private:
    // for create SlaveKcpSocket.
    KcpSocket(KcpSocketPrivate *d, const QHostAddress &addr, const quint16 port, KcpSocket::Mode mode);
    friend class SlaveKcpSocketPrivate;
private:
    KcpSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KcpSocket)
};


QSharedPointer<class SocketLike> asSocketLike(QSharedPointer<KcpSocket> s);


inline QSharedPointer<class SocketLike> asSocketLike(KcpSocket *s) { return asSocketLike(QSharedPointer<KcpSocket>(s)); }


QSharedPointer<KcpSocket> convertSocketLikeToKcpSocket(QSharedPointer<class SocketLike> socket);

QTNETWORKNG_NAMESPACE_END
#endif
