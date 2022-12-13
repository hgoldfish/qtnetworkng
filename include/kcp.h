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
    explicit KcpSocket(HostAddress::NetworkLayerProtocol protocol = HostAddress::IPv4Protocol);
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
    void setTearDownTime(float secs);
    float tearDownTime() const;
    Event busy;
    Event notBusy;
public:
    Socket::SocketError error() const;
    QString errorString() const;
    bool isValid() const;
    HostAddress localAddress() const;
    quint16 localPort() const;
    HostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    Socket::SocketType type() const;
    Socket::SocketState state() const;
    HostAddress::NetworkLayerProtocol protocol() const;
    QString localAddressURI() const;
    QString peerAddressURI() const;

    KcpSocket *accept();
    KcpSocket *accept(const HostAddress &addr, quint16 port);
    KcpSocket *accept(const QString &hostName, quint16 port,
                      QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>());

    bool bind(const HostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform);
    bool connect(const HostAddress &addr, quint16 port);
    bool connect(const QString &hostName, quint16 port,
                 QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>());
    void close();
    void abort();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

    bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface = NetworkInterface());
    bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface = NetworkInterface());
    NetworkInterface multicastInterface() const;
    bool setMulticastInterface(const NetworkInterface &iface);

    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    QByteArray recv(qint32 size);
    QByteArray recvall(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);

    virtual bool filter(char *data, qint32 *len, HostAddress *addr, quint16 *port);
    qint32 udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port);
    qint32 udpSend(const QByteArray &packet, const HostAddress &addr, quint16 port)
    {
        return udpSend(packet.constData(), packet.size(), addr, port);
    }

    static KcpSocket *createConnection(const HostAddress &host, quint16 port, Socket::SocketError *error = nullptr,
                                       int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol);
    static KcpSocket *createConnection(const QString &hostName, quint16 port, Socket::SocketError *error = nullptr,
                                       QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>(),
                                       int allowProtocol = HostAddress::IPv4Protocol | HostAddress::IPv6Protocol);
    // if backlog == 0, do not bind and listen.
    static KcpSocket *createServer(const HostAddress &host, quint16 port, int backlog = 50);
private:
    // for create SlaveKcpSocket.
    KcpSocket(KcpSocketPrivate *d, const HostAddress &addr, const quint16 port, KcpSocket::Mode mode);
    friend class SlaveKcpSocketPrivate;
private:
    KcpSocketPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(KcpSocket)
};

QSharedPointer<class SocketLike> asSocketLike(QSharedPointer<KcpSocket> s);

inline QSharedPointer<class SocketLike> asSocketLike(KcpSocket *s)
{
    return asSocketLike(QSharedPointer<KcpSocket>(s));
}

QSharedPointer<KcpSocket> convertSocketLikeToKcpSocket(QSharedPointer<class SocketLike> socket);

QTNETWORKNG_NAMESPACE_END
#endif
