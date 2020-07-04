#include <QtCore/qdatetime.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qendian.h>
#include "../include/kcp.h"
#include "../include/socket_utils.h"
#include "../include/coroutine_utils.h"
#include "../include/random.h"
#include "../include/private/socket_p.h"
#include "./kcp/ikcp.h"
QTNETWORKNG_NAMESPACE_BEGIN

const char PACKET_TYPE_UNCOMPRESSED_DATA = 0x01;
const char PACKET_TYPE_CREATE_MULTIPATH = 0x02;
const char PACKET_TYPE_CLOSE= 0X03;
const char PACKET_TYPE_KEEPALIVE = 0x04;
//#define DEBUG_PROTOCOL 1


class SlaveKcpSocketPrivate;
class KcpSocketPrivate: public QObject
{
public:
    KcpSocketPrivate(KcpSocket *q);
    virtual ~KcpSocketPrivate() override;
public:
    virtual Socket::SocketError getError() const = 0;
    virtual QString getErrorString() const = 0;
    virtual bool isValid() const = 0;
    virtual QHostAddress localAddress() const = 0;
    virtual quint16 localPort() const = 0;
    QHostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    Socket::SocketType type() const;
    virtual Socket::NetworkLayerProtocol protocol() const = 0;
public:
    virtual QSharedPointer<KcpSocket> accept() = 0;
    virtual QSharedPointer<KcpSocket> accept(const QHostAddress &addr, quint16 port) = 0;
    virtual QSharedPointer<KcpSocket> accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) = 0;
    virtual bool bind(const QHostAddress &address, quint16 port, Socket::BindMode mode) = 0;
    virtual bool bind(quint16 port, Socket::BindMode mode) = 0;
    virtual bool connect(const QHostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) = 0;
    virtual bool close(bool force) = 0;
    virtual bool listen(int backlog) = 0;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) = 0;
    virtual QVariant option(Socket::SocketOption option) const = 0;
public:
    void setMode(KcpSocket::Mode mode);
    qint32 send(const char *data, qint32 size, bool all);
    qint32 recv(char *data, qint32 size, bool all);
    bool handleDatagram(const char *buf, quint32 len);
    void updateKcp();
    void doUpdate();
    virtual qint32 rawSend(const char *data, qint32 size) = 0;
    virtual qint32 udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port) = 0;

    QByteArray makeDataPacket(const char *data, qint32 size);
    QByteArray makeShutdownPacket();
    QByteArray makeShutdownPacket(quint32 connectionId);
    QByteArray makeKeepalivePacket();
    QByteArray makeMultiPathPacket(quint32 connectionId);
public:
    KcpSocket * const q_ptr;
    Q_DECLARE_PUBLIC(KcpSocket)
public:
    CoroutineGroup *operations;
    QString errorString;
    Socket::SocketState state;
    Socket::SocketError error;

    QSharedPointer<Event> busy;
    QSharedPointer<Event> notBusy;
    QSharedPointer<Event> sendingQueueNotFull;
    QSharedPointer<Event> sendingQueueEmpty;
    QSharedPointer<Event> receivingQueueNotEmpty;
    QSharedPointer<RLock> kcpLock;
    QSharedPointer<Gate> forceToUpdate;
    QByteArray receivingBuffer;

    const quint64 zeroTimestamp;
    quint64 lastActiveTimestamp;
    quint64 lastKeepaliveTimestamp;
    quint64 tearDownTime;
    ikcpcb *kcp;
    quint32 waterLine;
    quint32 connectionId;

    QHostAddress remoteAddress;
    quint16 remotePort;

    KcpSocket::Mode mode;
};


static inline QString concat(const QHostAddress &addr, quint16 port)
{
    return addr.toString() + ":" + QString::number(port);
}


class MasterKcpSocketPrivate: public KcpSocketPrivate
{
public:
    MasterKcpSocketPrivate(Socket::NetworkLayerProtocol protocol, KcpSocket *q);
    MasterKcpSocketPrivate(qintptr socketDescriptor, KcpSocket *q);
    MasterKcpSocketPrivate(QSharedPointer<Socket> rawSocket, KcpSocket *q);
    virtual ~MasterKcpSocketPrivate() override;
public:
    virtual Socket::SocketError getError() const override;
    virtual QString getErrorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;
public:
    virtual QSharedPointer<KcpSocket> accept() override;
    virtual QSharedPointer<KcpSocket> accept(const QHostAddress &addr, quint16 port) override;
    virtual QSharedPointer<KcpSocket> accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool bind(const QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    virtual qint32 rawSend(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port) override;
public:
    void removeSlave(const QString &originalHostAndPort) { receiversByHostAndPort.remove(originalHostAndPort); }
    void removeSlave(quint32 connectionId) { receiversByConnectionId.remove(connectionId); }
    quint32 nextConnectionId();
    void doReceive();
    void doAccept();
    bool startReceivingCoroutine();
    QHostAddress resolve(const QString &hostName, QSharedPointer<SocketDnsCache> dnsCache);
public:
    QMap<QString, QPointer<class SlaveKcpSocketPrivate>> receiversByHostAndPort;
    QMap<quint32, QPointer<class SlaveKcpSocketPrivate>> receiversByConnectionId;
    QSharedPointer<Socket> rawSocket;
    Queue<QSharedPointer<KcpSocket>> pendingSlaves;
};


class SlaveKcpSocketPrivate: public KcpSocketPrivate
{
public:
    SlaveKcpSocketPrivate(MasterKcpSocketPrivate *parent, const QHostAddress &addr, quint16 port, KcpSocket *q);
    virtual ~SlaveKcpSocketPrivate() override;
public:
    static KcpSocket *create(KcpSocketPrivate *d, const QHostAddress &addr, quint16 port, KcpSocket::Mode mode);
    static SlaveKcpSocketPrivate *getPrivateHelper(QSharedPointer<KcpSocket> s);
public:
    virtual Socket::SocketError getError() const override;
    virtual QString getErrorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;
public:
    virtual QSharedPointer<KcpSocket> accept() override;
    virtual QSharedPointer<KcpSocket> accept(const QHostAddress &addr, quint16 port) override;
    virtual QSharedPointer<KcpSocket> accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool bind(const QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    virtual qint32 rawSend(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port) override;
public:
    QString originalHostAndPort;
    QPointer<MasterKcpSocketPrivate> parent;
};


KcpSocket *SlaveKcpSocketPrivate::create(KcpSocketPrivate *d, const QHostAddress &addr, quint16 port, KcpSocket::Mode mode)
{
    return new KcpSocket(d, addr, port, mode);
}


SlaveKcpSocketPrivate *SlaveKcpSocketPrivate::getPrivateHelper(QSharedPointer<KcpSocket> s)
{
    return static_cast<SlaveKcpSocketPrivate*>(s->d_ptr);
}


int kcp_callback(const char *buf, int len, ikcpcb *, void *user)
{
    KcpSocketPrivate *p = static_cast<KcpSocketPrivate*>(user);
    if (!p || !buf || len > 65535) {
        qWarning() << "kcp_callback got invalid data.";
        return -1;
    }
    const QByteArray &packet = p->makeDataPacket(buf, len);
    qint32 sentBytes = -1;
    for (int i = 0; i < 1; ++i) {
        sentBytes = p->rawSend(packet.data(), packet.size());
        if (sentBytes != packet.size()) {  // but why this happens?
            if (p->error == Socket::NoError) {
                p->error = Socket::SocketAccessError;
                p->errorString = QStringLiteral("can not send udp packet");
            }
#ifdef DEBUG_PROTOCOL
            qWarning() << "can not send packet.";
#endif
            p->close(true);
            return -1;
        }
    }
    return sentBytes;
}


KcpSocketPrivate::KcpSocketPrivate(KcpSocket *q)
    : q_ptr(q)
    , operations(new CoroutineGroup)
    , state(Socket::UnconnectedState)
    , error(Socket::NoError)
    , busy(new Event())
    , notBusy(new Event())
    , sendingQueueNotFull(new Event())
    , sendingQueueEmpty(new Event())
    , receivingQueueNotEmpty(new Event())
    , kcpLock(new RLock)
    , forceToUpdate(new Gate)
    , zeroTimestamp(static_cast<quint64>(QDateTime::currentMSecsSinceEpoch()))
    , lastActiveTimestamp(zeroTimestamp)
    , lastKeepaliveTimestamp(zeroTimestamp)
    , tearDownTime(1000 * 30)
    , waterLine(1024 * 16)
    , connectionId(0)
    , remotePort(0), mode(KcpSocket::Internet)
{
    kcp = ikcp_create(0, this);
    ikcp_setoutput(kcp, kcp_callback);
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
    receivingQueueNotEmpty->clear();
    busy->clear();
    notBusy->set();
    setMode(mode);
}


KcpSocketPrivate::~KcpSocketPrivate()
{
    delete operations;
    ikcp_release(kcp);
}


QHostAddress KcpSocketPrivate::peerAddress() const
{
    return remoteAddress;
}


QString KcpSocketPrivate::peerName() const
{
    return remoteAddress.toString();
}


quint16 KcpSocketPrivate::peerPort() const
{
    return remotePort;
}


Socket::SocketType KcpSocketPrivate::type() const
{
    return Socket::KcpSocket;
}


//bool KcpSocketPrivate::close()
//{
//}

void KcpSocketPrivate::setMode(KcpSocket::Mode mode)
{
    this->mode = mode;
    switch (mode) {
    case KcpSocket::LargeDelayInternet:
        ikcp_nodelay(kcp, 0, 40, 4, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 4096, 4096);
        break;
    case KcpSocket::Internet:
        ikcp_nodelay(kcp, 1, 30, 3, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 2048, 2048);
        break;
    case KcpSocket::FastInternet:
        ikcp_nodelay(kcp, 1, 20, 2, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    case KcpSocket::Ethernet:
        ikcp_nodelay(kcp, 1, 10, 2, 1);
        ikcp_setmtu(kcp, 1024 * 32);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    case KcpSocket::Loopback:
        ikcp_nodelay(kcp, 1, 10, 1, 0);
        ikcp_setmtu(kcp, 1024 * 63);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    }
}


qint32 KcpSocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (size <= 0 || !isValid()) {
        return -1;
    }

    bool ok = sendingQueueNotFull->wait();
    if (!ok) {
        return -1;
    }

    int count = 0;
    while (count < size) {
        if (state != Socket::ConnectedState) {
            error = Socket::SocketAccessError;
            errorString = QStringLiteral("KcpSocket is not connected.");
            return -1;
        }
        ScopedLock<RLock> l(kcpLock); Q_UNUSED(l);
        qint32 nextBlockSize = qMin<qint32>(static_cast<qint32>(kcp->mss), size - count);
        int result = ikcp_send(kcp, data + count, nextBlockSize);
        if (result < 0) {
            qWarning() << "why this happended?";
            if (count > 0) {
                updateKcp();
                return count;
            } else {
                return -1;
            }
        } else { // result == 0
            count += nextBlockSize;
            if (!all) {
                updateKcp();
                return count;
            }
        }
    }
    Q_ASSERT(all);
    updateKcp();
    return isValid() ? count : -1;
}


qint32 KcpSocketPrivate::recv(char *data, qint32 size, bool all)
{
    while (true) {
        if (state != Socket::ConnectedState) {
            error = Socket::SocketAccessError;
            errorString = QStringLiteral("KcpSocket is not connected.");
            return -1;
        }
        int peeksize = ikcp_peeksize(kcp);
        if (peeksize > 0) {
            QByteArray buf(peeksize, Qt::Uninitialized);
            ScopedLock<RLock> l(kcpLock); Q_UNUSED(l);
            int readBytes = ikcp_recv(kcp, buf.data(), buf.size());
            Q_ASSERT(readBytes == peeksize);
            receivingBuffer.append(buf);
        }
        if (!receivingBuffer.isEmpty()) {
            if (!all || receivingBuffer.size() >= size) {
                qint32 len = qMin(size, receivingBuffer.size());
                memcpy(data, receivingBuffer.data(), static_cast<size_t>(len));
                receivingBuffer.remove(0, len);
                return len;
            }
        }
        receivingQueueNotEmpty->clear();
        bool ok = receivingQueueNotEmpty->wait();
        if (!ok) {
            qDebug() << "not receivingQueueNotEmpty->wait()";
            return -1;
        }
    }
}


bool KcpSocketPrivate::handleDatagram(const char *buf, quint32 len)
{
    if (len < 5) {
        return true;
    }
    int result;
    switch(buf[0]) {
    case PACKET_TYPE_UNCOMPRESSED_DATA:
        {
            ScopedLock<RLock> l(kcpLock); Q_UNUSED(l);
            result = ikcp_input(kcp, buf + 1, len - 1);
        }
        if (result < 0) {
            // invalid datagram
#ifdef DEBUG_PROTOCOL
            qDebug() << "invalid datagram. kcp returns" << result;
#endif
        } else {
            lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
            receivingQueueNotEmpty->set();
            updateKcp();
        }
        break;
    case PACKET_TYPE_CREATE_MULTIPATH:
        break;
    case PACKET_TYPE_CLOSE:
        close(true);
        return false;
    case PACKET_TYPE_KEEPALIVE:
        lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        break;
    default:
        break;
    }
    return true;
}


void KcpSocketPrivate::doUpdate()
{
    // in close(), state is set to Socket::UnconnectedState but error = NoError.
    while (state == Socket::ConnectedState || (state == Socket::UnconnectedState && error == Socket::NoError)) {
        quint64 now = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        if (now - lastActiveTimestamp > tearDownTime && state == Socket::ConnectedState) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "tearDown!";
#endif
            error = Socket::SocketTimeoutError;
            errorString = QStringLiteral("KcpSocket is timeout.");
            close(true);
            return;
        }
        quint32 current = static_cast<quint32>(now - zeroTimestamp);  // impossible to overflow.
        {
            ScopedLock<RLock> l(kcpLock); Q_UNUSED(l);
            ikcp_update(kcp, current);   // ikcp_update() call ikcp_flush() and then kcp_callback(), and maybe close(true)
        }
        if (!(state == Socket::ConnectedState || (state == Socket::UnconnectedState && error == Socket::NoError))) {
            return;
        }

        if (now - lastKeepaliveTimestamp > 1000 * 5 && state == Socket::ConnectedState) {
            const QByteArray &packet = makeKeepalivePacket();
            if (rawSend(packet.data(), packet.size()) != packet.size()) {
#ifdef DEBUG_PROTOCOL
                qDebug() << "can not send keep alive packet.";
#endif
                close(true);
                return;
            }
        }

        int sendingQueueSize = ikcp_waitsnd(kcp);
        if (sendingQueueSize <= 0) {
            sendingQueueNotFull->set();
            sendingQueueEmpty->set();
            busy->clear();
            notBusy->set();
        } else {
            sendingQueueEmpty->clear();
            if (static_cast<quint32>(sendingQueueSize) > waterLine) {
                if (static_cast<quint32>(sendingQueueSize) > (waterLine * 1.2)) {
                    sendingQueueNotFull->clear();
                }
                busy->set();
                notBusy->clear();
            } else {
                sendingQueueNotFull->set();
                busy->clear();
                notBusy->set();
            }
        }

        quint32 ts = ikcp_check(kcp, current);
        quint32 interval = ts - current;
        if (interval > 0) {
            forceToUpdate->close();
            try {
                Timeout timeout(interval, 0); Q_UNUSED(timeout);
                bool ok = forceToUpdate->wait();
                if (!ok) {
                    return;
                }
            } catch (TimeoutException &) {
                // continue
            }
        }
    }
}


void KcpSocketPrivate::updateKcp()
{
    QSharedPointer<Coroutine> t = operations->spawnWithName("update_kcp", [this] { doUpdate(); }, false);
    forceToUpdate->open();
}


QByteArray KcpSocketPrivate::makeDataPacket(const char *data, qint32 size)
{
    QByteArray packet(size + 1, Qt::Uninitialized);
    packet.data()[0] = PACKET_TYPE_UNCOMPRESSED_DATA;
    memcpy(packet.data() + 1, data, static_cast<size_t>(size));
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(this->connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(this->connectionId, reinterpret_cast<uchar*>(packet.data() + 1));
#endif
    return packet;
}


QByteArray KcpSocketPrivate::makeShutdownPacket()
{
    // should be larger than 5 bytes. tail bytes are discard.
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
    packet.data()[0] = PACKET_TYPE_CLOSE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(this->connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(this->connectionId, reinterpret_cast<uchar*>(packet.data() + 1));
#endif
    return packet;
}


QByteArray KcpSocketPrivate::makeShutdownPacket(quint32 connectionId)
{
    // should be larger than 5 bytes. tail bytes are discard.
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
    packet.data()[0] = PACKET_TYPE_CLOSE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar*>(packet.data() + 1));
#endif
    return packet;
}


QByteArray KcpSocketPrivate::makeKeepalivePacket()
{
    // should be larger than 5 bytes. tail bytes are discard.
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
    packet.data()[0] = PACKET_TYPE_KEEPALIVE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(this->connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(this->connectionId, reinterpret_cast<uchar*>(packet.data() + 1));
#endif
    return packet;
}


QByteArray KcpSocketPrivate::makeMultiPathPacket(quint32 connectionId)
{
    // should be larger than 5 bytes. tail bytes are discard.
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
    packet.data()[0] = PACKET_TYPE_CREATE_MULTIPATH;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar*>(packet.data() + 1));
#endif
    return packet;
}


MasterKcpSocketPrivate::MasterKcpSocketPrivate(Socket::NetworkLayerProtocol protocol, KcpSocket *q)
    : KcpSocketPrivate(q), rawSocket(new Socket(protocol, Socket::UdpSocket))
{
}


MasterKcpSocketPrivate::MasterKcpSocketPrivate(qintptr socketDescriptor, KcpSocket *q)
    : KcpSocketPrivate(q), rawSocket(new Socket(socketDescriptor))
{
}


MasterKcpSocketPrivate::MasterKcpSocketPrivate(QSharedPointer<Socket> rawSocket, KcpSocket *q)
    : KcpSocketPrivate(q), rawSocket(rawSocket)
{
}


MasterKcpSocketPrivate::~MasterKcpSocketPrivate()
{
    MasterKcpSocketPrivate::close(true);
}


Socket::SocketError MasterKcpSocketPrivate::getError() const
{
    if (error != Socket::NoError) {
        return error;
    } else {
        return rawSocket->error();
    }
}


QString MasterKcpSocketPrivate::getErrorString() const
{
    if (!errorString.isEmpty()) {
        return errorString;
    } else {
        return rawSocket->errorString();
    }
}


bool MasterKcpSocketPrivate::isValid() const
{
    return state == Socket::ConnectedState || state == Socket::BoundState || state == Socket::ListeningState;
}


QHostAddress MasterKcpSocketPrivate::localAddress() const
{
    return rawSocket->localAddress();
}


quint16 MasterKcpSocketPrivate::localPort() const
{
    return rawSocket->localPort();
}


Socket::NetworkLayerProtocol MasterKcpSocketPrivate::protocol() const
{
    return rawSocket->protocol();
}


bool MasterKcpSocketPrivate::close(bool force)
{
    // if `force` is true, must not block. see doUpdate()
    if (state == Socket::UnconnectedState) {
        return true;
    } else if (state == Socket::ConnectedState) {
        state = Socket::UnconnectedState;
        if (!force && error == Socket::NoError) {
            if (!sendingQueueEmpty->isSet()) {
                updateKcp();
                if (!sendingQueueEmpty->wait()) {
                    return false;
                }
            }
            const QByteArray &packet = makeShutdownPacket();
            rawSend(packet.constData(), packet.size());
        }
    } else if (state == Socket::ListeningState) {
        state = Socket::UnconnectedState;
        for (QPointer<SlaveKcpSocketPrivate> receiver: receiversByHostAndPort.values()) {
            if (!receiver.isNull()) {
                receiver->close(force);
            }
        }
        receiversByHostAndPort.clear();
        receiversByConnectionId.clear();
    } else {  // BoundState
        state = Socket::UnconnectedState;
        rawSocket->close();
        return true;
    }

    //connected and listen state would do more cleaning work.
    operations->killall();
    // always kill operations before release resources.
    if (force) {
        rawSocket->abort();
    } else {
        rawSocket->close();
    }
    // await all pending recv()/send()
    receivingQueueNotEmpty->set();
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
#ifdef DEBUG_PROTOCOL
    qDebug() << "MasterKcpSocketPrivate::close() done";
#endif
    return true;
}


bool MasterKcpSocketPrivate::listen(int backlog)
{
    if (state != Socket::BoundState || backlog <= 0) {
        return false;
    }
    state = Socket::ListeningState;
    pendingSlaves.setCapacity(static_cast<quint32>(backlog));
    return true;
}


quint32 MasterKcpSocketPrivate::nextConnectionId()
{
    quint32 id;
    do {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        id = qFromBigEndian<quint32>(randomBytes(4).constData());
#else
        id = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(randomBytes(4).constData()));
#endif
    } while (receiversByConnectionId.contains(id));
    return id;
}


void MasterKcpSocketPrivate::doReceive()
{
    Q_Q(KcpSocket);
    QHostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "KcpSocket can not receive udp packet." << rawSocket->errorString();
#endif
            MasterKcpSocketPrivate::close(true);
            return;
        }
        if (q->filter(buf.data(), &len, &addr, &port)) {
            continue;
        }
//        if (Q_UNLIKELY(addr.toIPv6Address() != remoteAddress.toIPv6Address() || port != remotePort)) {
//            // not my packet.
//            qDebug() << "not my packet:" << addr << remoteAddress << port;
//            continue;
//        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "got invalid kcp packet smaller than 5 bytes." << QByteArray(buf.data(), len);
#endif
            continue;
        }

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(buf.data() + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(buf.data() + 1));
#endif
        if (connectionId == 0) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "the kcp server side returns an invalid packet with zero connection id.";
#endif
            continue;
        } else {
            if (this->connectionId != 0) {
                if (connectionId != this->connectionId) {
#ifdef DEBUG_PROTOCOL
                    qDebug() << "the kcp server side returns an invalid packet with mismatched connection id.";
#endif
                    continue;
                } else {
                    // do nothing.
                }
            } else {
                this->connectionId = connectionId;
            }
        }
        qToBigEndian<quint32>(0, reinterpret_cast<uchar*>(buf.data() + 1));
        if (!handleDatagram(buf.data(), static_cast<quint32>(len))) {
            return;
        }
    }
}


void MasterKcpSocketPrivate::doAccept()
{
    Q_Q(KcpSocket);
    QHostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "KcpSocket can not receive udp packet." << rawSocket->errorString();
#endif
            MasterKcpSocketPrivate::close(true);
            return;
        }
        if (q->filter(buf.data(), &len, &addr, &port)) {
            continue;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "got invalid kcp packet smaller than 5 bytes.";
#endif
            continue;
        }

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(buf.data() + 1);
        qToBigEndian<quint32>(0, buf.data() + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(buf.data() + 1));
        qToBigEndian<quint32>(0, reinterpret_cast<uchar*>(buf.data() + 1));
#endif
        const QString &key = concat(addr, port);
        QPointer<SlaveKcpSocketPrivate> receiver;
        receiver = receiversByHostAndPort.value(key);
        if (receiver.isNull() && connectionId != 0) {
            receiver = receiversByConnectionId.value(connectionId);
        }
        if (!receiver.isNull()) {
            receiver->remoteAddress = addr;
            receiver->remotePort = port;
            if (connectionId != 0 && receiver->connectionId == 0) {
                // only happened in the newly accept(host, port) connections.
                // or remote create new conn with the same port as old, and the old packet is received.
                receiver->connectionId = connectionId;
                // if this connectionId is unique in client. we add it to the receiversByConnectionId map.
                // if it is not, say sorry, and disable the multipath feature.
                if (!receiversByConnectionId.contains(connectionId)) {
                    receiversByConnectionId.insert(connectionId, receiver);
                }
            }
            if (!receiver->handleDatagram(buf.data(), static_cast<quint32>(len))) {
                receiversByHostAndPort.remove(receiver->originalHostAndPort);
                receiversByConnectionId.remove(receiver->connectionId);
            }
        } else {
            // if connection id is not zero, it must be bad packet.
            if (connectionId != 0) {
                const QByteArray &closePacket = makeShutdownPacket(connectionId);
                if (rawSocket->sendto(closePacket, addr, port) != closePacket.size()) {
                    if (error == Socket::NoError) {
                        error = Socket::SocketResourceError;
                        errorString = QStringLiteral("KcpSocket can not send udp packet.");
                    }
#ifdef DEBUG_PROTOCOL
                    qDebug() << errorString;
#endif
                    MasterKcpSocketPrivate::close(true);
                }
            } else if (connectionId == 0 && pendingSlaves.size() < pendingSlaves.capacity()) {  // not full.
                QSharedPointer<KcpSocket> slave(SlaveKcpSocketPrivate::create(this, addr, port, this->mode));
                SlaveKcpSocketPrivate *d = SlaveKcpSocketPrivate::getPrivateHelper(slave);
                d->originalHostAndPort = key;
                d->connectionId = nextConnectionId();
                if (d->handleDatagram(buf.data(), static_cast<quint32>(len))) {
                    receiversByHostAndPort.insert(key, d);
                    receiversByConnectionId.insert(d->connectionId, d);
                    pendingSlaves.put(slave);
                    const QByteArray &multiPathPacket = makeMultiPathPacket(d->connectionId);
                    if (rawSocket->sendto(multiPathPacket, addr, port) != multiPathPacket.size()) {
                        if (error == Socket::NoError) {
                            error = Socket::SocketResourceError;
                            errorString = QStringLiteral("KcpSocket can not send udp packet.");
                        }
#ifdef DEBUG_PROTOCOL
                        qDebug() << errorString;
#endif
                        MasterKcpSocketPrivate::close(true);
                    }
                }
            }
        }
    }
}

bool MasterKcpSocketPrivate::startReceivingCoroutine()
{
    if (!operations->get("receiving").isNull()) {
        return true;
    }
    switch (state) {
    case Socket::UnconnectedState:
    case Socket::BoundState:
    case Socket::ConnectingState:
    case Socket::HostLookupState:
    case Socket::ClosingState:
        return false;
    case Socket::ConnectedState:
        operations->spawnWithName("receiving", [this] { doReceive(); });
        break;
    case Socket::ListeningState:
        operations->spawnWithName("receiving", [this] { doAccept(); });
        break;
    }
    return true;
}


QSharedPointer<KcpSocket> MasterKcpSocketPrivate::accept()
{
    if (state != Socket::ListeningState) {
        return QSharedPointer<KcpSocket>();
    }
    startReceivingCoroutine();
    return pendingSlaves.get();
}


QSharedPointer<KcpSocket> MasterKcpSocketPrivate::accept(const QHostAddress &addr, quint16 port)
{
    if (state != Socket::ListeningState || addr.isNull() || port == 0) {
        return QSharedPointer<KcpSocket>();
    }
    startReceivingCoroutine();
    const QString &key = concat(addr, port);
    QPointer<SlaveKcpSocketPrivate> receiver;
    receiver = receiversByHostAndPort.value(key);
    if (!receiver.isNull() && receiver->isValid()) {
        return QSharedPointer<KcpSocket>();
    } else {
        QSharedPointer<KcpSocket> slave(SlaveKcpSocketPrivate::create(this, addr, port, this->mode));
        SlaveKcpSocketPrivate *d = SlaveKcpSocketPrivate::getPrivateHelper(slave);
        d->originalHostAndPort = key;
        d->updateKcp();
        receiversByHostAndPort.insert(key, d);
        // the connectionId is generated in server side. accept() is acually a connect().
        // receiversByConnectionId.insert(d->connectionId, d);
        return slave;
    }
}


QSharedPointer<KcpSocket> MasterKcpSocketPrivate::accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    if (state != Socket::ListeningState || hostName.isNull() || port == 0) {
        return QSharedPointer<KcpSocket>();
    }
    const QHostAddress &addr = resolve(hostName, dnsCache);
    if (addr.isNull()) {
        return QSharedPointer<KcpSocket>();
    } else {
        return accept(addr, port);
    }
}


bool MasterKcpSocketPrivate::connect(const QHostAddress &addr, quint16 port)
{
    if ((state != Socket::UnconnectedState && state != Socket::BoundState) || addr.isNull()) {
        return false;
    }
    remoteAddress = addr;
    remotePort = port;
    state = Socket::ConnectedState;
    return true;
}


bool MasterKcpSocketPrivate::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    if (state != Socket::UnconnectedState && state != Socket::BoundState) {
        return false;
    }
    const QHostAddress &addr = resolve(hostName, dnsCache);
    if (addr.isNull()) {
        return false;
    } else {
        return connect(addr, port);
    }
}


QHostAddress MasterKcpSocketPrivate::resolve(const QString &hostName, QSharedPointer<SocketDnsCache> dnsCache)
{
    QList<QHostAddress> addresses;
    QHostAddress t;
    if (t.setAddress(hostName)) {
        addresses.append(t);
    } else {
        if (dnsCache.isNull()) {
            addresses = Socket::resolve(hostName);
        } else {
            addresses = dnsCache->resolve(hostName);
        }
    }
    for (int i = 0; i < addresses.size(); ++i) {
        const QHostAddress &addr = addresses.at(i);
        if (rawSocket->protocol() == Socket::IPv4Protocol && addr.protocol() == QAbstractSocket::IPv6Protocol) {
            continue;
        }
        if (rawSocket->protocol() == Socket::IPv6Protocol && addr.protocol() == QAbstractSocket::IPv4Protocol) {
            continue;
        }
        return addr;
    }
    return QHostAddress();
}


qint32 MasterKcpSocketPrivate::rawSend(const char *data, qint32 size)
{
    lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    startReceivingCoroutine();
    qint32 len = rawSocket->sendto(data, size, remoteAddress, remotePort);
    return len;
}


qint32 MasterKcpSocketPrivate::udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port)
{
    return rawSocket->sendto(data, size, addr, port);
}


bool MasterKcpSocketPrivate::bind(const QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    if (state != Socket::UnconnectedState) {
        return false;
    }
    if(mode & Socket::ReuseAddressHint) {
        rawSocket->setOption(Socket::AddressReusable, true);
    }
    if (rawSocket->bind(address, port, mode)) {
        state = Socket::BoundState;
        return true;
    } else {
        return false;
    }
}


bool MasterKcpSocketPrivate::bind(quint16 port, Socket::BindMode mode)
{
    if (state != Socket::UnconnectedState) {
        return false;
    }
    if(mode & Socket::ReuseAddressHint) {
        rawSocket->setOption(Socket::AddressReusable, true);
    }
    if (rawSocket->bind(port, mode)) {
        state = Socket::BoundState;
        return true;
    } else {
        return false;
    }
}


bool MasterKcpSocketPrivate::setOption(Socket::SocketOption option, const QVariant &value)
{
    return rawSocket->setOption(option, value);
}


QVariant MasterKcpSocketPrivate::option(Socket::SocketOption option) const
{
    return rawSocket->option(option);
}


SlaveKcpSocketPrivate::SlaveKcpSocketPrivate(MasterKcpSocketPrivate *parent, const QHostAddress &addr, quint16 port, KcpSocket *q)
    :KcpSocketPrivate(q), parent(parent)
{
    remoteAddress = addr;
    remotePort = port;
    state = Socket::ConnectedState;
}


SlaveKcpSocketPrivate::~SlaveKcpSocketPrivate()
{
    SlaveKcpSocketPrivate::close(true);
}


Socket::SocketError SlaveKcpSocketPrivate::getError() const
{
    if (error != Socket::NoError) {
        return error;
    } else {
        if (!parent.isNull()) {
            return parent->rawSocket->error();
        } else {
            return Socket::SocketAccessError;
        }
    }
}


QString SlaveKcpSocketPrivate::getErrorString() const
{
    if (!errorString.isEmpty()) {
        return errorString;
    } else {
        if (!parent.isNull()) {
            return parent->rawSocket->errorString();
        } else {
            return QString::fromLatin1("Invalid socket descriptor");
        }
    }
}


bool SlaveKcpSocketPrivate::isValid() const
{
    return state == Socket::ConnectedState && !parent.isNull();
}


QHostAddress SlaveKcpSocketPrivate::localAddress() const
{
    if (parent.isNull()) {
        return QHostAddress();
    }
    return parent->rawSocket->localAddress();
}


quint16 SlaveKcpSocketPrivate::localPort() const
{
    if (parent.isNull()) {
        return 0;
    }
    return parent->rawSocket->localPort();
}


Socket::NetworkLayerProtocol SlaveKcpSocketPrivate::protocol() const
{
    if (parent.isNull()) {
        return Socket::UnknownNetworkLayerProtocol;
    }
    return parent->rawSocket->protocol();
}


bool SlaveKcpSocketPrivate::close(bool force)
{
    // if `force` is true, must not block. it is called by doUpdate()
    if (state == Socket::UnconnectedState) {
        return true;
    } else if (state == Socket::ConnectedState) {
        state = Socket::UnconnectedState;
        if (!force && error != Socket::NoError) {
            if (!sendingQueueEmpty->isSet()) {
                updateKcp();
                if (!sendingQueueEmpty->wait()) {
                    return false;
                }
            }
            const QByteArray &packet = makeShutdownPacket();
            rawSend(packet.constData(), packet.size());
        }
    } else {  // there can be no other states.
        state = Socket::UnconnectedState;
    }
    operations->kill("update_kcp");
    if (!parent.isNull()) {
        parent->removeSlave(originalHostAndPort);
        parent->removeSlave(connectionId);
        parent.clear();
    }
    // await all pending recv()/send()
    receivingQueueNotEmpty->set();
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
    notBusy->set();
    busy->set();
#ifdef DEBUG_PROTOCOL
    qDebug() << "SlaveKcpSocketPrivate::close() done.";
#endif
    return true;
}


bool SlaveKcpSocketPrivate::listen(int)
{
    return false;
}


QSharedPointer<KcpSocket> SlaveKcpSocketPrivate::accept()
{
    return QSharedPointer<KcpSocket>();
}


QSharedPointer<KcpSocket> SlaveKcpSocketPrivate::accept(const QHostAddress &, quint16)
{
    return QSharedPointer<KcpSocket>();
}


QSharedPointer<KcpSocket> SlaveKcpSocketPrivate::accept(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return QSharedPointer<KcpSocket>();
}


bool SlaveKcpSocketPrivate::connect(const QHostAddress &, quint16)
{
    return false;
}


bool SlaveKcpSocketPrivate::connect(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return false;
}


qint32 SlaveKcpSocketPrivate::rawSend(const char *data, qint32 size)
{
    if (parent.isNull()) {
        return -1;
    } else {
        lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        qint32 len = parent->rawSocket->sendto(data, size, remoteAddress, remotePort);
        return len;
    }
}


qint32 SlaveKcpSocketPrivate::udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port)
{
    if (parent.isNull()) {
        return -1;
    } else {
        return parent->rawSocket->sendto(data, size, addr, port);
    }
}


bool SlaveKcpSocketPrivate::bind(const QHostAddress &, quint16, Socket::BindMode)
{
    return false;
}


bool SlaveKcpSocketPrivate::bind(quint16, Socket::BindMode)
{
    return false;
}


bool SlaveKcpSocketPrivate::setOption(Socket::SocketOption, const QVariant &)
{
    return false;
}


QVariant SlaveKcpSocketPrivate::option(Socket::SocketOption option) const
{
    if (parent.isNull()) {
        return QVariant();
    } else {
        return parent->rawSocket->option(option);
    }
}


KcpSocket::KcpSocket(Socket::NetworkLayerProtocol protocol)
    : d_ptr(new MasterKcpSocketPrivate(protocol, this))
{
    busy = d_ptr->busy;
    notBusy = d_ptr->notBusy;
}


KcpSocket::KcpSocket(qintptr socketDescriptor)
    : d_ptr(new MasterKcpSocketPrivate(socketDescriptor, this))
{

}


KcpSocket::KcpSocket(QSharedPointer<Socket> rawSocket)
    : d_ptr(new MasterKcpSocketPrivate(rawSocket, this))
{

}


KcpSocket::KcpSocket(KcpSocketPrivate *parent, const QHostAddress &addr, const quint16 port, KcpSocket::Mode mode)
    :d_ptr(new SlaveKcpSocketPrivate(static_cast<MasterKcpSocketPrivate*>(parent), addr, port, this))
{
    setMode(mode);
}


KcpSocket::~KcpSocket()
{
    delete d_ptr;
}


void KcpSocket::setMode(Mode mode)
{
    Q_D(KcpSocket);
    d->setMode(mode);
}


KcpSocket::Mode KcpSocket::mode() const
{
    Q_D(const KcpSocket);
    return d->mode;
}


void KcpSocket::setUdpPacketSize(quint32 udpPacketSize)
{
    Q_D(const KcpSocket);
    if (udpPacketSize < 65535) {
        ikcp_setmtu(d->kcp, static_cast<int>(udpPacketSize));
    }
}


quint32 KcpSocket::udpPacketSize() const
{
    Q_D(const KcpSocket);
    return d->kcp->mtu;
}


void KcpSocket::setSendQueueSize(quint32 sendQueueSize)
{
    Q_D(KcpSocket);
    d->waterLine = sendQueueSize;
}


quint32 KcpSocket::sendQueueSize() const
{
    Q_D(const KcpSocket);
    return d->waterLine;
}


quint32 KcpSocket::payloadSizeHint() const
{
    Q_D(const KcpSocket);
    return d->kcp->mss;
}


Socket::SocketError KcpSocket::error() const
{
    Q_D(const KcpSocket);
    return d->getError();
}


QString KcpSocket::errorString() const
{
    Q_D(const KcpSocket);
    return d->getErrorString();
}


bool KcpSocket::isValid() const
{
    Q_D(const KcpSocket);
    return d->isValid();
}


QHostAddress KcpSocket::localAddress() const
{
    Q_D(const KcpSocket);
    return d->localAddress();
}


quint16 KcpSocket::localPort() const
{
    Q_D(const KcpSocket);
    return d->localPort();
}


QHostAddress KcpSocket::peerAddress() const
{
    Q_D(const KcpSocket);
    return d->peerAddress();
}


QString KcpSocket::peerName() const
{
    Q_D(const KcpSocket);
    return d->peerName();
}


quint16 KcpSocket::peerPort() const
{
    Q_D(const KcpSocket);
    return d->peerPort();
}


Socket::SocketType KcpSocket::type() const
{
    Q_D(const KcpSocket);
    return d->type();
}


Socket::SocketState KcpSocket::state() const
{
    Q_D(const KcpSocket);
    return d->state;
}


Socket::NetworkLayerProtocol KcpSocket::protocol() const
{
    Q_D(const KcpSocket);
    return d->protocol();
}


QSharedPointer<KcpSocket> KcpSocket::accept()
{
    Q_D(KcpSocket);
    return d->accept();
}


QSharedPointer<KcpSocket> KcpSocket::accept(const QHostAddress &addr, quint16 port)
{
    Q_D(KcpSocket);
    return d->accept(addr, port);
}


QSharedPointer<KcpSocket> KcpSocket::accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    Q_D(KcpSocket);
    return d->accept(hostName, port, dnsCache);
}


bool KcpSocket::bind(const QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    Q_D(KcpSocket);
    return d->bind(address, port, mode);
}


bool KcpSocket::bind(quint16 port, Socket::BindMode mode)
{
    Q_D(KcpSocket);
    return d->bind(port, mode);
}


bool KcpSocket::connect(const QHostAddress &addr, quint16 port)
{
    Q_D(KcpSocket);
    return d->connect(addr, port);
}


bool KcpSocket::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    Q_D(KcpSocket);
    return d->connect(hostName, port, dnsCache);
}


void KcpSocket::close()
{
    Q_D(KcpSocket);
    d->close(false);
}

void KcpSocket::abort()
{
    Q_D(KcpSocket);
    d->close(true);
}

bool KcpSocket::listen(int backlog)
{
    Q_D(KcpSocket);
    return d->listen(backlog);
}


bool KcpSocket::setOption(Socket::SocketOption option, const QVariant &value)
{
    Q_D(KcpSocket);
    return d->setOption(option, value);
}


QVariant KcpSocket::option(Socket::SocketOption option) const
{
    Q_D(const KcpSocket);
    return d->option(option);
}


qint32 KcpSocket::recv(char *data, qint32 size)
{
    Q_D(KcpSocket);
    return d->recv(data, size, false);
}


qint32 KcpSocket::recvall(char *data, qint32 size)
{
    Q_D(KcpSocket);
    return d->recv(data, size, true);
}


qint32 KcpSocket::send(const char *data, qint32 size)
{
    Q_D(KcpSocket);
    qint32 bytesSent = d->send(data, size, false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}


qint32 KcpSocket::sendall(const char *data, qint32 size)
{
    Q_D(KcpSocket);
    return d->send(data, size, true);
}


QByteArray KcpSocket::recv(qint32 size)
{
    Q_D(KcpSocket);
    QByteArray bs;
    bs.resize(size);

    qint32 bytes = d->recv(bs.data(), bs.size(), false);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}


QByteArray KcpSocket::recvall(qint32 size)
{
    Q_D(KcpSocket);
    QByteArray bs;
    bs.resize(size);

    qint32 bytes = d->recv(bs.data(), bs.size(), true);
    if(bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}


qint32 KcpSocket::send(const QByteArray &data)
{
    Q_D(KcpSocket);
    qint32 bytesSent = d->send(data.data(), data.size(), false);
    if(bytesSent == 0 && !d->isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}


qint32 KcpSocket::sendall(const QByteArray &data)
{
    Q_D(KcpSocket);
    return d->send(data.data(), data.size(), true);
}


bool KcpSocket::filter(char *data, qint32 *len, QHostAddress *addr, quint16 *port)
{
    Q_UNUSED(data);
    Q_UNUSED(len);
    Q_UNUSED(addr);
    Q_UNUSED(port);
    return false;
}


qint32 KcpSocket::udpSend(const char *data, qint32 size, const QHostAddress &addr, quint16 port)
{
    Q_D(KcpSocket);
    return d->udpSend(data, size, addr, port);
}


QSharedPointer<KcpSocket> KcpSocket::createConnection(const QHostAddress &host, quint16 port, Socket::SocketError *error, int allowProtocol)
{
    return QSharedPointer<KcpSocket>(QTNETWORKNG_NAMESPACE::createConnection<KcpSocket>(host, port, error, allowProtocol, MakeSocketType<KcpSocket>));
}


QSharedPointer<KcpSocket> KcpSocket::createConnection(const QString &hostName, quint16 port, Socket::SocketError *error,
                                  QSharedPointer<SocketDnsCache> dnsCache, int allowProtocol)
{
    return QSharedPointer<KcpSocket>(QTNETWORKNG_NAMESPACE::createConnection<KcpSocket>(hostName, port, error, dnsCache, allowProtocol, MakeSocketType<KcpSocket>));
}


QSharedPointer<KcpSocket> KcpSocket::createServer(const QHostAddress &host, quint16 port, int backlog)
{
    return QSharedPointer<KcpSocket>(QTNETWORKNG_NAMESPACE::createServer<KcpSocket>(host, port, backlog, MakeSocketType<KcpSocket>));
}


namespace {


class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<KcpSocket> s);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual QHostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr	fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual void close() override;
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
public:
    QSharedPointer<KcpSocket> s;
};


SocketLikeImpl::SocketLikeImpl(QSharedPointer<KcpSocket> s)
    :s(s) {}


Socket::SocketError SocketLikeImpl::error() const
{
    return s->error();
}


QString SocketLikeImpl::errorString() const
{
    return s->errorString();
}


bool SocketLikeImpl::isValid() const
{
    return s->isValid();
}


QHostAddress SocketLikeImpl::localAddress() const
{
    return s->localAddress();
}


quint16 SocketLikeImpl::localPort() const
{
    return s->localPort();
}


QHostAddress SocketLikeImpl::peerAddress() const
{
    return s->peerAddress();
}


QString SocketLikeImpl::peerName() const
{
    return s->peerName();
}


quint16 SocketLikeImpl::peerPort() const
{
    return s->peerPort();
}


qintptr	SocketLikeImpl::fileno() const
{
    return -1;
}


Socket::SocketType SocketLikeImpl::type() const
{
    return s->type();
}


Socket::SocketState SocketLikeImpl::state() const
{
    return s->state();
}


Socket::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    return s->protocol();
}


Socket *SocketLikeImpl::acceptRaw()
{
    return nullptr;
}


QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    return asSocketLike(s->accept());
}


bool SocketLikeImpl::bind(const QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform)
{
    return s->bind(address, port, mode);
}


bool SocketLikeImpl::bind(quint16 port, Socket::BindMode mode)
{
    return s->bind(port, mode);
}


bool SocketLikeImpl::connect(const QHostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}


bool SocketLikeImpl::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    return s->connect(hostName, port, dnsCache);
}


void SocketLikeImpl::close()
{
    s->close();
}


void SocketLikeImpl::abort()
{
    s->abort();
}


bool SocketLikeImpl::listen(int backlog)
{
    return s->listen(backlog);
}


bool SocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}


QVariant SocketLikeImpl::option(Socket::SocketOption option) const
{
    return s->option(option);
}


qint32 SocketLikeImpl::recv(char *data, qint32 size)
{
    return s->recv(data, size);
}


qint32 SocketLikeImpl::recvall(char *data, qint32 size)
{
    return s->recvall(data, size);
}


qint32 SocketLikeImpl::send(const char *data, qint32 size)
{
    return s->send(data, size);
}


qint32 SocketLikeImpl::sendall(const char *data, qint32 size)
{
    return s->sendall(data, size);
}


QByteArray SocketLikeImpl::recv(qint32 size)
{
    return s->recv(size);
}


QByteArray SocketLikeImpl::recvall(qint32 size)
{
    return s->recvall(size);
}


qint32 SocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}


qint32 SocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}


}


QSharedPointer<SocketLike> asSocketLike(QSharedPointer<KcpSocket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}


QSharedPointer<KcpSocket> convertSocketLikeToKcpSocket(QSharedPointer<SocketLike> socket)
{
    QSharedPointer<SocketLikeImpl> impl = socket.dynamicCast<SocketLikeImpl>();
    if (impl.isNull()) {
        return QSharedPointer<KcpSocket>();
    } else {
        return impl->s;
    }
}

QTNETWORKNG_NAMESPACE_END

