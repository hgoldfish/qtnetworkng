#include <QtCore/qdatetime.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qendian.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QtCore/qrandom.h>
#endif
#include "../include/kcp.h"
#include "../include/socket_utils.h"
#include "../include/coroutine_utils.h"
#include "../include/random.h"
#include "../include/private/socket_p.h"
#include "./kcp/ikcp.h"
#include "debugger.h"

QTNG_LOGGER("qtng.kcp");

QTNETWORKNG_NAMESPACE_BEGIN

const char PACKET_TYPE_UNCOMPRESSED_DATA = 0x01;
const char PACKET_TYPE_CREATE_MULTIPATH = 0x02;
const char PACKET_TYPE_CLOSE = 0X03;
const char PACKET_TYPE_KEEPALIVE = 0x04;

//#define DEBUG_PROTOCOL 1

class SlaveKcpSocketPrivate;
class KcpSocketPrivate : public QObject
{
public:
    KcpSocketPrivate(KcpSocket *q);
    virtual ~KcpSocketPrivate() override;
public:
    virtual Socket::SocketError getError() const = 0;
    virtual QString getErrorString() const = 0;
    virtual bool isValid() const = 0;
    virtual HostAddress localAddress() const = 0;
    virtual quint16 localPort() const = 0;
    HostAddress peerAddress() const;
    QString peerName() const;
    quint16 peerPort() const;
    Socket::SocketType type() const;
    virtual HostAddress::NetworkLayerProtocol protocol() const = 0;
public:
    virtual KcpSocket *accept() = 0;
    virtual KcpSocket *accept(const HostAddress &addr, quint16 port) = 0;
    virtual KcpSocket *accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) = 0;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) = 0;
    virtual bool bind(quint16 port, Socket::BindMode mode) = 0;
    virtual bool connect(const HostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) = 0;
    virtual bool close(bool force) = 0;
    virtual bool listen(int backlog) = 0;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) = 0;
    virtual QVariant option(Socket::SocketOption option) const = 0;
    virtual bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) = 0;
    virtual bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) = 0;
    virtual NetworkInterface multicastInterface() const = 0;
    virtual bool setMulticastInterface(const NetworkInterface &iface) = 0;
public:
    void setMode(KcpSocket::Mode mode);
    qint32 send(const char *data, qint32 size, bool all);
    qint32 recv(char *data, qint32 size, bool all);
    qint32 peek(char *data, qint32 size);
    virtual qint32 peekRaw(char *data, qint32 size) = 0;
    bool handleDatagram(const char *buf, quint32 len);
    void updateKcp();
    void updateStatus();
    void doUpdate();
    virtual qint32 rawSend(const char *data, qint32 size) = 0;
    virtual qint32 udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port) = 0;

    QByteArray makeDataPacket(const char *data, qint32 size);
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

    Event sendingQueueNotFull;
    Event sendingQueueEmpty;
    Event receivingQueueNotEmpty;
    RLock kcpLock;
    Gate forceToUpdate;
    QByteArray receivingBuffer;

    const quint64 zeroTimestamp;
    quint64 lastActiveTimestamp;
    quint64 lastKeepaliveTimestamp;
    quint64 tearDownTime;
    ikcpcb *kcp;
    quint32 waterLine;
    quint32 connectionId;

    HostAddress remoteAddress;
    quint16 remotePort;

    KcpSocket::Mode mode;
};

static inline QString concat(const HostAddress &addr, quint16 port)
{
    return addr.toString() + QLatin1String(":") + QString::number(port);
}

class MasterKcpSocketPrivate : public KcpSocketPrivate
{
public:
    MasterKcpSocketPrivate(HostAddress::NetworkLayerProtocol protocol, KcpSocket *q);
    MasterKcpSocketPrivate(qintptr socketDescriptor, KcpSocket *q);
    MasterKcpSocketPrivate(QSharedPointer<Socket> rawSocket, KcpSocket *q);
    virtual ~MasterKcpSocketPrivate() override;
public:
    virtual Socket::SocketError getError() const override;
    virtual QString getErrorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
public:
    virtual KcpSocket *accept() override;
    virtual KcpSocket *accept(const HostAddress &addr, quint16 port) override;
    virtual KcpSocket *accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
    virtual bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) override;
    virtual bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) override;
    virtual NetworkInterface multicastInterface() const override;
    virtual bool setMulticastInterface(const NetworkInterface &iface) override;
public:
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 rawSend(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port) override;
public:
    void removeSlave(const QString &originalHostAndPort) { receiversByHostAndPort.remove(originalHostAndPort); }
    void removeSlave(quint32 connectionId) { receiversByConnectionId.remove(connectionId); }
    quint32 nextConnectionId();
    void doReceive();
    void doAccept();
    bool startReceivingCoroutine();
    HostAddress resolve(const QString &hostName, QSharedPointer<SocketDnsCache> dnsCache);
public:
    QMap<QString, QPointer<class SlaveKcpSocketPrivate>> receiversByHostAndPort;
    QMap<quint32, QPointer<class SlaveKcpSocketPrivate>> receiversByConnectionId;
    QSharedPointer<Socket> rawSocket;
    Queue<KcpSocket *> pendingSlaves;
    int nextPathSocket;  // 0 for rawSocket
};

class SlaveKcpSocketPrivate : public KcpSocketPrivate
{
public:
    SlaveKcpSocketPrivate(MasterKcpSocketPrivate *parent, const HostAddress &addr, quint16 port, KcpSocket *q);
    virtual ~SlaveKcpSocketPrivate() override;
public:
    static KcpSocket *create(KcpSocketPrivate *d, const HostAddress &addr, quint16 port, KcpSocket::Mode mode);
    static SlaveKcpSocketPrivate *getPrivateHelper(KcpSocket *s);
public:
    virtual Socket::SocketError getError() const override;
    virtual QString getErrorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
public:
    virtual KcpSocket *accept() override;
    virtual KcpSocket *accept(const HostAddress &addr, quint16 port) override;
    virtual KcpSocket *accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
    virtual bool joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) override;
    virtual bool leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface) override;
    virtual NetworkInterface multicastInterface() const override;
    virtual bool setMulticastInterface(const NetworkInterface &iface) override;
public:
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 rawSend(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port) override;
public:
    QString originalHostAndPort;
    QPointer<MasterKcpSocketPrivate> parent;
};

KcpSocket *SlaveKcpSocketPrivate::create(KcpSocketPrivate *d, const HostAddress &addr, quint16 port,
                                         KcpSocket::Mode mode)
{
    return new KcpSocket(d, addr, port, mode);
}

SlaveKcpSocketPrivate *SlaveKcpSocketPrivate::getPrivateHelper(KcpSocket *s)
{
    return static_cast<SlaveKcpSocketPrivate *>(s->d_ptr);
}

int kcp_callback(const char *buf, int len, ikcpcb *, void *user)
{
    KcpSocketPrivate *p = static_cast<KcpSocketPrivate *>(user);
    if (!p || !buf || len > 65535) {
        qtng_warning << "kcp_callback got invalid data.";
        return -1;
    }
    const QByteArray &packet = p->makeDataPacket(buf, len);
    qint32 sentBytes = p->rawSend(packet.data(), packet.size());
    if (sentBytes != packet.size()) {  // but why this happens?
        if (p->error == Socket::NoError) {
            p->error = Socket::SocketAccessError;
            p->errorString = QString::fromLatin1("can not send udp packet");
        }
#ifdef DEBUG_PROTOCOL
        qtng_warning << "can not send packet.";
#endif
        p->close(true);
        return -1;
    }
    return sentBytes;
}

KcpSocketPrivate::KcpSocketPrivate(KcpSocket *q)
    : q_ptr(q)
    , operations(new CoroutineGroup)
    , state(Socket::UnconnectedState)
    , error(Socket::NoError)
    , zeroTimestamp(static_cast<quint64>(QDateTime::currentMSecsSinceEpoch()))
    , lastActiveTimestamp(zeroTimestamp)
    , lastKeepaliveTimestamp(zeroTimestamp)
    , tearDownTime(1000 * 30)
    , waterLine(1024)
    , connectionId(0)
    , remotePort(0)
    , mode(KcpSocket::Internet)
{
    kcp = ikcp_create(0, this);
    ikcp_setoutput(kcp, kcp_callback);
    sendingQueueEmpty.set();
    sendingQueueNotFull.set();
    receivingQueueNotEmpty.clear();
    q->busy.clear();
    q->notBusy.set();
    setMode(mode);
}

KcpSocketPrivate::~KcpSocketPrivate()
{
    delete operations;
    ikcp_release(kcp);
}

HostAddress KcpSocketPrivate::peerAddress() const
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

// bool KcpSocketPrivate::close()
//{
// }

void KcpSocketPrivate::setMode(KcpSocket::Mode mode)
{
    this->mode = mode;
    switch (mode) {
    case KcpSocket::LargeDelayInternet:
        waterLine = 512;
        ikcp_nodelay(kcp, 0, 20, 1, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    case KcpSocket::Internet:
        waterLine = 256;
        ikcp_nodelay(kcp, 1, 10, 1, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        kcp->rx_minrto = 30;
        // kcp->interval = 5;
        break;
    case KcpSocket::FastInternet:
        waterLine = 192;
        ikcp_nodelay(kcp, 1, 10, 1, 0);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 512, 512);
        kcp->rx_minrto = 20;
        // kcp->interval = 2;
        break;
    case KcpSocket::Ethernet:
        waterLine = 64;
        ikcp_nodelay(kcp, 1, 10, 4, 0);
        ikcp_setmtu(kcp, 1024 * 32);
        ikcp_wndsize(kcp, 128, 128);
        kcp->rx_minrto = 10;
        // kcp->interval = 1;
        break;
    case KcpSocket::Loopback:
        waterLine = 64;
        ikcp_nodelay(kcp, 1, 10, 0, 0);
        ikcp_setmtu(kcp, 1024 * 64 - 256);
        ikcp_wndsize(kcp, 128, 128);
        kcp->rx_minrto = 5;
        // kcp->interval = 1;
        break;
    }
}

qint32 KcpSocketPrivate::send(const char *data, qint32 size, bool all)
{
    if (size <= 0 || !isValid()) {
        return -1;
    }

    sendingQueueEmpty.clear();

    int count = 0;
    while (count < size) {
        if (state != Socket::ConnectedState) {
            error = Socket::SocketAccessError;
            errorString = QString::fromLatin1("KcpSocket is not connected.");
            return -1;
        }
        bool ok = sendingQueueNotFull.tryWait();
        if (!ok) {
            return -1;
        }
        qint32 nextBlockSize = qMin<qint32>(static_cast<qint32>(kcp->mss), size - count);
        int result;
        {
            ScopedLock<RLock> l(kcpLock);
            result = ikcp_send(kcp, data + count, nextBlockSize);
        }
        updateStatus();
        if (result < 0) {
            qtng_warning << "why this happened?";
            if (count > 0) {
                updateKcp();
                return count;
            } else {
                return -1;
            }
        } else {  // result == 0
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
            errorString = QString::fromLatin1("KcpSocket is not connected.");
            return -1;
        }
        if (!receivingBuffer.isEmpty()) {
            if (!all || receivingBuffer.size() >= size) {
                qint32 len = qMin(size, receivingBuffer.size());
                memcpy(data, receivingBuffer.data(), static_cast<size_t>(len));
                receivingBuffer.remove(0, len);
                return len;
            }
        }
        int peeksize = ikcp_peeksize(kcp);
        if (peeksize > 0) {
            QByteArray buf(peeksize, Qt::Uninitialized);
            int readBytes;
            {
                ScopedLock<RLock> l(kcpLock);
                readBytes = ikcp_recv(kcp, buf.data(), buf.size());
            }
            Q_ASSERT(readBytes == peeksize);
            receivingBuffer.append(buf);
            continue;
        }
        receivingQueueNotEmpty.clear();
        bool ok = receivingQueueNotEmpty.tryWait();
        if (!ok) {
            qtng_debug << "not receivingQueueNotEmpty->tryWait()";
            return -1;
        }
    }
}

qint32 KcpSocketPrivate::peek(char *data, qint32 size)
{
    if (state != Socket::ConnectedState) {
        return -1;
    }
    if (!receivingBuffer.isEmpty()) {
        qint32 len = qMin(size, receivingBuffer.size());
        memcpy(data, receivingBuffer.data(), static_cast<size_t>(len));
        return len;
    }
    return 0;
}

bool KcpSocketPrivate::handleDatagram(const char *buf, quint32 len)
{
    if (len < 5) {
        return true;
    }
    switch (buf[0]) {
    case PACKET_TYPE_UNCOMPRESSED_DATA: {
        int result;
        {
            ScopedLock<RLock> l(kcpLock);
            result = ikcp_input(kcp, buf + 1, len - 1);
        }
        if (result < 0) {
            // invalid datagram
#ifdef DEBUG_PROTOCOL
            qtng_debug << "invalid datagram. kcp returns" << result;
#endif
        } else {
            lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
            receivingQueueNotEmpty.set();
            updateKcp();
        }
        break;
    }
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
        // now and lastActiveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastActiveTimestamp && (now - lastActiveTimestamp > tearDownTime)
            && state == Socket::ConnectedState) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "kcp socket tearDown!";
#endif
            error = Socket::SocketTimeoutError;
            errorString = QString::fromLatin1("KcpSocket is timeout.");
            close(true);
            return;
        }
        quint32 current = static_cast<quint32>(now - zeroTimestamp);  // impossible to overflow.
        {
            ScopedLock<RLock> l(kcpLock);

            ikcp_update(kcp,
                        current);  // ikcp_update() call ikcp_flush() and then kcp_callback(), and maybe close(true)
        }
        if (!(state == Socket::ConnectedState || (state == Socket::UnconnectedState && error == Socket::NoError))) {
            return;
        }

        // now and lastKeepaliveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastKeepaliveTimestamp && (now - lastKeepaliveTimestamp > 1000 * 5)
            && state == Socket::ConnectedState) {
            const QByteArray &packet = makeKeepalivePacket();
            if (rawSend(packet.data(), packet.size()) != packet.size()) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "can not send keep alive packet.";
#endif
                close(true);
                return;
            } else {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "keep alive packet sent.";
#endif
            }
        }

        updateStatus();

        quint32 ts = ikcp_check(kcp, current);
        quint32 interval = ts - current;
        if (interval > 0) {
            forceToUpdate.close();
            forceToUpdate.tryWait(interval);  // timeout continue
        }
    }
}

void KcpSocketPrivate::updateKcp()
{
    QSharedPointer<Coroutine> t = operations->spawnWithName(
            QString::fromLatin1("update_kcp"), [this] { doUpdate(); }, false);
    kcp->updated = 0;
    forceToUpdate.open();
}

void KcpSocketPrivate::updateStatus()
{
    Q_Q(KcpSocket);
    int sendingQueueSize = ikcp_waitsnd(kcp);
    if (sendingQueueSize <= 0) {
        sendingQueueNotFull.set();
        sendingQueueEmpty.set();
        q->busy.clear();
        q->notBusy.set();
    } else {
        sendingQueueEmpty.clear();
        if (static_cast<quint32>(sendingQueueSize) > (waterLine * 1.2)) {
            sendingQueueNotFull.clear();
            q->busy.set();
            q->notBusy.clear();
        } else if (static_cast<quint32>(sendingQueueSize) > waterLine) {
            q->busy.set();
            q->notBusy.clear();
        } else {
            sendingQueueNotFull.set();
            q->busy.clear();
            q->notBusy.set();
        }
    }
}

QByteArray KcpSocketPrivate::makeDataPacket(const char *data, qint32 size)
{
    QByteArray packet(size + 1, Qt::Uninitialized);
    packet.data()[0] = PACKET_TYPE_UNCOMPRESSED_DATA;
    memcpy(packet.data() + 1, data, static_cast<size_t>(size));
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(this->connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(this->connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

QByteArray KcpSocketPrivate::makeShutdownPacket(quint32 connectionId)
{
    // should be larger than 5 bytes. tail bytes are discard.
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QByteArray packet = randomBytes(QRandomGenerator::global()->bounded(5, 64));
#else
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
#endif
    packet.data()[0] = PACKET_TYPE_CLOSE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

QByteArray KcpSocketPrivate::makeKeepalivePacket()
{
    // should be larger than 5 bytes. tail bytes are discard.
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QByteArray packet = randomBytes(QRandomGenerator::global()->bounded(5, 64));
#else
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
#endif
    packet.data()[0] = PACKET_TYPE_KEEPALIVE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(this->connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(this->connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

QByteArray KcpSocketPrivate::makeMultiPathPacket(quint32 connectionId)
{
    // should be larger than 5 bytes. tail bytes are discard.
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QByteArray packet = randomBytes(QRandomGenerator::global()->bounded(5, 64));
#else
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
#endif
    packet.data()[0] = PACKET_TYPE_CREATE_MULTIPATH;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

MasterKcpSocketPrivate::MasterKcpSocketPrivate(HostAddress::NetworkLayerProtocol protocol, KcpSocket *q)
    : KcpSocketPrivate(q)
    , rawSocket(new Socket(protocol, Socket::UdpSocket))
    , nextPathSocket(0)
{
}

MasterKcpSocketPrivate::MasterKcpSocketPrivate(qintptr socketDescriptor, KcpSocket *q)
    : KcpSocketPrivate(q)
    , rawSocket(new Socket(socketDescriptor))
    , nextPathSocket(0)
{
}

MasterKcpSocketPrivate::MasterKcpSocketPrivate(QSharedPointer<Socket> rawSocket, KcpSocket *q)
    : KcpSocketPrivate(q)
    , rawSocket(rawSocket)
    , nextPathSocket(0)
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

HostAddress MasterKcpSocketPrivate::localAddress() const
{
    return rawSocket->localAddress();
}

quint16 MasterKcpSocketPrivate::localPort() const
{
    return rawSocket->localPort();
}

HostAddress::NetworkLayerProtocol MasterKcpSocketPrivate::protocol() const
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
            if (!sendingQueueEmpty.isSet()) {
                updateKcp();
                if (!sendingQueueEmpty.tryWait()) {
                    return false;
                }
            }
            const QByteArray &packet = makeShutdownPacket(this->connectionId);
            rawSend(packet.constData(), packet.size());
        }
    } else if (state == Socket::ListeningState) {
        state = Socket::UnconnectedState;
        QMap<QString, QPointer<class SlaveKcpSocketPrivate>> receiversByHostAndPort(this->receiversByHostAndPort);
        this->receiversByHostAndPort.clear();
        for (QPointer<SlaveKcpSocketPrivate> receiver : receiversByHostAndPort) {
            if (!receiver.isNull()) {
                receiver->close(force);
            }
        }
        receiversByConnectionId.clear();
    } else {  // BoundState
        state = Socket::UnconnectedState;
        rawSocket->abort();
        return true;
    }

    while (!pendingSlaves.isEmpty()) {
        delete pendingSlaves.get();
    }
    pendingSlaves.put(nullptr);

    // connected and listen state would do more cleaning work.
    operations->killall();
    // always kill operations before release resources.
    rawSocket->abort();
    //    if (force) {
    //        rawSocket->abort();
    //    } else {
    //        rawSocket->close();
    //    }
    // awake all pending recv()/send()
    receivingQueueNotEmpty.set();
    sendingQueueEmpty.set();
    sendingQueueNotFull.set();
#ifdef DEBUG_PROTOCOL
    qtng_debug << "MasterKcpSocketPrivate::close() done";
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
        id = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(randomBytes(4).constData()));
#endif
    } while (receiversByConnectionId.contains(id));
    return id;
}

void MasterKcpSocketPrivate::doReceive()
{
    Q_Q(KcpSocket);
    HostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "KcpSocket can not receive udp packet." << rawSocket->errorString();
#endif
            MasterKcpSocketPrivate::close(true);
            return;
        }
        if (q->filter(buf.data(), &len, &addr, &port)) {
            continue;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "got invalid kcp packet smaller than 5 bytes." << QByteArray(buf.data(), len);
#endif
            continue;
        }

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(buf.data() + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar *>(buf.data() + 1));
#endif
        if (connectionId == 0) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "the kcp server side returns an invalid packet with zero connection id.";
#endif
            continue;
        } else {
            if (this->connectionId == 0) {
                this->connectionId = connectionId;
            } else {
                if (connectionId != this->connectionId) {
#ifdef DEBUG_PROTOCOL
                    qtng_debug << "the kcp server side returns an invalid packet with mismatched connection id.";
#endif
                    continue;
                } else {
                    // do nothing.
                }
            }
        }
        qToBigEndian<quint32>(0, reinterpret_cast<uchar *>(buf.data() + 1));
        if (!handleDatagram(buf.data(), static_cast<quint32>(len))) {
            return;
        }
    }
}

void MasterKcpSocketPrivate::doAccept()
{
    Q_Q(KcpSocket);
    HostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "KcpSocket can not receive udp packet." << rawSocket->errorString();
#endif
            MasterKcpSocketPrivate::close(true);
            return;
        }
        if (q->filter(buf.data(), &len, &addr, &port)) {
            continue;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "got invalid kcp packet smaller than 5 bytes.";
#endif
            continue;
        }

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(buf.data() + 1);
        qToBigEndian<quint32>(0, buf.data() + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar *>(buf.data() + 1));
        qToBigEndian<quint32>(0, reinterpret_cast<uchar *>(buf.data() + 1));
#endif
        const QString &key = concat(addr, port);
        QPointer<SlaveKcpSocketPrivate> receiver;
        receiver = receiversByHostAndPort.value(key);
        if (!receiver.isNull()) {
            receiver->remoteAddress = addr;
            receiver->remotePort = port;
            if (connectionId != 0) {
                if (receiver->connectionId == 0) {
                    // only if the slave was created by accept(host, port), we had zero id.
                    // if this connectionId is unique in client. we add it to the receiversByConnectionId map.
                    // if it is not, say sorry, and disable the multipath feature.
                    if (!receiversByConnectionId.contains(connectionId)) {
                        // only happened in the newly accept(host, port) connections.
                        // or remote create new conn with the same port as old, and the old packet is received.
                        receiver->connectionId = connectionId;
                        receiversByConnectionId.insert(connectionId, receiver);
                    }
                } else if (connectionId != receiver->connectionId) {
#ifdef DEBUG_PROTOCOL
                    qtng_debug << "the client sent a invalid connection id";
#endif
                    continue;
                }
            }
            if (!receiver->handleDatagram(buf.data(), static_cast<quint32>(len))) {
                receiversByHostAndPort.remove(receiver->originalHostAndPort);
                receiversByConnectionId.remove(receiver->connectionId);
            }
        } else {
            if (connectionId != 0) {  // a multipath packet.
                receiver = receiversByConnectionId.value(connectionId);
                if (receiver.isNull()) {
                    // it must be bad packet.
                    const QByteArray &closePacket = makeShutdownPacket(connectionId);
                    if (rawSocket->sendto(closePacket, addr, port) != closePacket.size()) {
                        if (error == Socket::NoError) {
                            error = Socket::SocketResourceError;
                            errorString = QString::fromLatin1("KcpSocket can not send udp packet.");
                        }
#ifdef DEBUG_PROTOCOL
                        qtng_debug << errorString;
#endif
                        MasterKcpSocketPrivate::close(true);
                    }
                } else {
                    Q_ASSERT(connectionId == receiver->connectionId);
                    receiver->remoteAddress = addr;
                    receiver->remotePort = port;
                    if (!receiver->handleDatagram(buf.data(), static_cast<quint32>(len))) {
#ifdef DEBUG_PROTOCOL
                        qtng_debug << "can not handle multipath packet.";
#endif
                        receiversByHostAndPort.remove(receiver->originalHostAndPort);
                        receiversByConnectionId.remove(receiver->connectionId);
                    }
                }
            } else if (pendingSlaves.size() < pendingSlaves.capacity()) {  // not full. process new connection.
                QScopedPointer<KcpSocket> slave(SlaveKcpSocketPrivate::create(this, addr, port, this->mode));
                SlaveKcpSocketPrivate *d = SlaveKcpSocketPrivate::getPrivateHelper(slave.data());
                d->originalHostAndPort = key;
                d->connectionId = nextConnectionId();
                if (d->handleDatagram(buf.data(), static_cast<quint32>(len))) {
                    receiversByHostAndPort.insert(key, d);
                    receiversByConnectionId.insert(d->connectionId, d);
                    pendingSlaves.put(slave.take());
                    const QByteArray &multiPathPacket = makeMultiPathPacket(d->connectionId);
                    if (rawSocket->sendto(multiPathPacket, addr, port) != multiPathPacket.size()) {
                        if (error == Socket::NoError) {
                            error = Socket::SocketResourceError;
                            errorString = QString::fromLatin1("KcpSocket can not send udp packet.");
                        }
#ifdef DEBUG_PROTOCOL
                        qtng_debug << errorString;
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
    if (!operations->get(QString::fromLatin1("receiving")).isNull()) {
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
        operations->spawnWithName(QString::fromLatin1("receiving"), [this] { doReceive(); });
        break;
    case Socket::ListeningState:
        operations->spawnWithName(QString::fromLatin1("receiving"), [this] { doAccept(); });
        break;
    }
    return true;
}

KcpSocket *MasterKcpSocketPrivate::accept()
{
    if (state != Socket::ListeningState) {
        return nullptr;
    }
    startReceivingCoroutine();
    return pendingSlaves.get();
}

KcpSocket *MasterKcpSocketPrivate::accept(const HostAddress &addr, quint16 port)
{
    if (state != Socket::ListeningState || addr.isNull() || port == 0) {
        return nullptr;
    }
    startReceivingCoroutine();
    const QString &key = concat(addr, port);
    QPointer<SlaveKcpSocketPrivate> receiver;
    receiver = receiversByHostAndPort.value(key);
    if (!receiver.isNull() && receiver->isValid()) {
        return nullptr;
    } else {
        QScopedPointer<KcpSocket> slave(SlaveKcpSocketPrivate::create(this, addr, port, this->mode));
        SlaveKcpSocketPrivate *d = SlaveKcpSocketPrivate::getPrivateHelper(slave.data());
        d->originalHostAndPort = key;
        d->updateKcp();
        receiversByHostAndPort.insert(key, d);
        // the connectionId is generated in server side. accept() is acually a connect().
        // receiversByConnectionId.insert(d->connectionId, d);
        return slave.take();
    }
}

KcpSocket *MasterKcpSocketPrivate::accept(const QString &hostName, quint16 port,
                                          QSharedPointer<SocketDnsCache> dnsCache)
{
    if (state != Socket::ListeningState || hostName.isNull() || port == 0) {
        return nullptr;
    }
    const HostAddress &addr = resolve(hostName, dnsCache);
    if (addr.isNull()) {
        return nullptr;
    } else {
        return accept(addr, port);
    }
}

bool MasterKcpSocketPrivate::connect(const HostAddress &addr, quint16 port)
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
    const HostAddress &addr = resolve(hostName, dnsCache);
    if (addr.isNull()) {
        return false;
    } else {
        return connect(addr, port);
    }
}

HostAddress MasterKcpSocketPrivate::resolve(const QString &hostName, QSharedPointer<SocketDnsCache> dnsCache)
{
    QList<HostAddress> addresses;
    HostAddress t;
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
        const HostAddress &addr = addresses.at(i);
        if (rawSocket->protocol() == HostAddress::IPv4Protocol && addr.protocol() == HostAddress::IPv6Protocol) {
            continue;
        }
        if (rawSocket->protocol() == HostAddress::IPv6Protocol && addr.protocol() == HostAddress::IPv4Protocol) {
            continue;
        }
        return addr;
    }
    return HostAddress();
}

qint32 MasterKcpSocketPrivate::peekRaw(char *data, qint32 size)
{
    return rawSocket->peek(data, size);
}

qint32 MasterKcpSocketPrivate::rawSend(const char *data, qint32 size)
{
    lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    startReceivingCoroutine();
    return rawSocket->sendto(data, size, remoteAddress, remotePort);
}

qint32 MasterKcpSocketPrivate::udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    return rawSocket->sendto(data, size, addr, port);
}

bool MasterKcpSocketPrivate::bind(const HostAddress &address, quint16 port, Socket::BindMode mode)
{
    if (state != Socket::UnconnectedState) {
        return false;
    }
    if (mode & Socket::ReuseAddressHint) {
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
    if (mode & Socket::ReuseAddressHint) {
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

bool MasterKcpSocketPrivate::joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    return rawSocket->joinMulticastGroup(groupAddress, iface);
}

bool MasterKcpSocketPrivate::leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    return rawSocket->leaveMulticastGroup(groupAddress, iface);
}

NetworkInterface MasterKcpSocketPrivate::multicastInterface() const
{
    return rawSocket->multicastInterface();
}

bool MasterKcpSocketPrivate::setMulticastInterface(const NetworkInterface &iface)
{
    return rawSocket->setMulticastInterface(iface);
}

SlaveKcpSocketPrivate::SlaveKcpSocketPrivate(MasterKcpSocketPrivate *parent, const HostAddress &addr, quint16 port,
                                             KcpSocket *q)
    : KcpSocketPrivate(q)
    , parent(parent)
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

HostAddress SlaveKcpSocketPrivate::localAddress() const
{
    if (parent.isNull()) {
        return HostAddress();
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

HostAddress::NetworkLayerProtocol SlaveKcpSocketPrivate::protocol() const
{
    if (parent.isNull()) {
        return HostAddress::UnknownNetworkLayerProtocol;
    }
    return parent->rawSocket->protocol();
}

bool SlaveKcpSocketPrivate::close(bool force)
{
    Q_Q(KcpSocket);
    // if `force` is true, must not block. it is called by doUpdate()
    if (state == Socket::UnconnectedState) {
        return true;
    } else if (state == Socket::ConnectedState) {
        state = Socket::UnconnectedState;
        if (!force && error != Socket::NoError) {
            if (!sendingQueueEmpty.isSet()) {
                updateKcp();
                if (!sendingQueueEmpty.tryWait()) {
                    return false;
                }
            }
            const QByteArray &packet = makeShutdownPacket(this->connectionId);
            rawSend(packet.constData(), packet.size());
        }
    } else {  // there can be no other states.
        state = Socket::UnconnectedState;
    }
    operations->killall();
    if (!parent.isNull()) {
        parent->removeSlave(originalHostAndPort);
        parent->removeSlave(connectionId);
        parent.clear();
    }
    // await all pending recv()/send()
    receivingQueueNotEmpty.set();
    sendingQueueEmpty.set();
    sendingQueueNotFull.set();
    q->notBusy.set();
    q->busy.set();
#ifdef DEBUG_PROTOCOL
    qtng_debug << "SlaveKcpSocketPrivate::close() done.";
#endif
    return true;
}

bool SlaveKcpSocketPrivate::listen(int)
{
    return false;
}

KcpSocket *SlaveKcpSocketPrivate::accept()
{
    return nullptr;
}

KcpSocket *SlaveKcpSocketPrivate::accept(const HostAddress &, quint16)
{
    return nullptr;
}

KcpSocket *SlaveKcpSocketPrivate::accept(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return nullptr;
}

bool SlaveKcpSocketPrivate::connect(const HostAddress &, quint16)
{
    return false;
}

bool SlaveKcpSocketPrivate::connect(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return false;
}

qint32 SlaveKcpSocketPrivate::peekRaw(char *data, qint32 size)
{
    if (parent.isNull()) {
        return -1;
    }
    return parent->rawSocket->peek(data, size);
}

qint32 SlaveKcpSocketPrivate::rawSend(const char *data, qint32 size)
{
    if (parent.isNull()) {
        return -1;
    } else {
        lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        return parent->rawSocket->sendto(data, size, remoteAddress, remotePort);
    }
}

qint32 SlaveKcpSocketPrivate::udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    if (parent.isNull()) {
        return -1;
    } else {
        return parent->rawSocket->sendto(data, size, addr, port);
    }
}

bool SlaveKcpSocketPrivate::bind(const HostAddress &, quint16, Socket::BindMode)
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

bool SlaveKcpSocketPrivate::joinMulticastGroup(const HostAddress &, const NetworkInterface &)
{
    return false;
}

bool SlaveKcpSocketPrivate::leaveMulticastGroup(const HostAddress &, const NetworkInterface &)
{
    return false;
}

NetworkInterface SlaveKcpSocketPrivate::multicastInterface() const
{
    return NetworkInterface();
}

bool SlaveKcpSocketPrivate::setMulticastInterface(const NetworkInterface &)
{
    return false;
}

KcpSocket::KcpSocket(HostAddress::NetworkLayerProtocol protocol)
    : d_ptr(new MasterKcpSocketPrivate(protocol, this))
{
}

KcpSocket::KcpSocket(qintptr socketDescriptor)
    : d_ptr(new MasterKcpSocketPrivate(socketDescriptor, this))
{
}

KcpSocket::KcpSocket(QSharedPointer<Socket> rawSocket)
    : d_ptr(new MasterKcpSocketPrivate(rawSocket, this))
{
}

KcpSocket::KcpSocket(KcpSocketPrivate *parent, const HostAddress &addr, const quint16 port, KcpSocket::Mode mode)
    : d_ptr(new SlaveKcpSocketPrivate(static_cast<MasterKcpSocketPrivate *>(parent), addr, port, this))
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

void KcpSocket::setTearDownTime(float secs)
{
    Q_D(KcpSocket);
    if (secs > 0) {
        d->tearDownTime = static_cast<quint64>(secs * 1000);
        if (d->tearDownTime < 1000) {
            d->tearDownTime = 1000;
        }
    }
}

float KcpSocket::tearDownTime() const
{
    Q_D(const KcpSocket);
    return d->tearDownTime / 1000.0f;
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

HostAddress KcpSocket::localAddress() const
{
    Q_D(const KcpSocket);
    return d->localAddress();
}

quint16 KcpSocket::localPort() const
{
    Q_D(const KcpSocket);
    return d->localPort();
}

HostAddress KcpSocket::peerAddress() const
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

HostAddress::NetworkLayerProtocol KcpSocket::protocol() const
{
    Q_D(const KcpSocket);
    return d->protocol();
}

QString KcpSocket::localAddressURI() const
{
    Q_D(const KcpSocket);
    QString address = QLatin1String("kcp://%1:%2");
    const HostAddress &localAddress = d->localAddress();
    if (localAddress.protocol() == HostAddress::IPv6Protocol) {
        address = address.arg(QString::fromLatin1("[%1]").arg(localAddress.toString()));
    } else {
        address = address.arg(localAddress.toString());
    }
    address = address.arg(d->localPort());
    return address;
}

QString KcpSocket::peerAddressURI() const
{
    Q_D(const KcpSocket);
    QString address = QLatin1String("kcp://%1:%2");
    if (d->remoteAddress.protocol() == HostAddress::IPv6Protocol) {
        address = address.arg(QString::fromLatin1("[%1]").arg(d->remoteAddress.toString()));
    } else {
        address = address.arg(d->remoteAddress.toString());
    }
    address = address.arg(d->remotePort);
    return address;
}

KcpSocket *KcpSocket::accept()
{
    Q_D(KcpSocket);
    return d->accept();
}

KcpSocket *KcpSocket::accept(const HostAddress &addr, quint16 port)
{
    Q_D(KcpSocket);
    return d->accept(addr, port);
}

KcpSocket *KcpSocket::accept(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    Q_D(KcpSocket);
    return d->accept(hostName, port, dnsCache);
}

bool KcpSocket::bind(const HostAddress &address, quint16 port, Socket::BindMode mode)
{
    Q_D(KcpSocket);
    return d->bind(address, port, mode);
}

bool KcpSocket::bind(quint16 port, Socket::BindMode mode)
{
    Q_D(KcpSocket);
    return d->bind(port, mode);
}

bool KcpSocket::connect(const HostAddress &addr, quint16 port)
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

bool KcpSocket::joinMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    Q_D(KcpSocket);
    return d->joinMulticastGroup(groupAddress, iface);
}

bool KcpSocket::leaveMulticastGroup(const HostAddress &groupAddress, const NetworkInterface &iface)
{
    Q_D(KcpSocket);
    return d->leaveMulticastGroup(groupAddress, iface);
}

NetworkInterface KcpSocket::multicastInterface() const
{
    Q_D(const KcpSocket);
    return d->multicastInterface();
}

bool KcpSocket::setMulticastInterface(const NetworkInterface &iface)
{
    Q_D(KcpSocket);
    return d->setMulticastInterface(iface);
}

qint32 KcpSocket::peek(char *data, qint32 size)
{
    Q_D(KcpSocket);
    return d->peek(data, size);
}

qint32 KcpSocket::peekRaw(char *data, qint32 size)
{
    Q_D(KcpSocket);
    return d->peekRaw(data, size);
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
    if (bytesSent == 0 && !d->isValid()) {
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
    QByteArray bs(size, Qt::Uninitialized);

    qint32 bytes = d->recv(bs.data(), bs.size(), false);
    if (bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

QByteArray KcpSocket::recvall(qint32 size)
{
    Q_D(KcpSocket);
    QByteArray bs(size, Qt::Uninitialized);

    qint32 bytes = d->recv(bs.data(), bs.size(), true);
    if (bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

qint32 KcpSocket::send(const QByteArray &data)
{
    Q_D(KcpSocket);
    qint32 bytesSent = d->send(data.data(), data.size(), false);
    if (bytesSent == 0 && !d->isValid()) {
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

bool KcpSocket::filter(char *data, qint32 *len, HostAddress *addr, quint16 *port)
{
    Q_UNUSED(data);
    Q_UNUSED(len);
    Q_UNUSED(addr);
    Q_UNUSED(port);
    return false;
}

qint32 KcpSocket::udpSend(const char *data, qint32 size, const HostAddress &addr, quint16 port)
{
    Q_D(KcpSocket);
    return d->udpSend(data, size, addr, port);
}

KcpSocket *KcpSocket::createConnection(const HostAddress &host, quint16 port, Socket::SocketError *error,
                                       int allowProtocol)
{
    return QTNETWORKNG_NAMESPACE::createConnection<KcpSocket>(host, port, error, allowProtocol,
                                                              MakeSocketType<KcpSocket>);
}

KcpSocket *KcpSocket::createConnection(const QString &hostName, quint16 port, Socket::SocketError *error,
                                       QSharedPointer<SocketDnsCache> dnsCache, int allowProtocol)
{
    return QTNETWORKNG_NAMESPACE::createConnection<KcpSocket>(hostName, port, error, dnsCache, allowProtocol,
                                                              MakeSocketType<KcpSocket>);
}

KcpSocket *KcpSocket::createServer(const HostAddress &host, quint16 port, int backlog)
{
    return QTNETWORKNG_NAMESPACE::createServer<KcpSocket>(host, port, backlog, MakeSocketType<KcpSocket>);
}

namespace {

class KcpSocketLikeImpl : public SocketLike
{
public:
    KcpSocketLikeImpl(QSharedPointer<KcpSocket> s);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;
    virtual QString localAddressURI() const override;
    virtual QString peerAddressURI() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual void close() override;
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint32 peek(char *data, qint32 size) override;
    virtual qint32 peekRaw(char *data, qint32 size) override;
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

KcpSocketLikeImpl::KcpSocketLikeImpl(QSharedPointer<KcpSocket> s)
    : s(s)
{
}

Socket::SocketError KcpSocketLikeImpl::error() const
{
    return s->error();
}

QString KcpSocketLikeImpl::errorString() const
{
    return s->errorString();
}

bool KcpSocketLikeImpl::isValid() const
{
    return s->isValid();
}

HostAddress KcpSocketLikeImpl::localAddress() const
{
    return s->localAddress();
}

quint16 KcpSocketLikeImpl::localPort() const
{
    return s->localPort();
}

HostAddress KcpSocketLikeImpl::peerAddress() const
{
    return s->peerAddress();
}

QString KcpSocketLikeImpl::peerName() const
{
    return s->peerName();
}

quint16 KcpSocketLikeImpl::peerPort() const
{
    return s->peerPort();
}

qintptr KcpSocketLikeImpl::fileno() const
{
    return -1;
}

Socket::SocketType KcpSocketLikeImpl::type() const
{
    return s->type();
}

Socket::SocketState KcpSocketLikeImpl::state() const
{
    return s->state();
}

HostAddress::NetworkLayerProtocol KcpSocketLikeImpl::protocol() const
{
    return s->protocol();
}

QString KcpSocketLikeImpl::localAddressURI() const
{
    return s->localAddressURI();
}

QString KcpSocketLikeImpl::peerAddressURI() const
{
    return s->peerAddressURI();
}

Socket *KcpSocketLikeImpl::acceptRaw()
{
    return nullptr;
}

QSharedPointer<SocketLike> KcpSocketLikeImpl::accept()
{
    return asSocketLike(s->accept());
}

bool KcpSocketLikeImpl::bind(const HostAddress &address, quint16 port = 0,
                             Socket::BindMode mode = Socket::DefaultForPlatform)
{
    return s->bind(address, port, mode);
}

bool KcpSocketLikeImpl::bind(quint16 port, Socket::BindMode mode)
{
    return s->bind(port, mode);
}

bool KcpSocketLikeImpl::connect(const HostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}

bool KcpSocketLikeImpl::connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache)
{
    return s->connect(hostName, port, dnsCache);
}

void KcpSocketLikeImpl::close()
{
    s->close();
}

void KcpSocketLikeImpl::abort()
{
    s->abort();
}

bool KcpSocketLikeImpl::listen(int backlog)
{
    return s->listen(backlog);
}

bool KcpSocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}

QVariant KcpSocketLikeImpl::option(Socket::SocketOption option) const
{
    return s->option(option);
}

qint32 KcpSocketLikeImpl::peek(char *data, qint32 size)
{
    return s->peek(data, size);
}

qint32 KcpSocketLikeImpl::peekRaw(char *data, qint32 size)
{
    return s->peekRaw(data, size);
}

qint32 KcpSocketLikeImpl::recv(char *data, qint32 size)
{
    return s->recv(data, size);
}

qint32 KcpSocketLikeImpl::recvall(char *data, qint32 size)
{
    return s->recvall(data, size);
}

qint32 KcpSocketLikeImpl::send(const char *data, qint32 size)
{
    return s->send(data, size);
}

qint32 KcpSocketLikeImpl::sendall(const char *data, qint32 size)
{
    return s->sendall(data, size);
}

QByteArray KcpSocketLikeImpl::recv(qint32 size)
{
    return s->recv(size);
}

QByteArray KcpSocketLikeImpl::recvall(qint32 size)
{
    return s->recvall(size);
}

qint32 KcpSocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}

qint32 KcpSocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}

}  // namespace

QSharedPointer<SocketLike> asSocketLike(QSharedPointer<KcpSocket> s)
{
    if (s.isNull()) {
        return QSharedPointer<SocketLike>();
    }
    return QSharedPointer<KcpSocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QSharedPointer<KcpSocket> convertSocketLikeToKcpSocket(QSharedPointer<SocketLike> socket)
{
    QSharedPointer<KcpSocketLikeImpl> impl = socket.dynamicCast<KcpSocketLikeImpl>();
    if (impl.isNull()) {
        return QSharedPointer<KcpSocket>();
    } else {
        return impl->s;
    }
}

QTNETWORKNG_NAMESPACE_END
