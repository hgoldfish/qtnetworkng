#ifndef QTNG_KCP_BASE_P_H
#define QTNG_KCP_BASE_P_H

#include <QtCore/qdatetime.h>
#include <QtCore/qendian.h>
#include <QtCore/qobject.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QtCore/qrandom.h>
#endif
#include "../include/kcp_base.h"
#include "../include/coroutine_utils.h"
#include "../include/random.h"
#include "./kcp/ikcp.h"
#include "debugger.h"

QTNG_LOGGER("qtng.kcp_base");

QTNETWORKNG_NAMESPACE_BEGIN

const char PACKET_TYPE_UNCOMPRESSED_DATA = 0x01;
const char PACKET_TYPE_CREATE_MULTIPATH = 0x02;
const char PACKET_TYPE_CLOSE = 0x03;
const char PACKET_TYPE_KEEPALIVE = 0x04;

// #define DEBUG_PROTOCOL 1

template<typename Link>
class KcpBase : public QObject
{
public:
    typedef typename Link::PathID LinkPathID;
    explicit KcpBase(KcpMode mode = KcpMode::Internet);
    virtual ~KcpBase();
public:
    void setMode(KcpMode mode);
    void setDebugLevel(int level);
    void setSendQueueSize(quint32 sendQueueSize);
    quint32 sendQueueSize() const;
    void setUdpPacketSize(quint32 udpPacketSize);
    quint32 udpPacketSize() const;
    quint32 payloadSizeHint() const;
    void setTearDownTime(float secs);
    float tearDownTime() const;
    void setState(Socket::SocketState state);
    LinkPathID peerId() const;
public:
    virtual bool isValid() const = 0;
    virtual QSharedPointer<KcpBase<Link>> accept() = 0;
    virtual QSharedPointer<KcpBase<Link>> accept(const LinkPathID &remote) = 0;
    virtual bool canBind() = 0;
    virtual bool canConnect() = 0;

    void close();
    void abort();

    qint32 peek(char *data, qint32 size);
    virtual qint32 peekRaw(char *data, qint32 size) = 0;
    qint32 recv(char *data, qint32 size);
    qint32 recvall(char *data, qint32 size);
    qint32 send(const char *data, qint32 size);
    qint32 sendall(const char *data, qint32 size);
    QByteArray recv(qint32 size);
    QByteArray recvall(qint32 size);
    qint32 send(const QByteArray &data);
    qint32 sendall(const QByteArray &data);

    qint32 udpSend(const QByteArray &packet, const LinkPathID &remote)
    {
        return udpSend(packet.constData(), packet.size(), remote);
    }

    static int kcp_callback(const char *buf, int len, ikcpcb *, void *user);
    static QByteArray makeDataPacket(quint32 connectionId, const char *data, qint32 size);
    static QByteArray makeShutdownPacket(quint32 connectionId);
    static QByteArray makeKeepalivePacket(quint32 connectionId);
    static QByteArray makeMultiPathPacket(quint32 connectionId);

    virtual qint32 sendRaw(const char *data, qint32 size) = 0;
    virtual qint32 udpSend(const char *data, qint32 size, const LinkPathID &remote) = 0;
    virtual bool listen(int backlog) = 0;
protected:
    qint32 send(const char *data, qint32 size, bool all);
    qint32 recv(char *data, qint32 size, bool all);
    virtual bool close(bool force) = 0;
protected:
    bool handleDatagram(const char *buf, qint32 len, const LinkPathID &remote);  // len bigger than 5
    void updateKcp();
    void updateStatus();
    virtual void doUpdate();
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

    char waitToReadBuffer[65536];
    int waitToReadOffset;
    int waitToReadSize;

    const quint64 zeroTimestamp;
    quint64 lastActiveTimestamp;
    quint64 lastKeepaliveTimestamp;
    quint64 m_tearDownTime;
    ikcpcb *kcp;
    quint32 waterLine;
    quint32 connectionId;
    LinkPathID remoteId;
    KcpMode mode;
};

template<typename Link>
class SlaveKcpBase;

template<typename Link>
class MasterKcpBase : public KcpBase<Link>
{
public:
    typedef typename Link::PathID LinkPathID;
    explicit MasterKcpBase(QSharedPointer<Link> link);
    virtual ~MasterKcpBase();
public:
    virtual bool isValid() const override;
    virtual bool canBind() override;
    virtual bool canConnect() override;
    virtual QSharedPointer<KcpBase<Link>> accept() override;
    virtual QSharedPointer<KcpBase<Link>> accept(const LinkPathID &remote) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 sendRaw(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const LinkPathID &remote) override;
protected:
    quint32 nextConnectionId();
    void doReceive();
    void doAccept();
    QWeakPointer<class SlaveKcpBase<Link>> doAccept(quint32 connectionId, const LinkPathID &remote, bool &add);
    bool startReceivingCoroutine();
public:
    friend class SlaveKcpBase<Link>;
    QSharedPointer<Link> link;
    QMap<LinkPathID, QWeakPointer<class SlaveKcpBase<Link>>> receiversByLinkPathID;
    QMap<quint32, QWeakPointer<class SlaveKcpBase<Link>>> receiversByConnectionId;
    Queue<QSharedPointer<KcpBase<Link>>> pendingSlaves;
};

template<typename Link>
class SlaveKcpBase : public KcpBase<Link>
{
public:
    typedef typename Link::PathID LinkPathID;
    SlaveKcpBase(MasterKcpBase<Link> *parent, const LinkPathID &remote, KcpMode mode);
    virtual ~SlaveKcpBase();
public:
    virtual bool isValid() const override;
    virtual bool canBind() override;
    virtual bool canConnect() override;
    virtual QSharedPointer<KcpBase<Link>> accept() override;
    virtual QSharedPointer<KcpBase<Link>> accept(const LinkPathID &remote) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual qint32 peekRaw(char *data, qint32 size) override;
    virtual qint32 sendRaw(const char *data, qint32 size) override;
    virtual qint32 udpSend(const char *data, qint32 size, const LinkPathID &remote) override;
    virtual void doUpdate() override;
public:
    friend class MasterKcpBase<Link>;
    LinkPathID originalPathID;
    QPointer<MasterKcpBase<Link>> parent;
};

template<typename Link>
KcpBase<Link>::KcpBase(KcpMode mode /* = KcpMode::Internet*/)
    : operations(new CoroutineGroup())
    , state(Socket::UnconnectedState)
    , error(Socket::NoError)
    , waitToReadOffset(0)
    , waitToReadSize(0)
    , zeroTimestamp(static_cast<quint64>(QDateTime::currentMSecsSinceEpoch()))
    , lastActiveTimestamp(zeroTimestamp)
    , lastKeepaliveTimestamp(zeroTimestamp)
    , m_tearDownTime(1000 * 30)
    , waterLine(1024)
    , connectionId(0)
    , mode(mode)
{
    kcp = ikcp_create(0, this);
    ikcp_setoutput(kcp, kcp_callback);

    sendingQueueEmpty.set();
    sendingQueueNotFull.set();
    receivingQueueNotEmpty.clear();
    setMode(mode);
}

template<typename Link>
KcpBase<Link>::~KcpBase()
{
    delete operations;
    ikcp_release(kcp);
}

template<typename Link>
void KcpBase<Link>::setMode(KcpMode mode)
{
    this->mode = mode;
    switch (mode) {
    case KcpMode::LargeDelayInternet:
        waterLine = 512;
        ikcp_nodelay(kcp, 0, 20, 1, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    case KcpMode::Internet:
        waterLine = 256;
        ikcp_nodelay(kcp, 1, 10, 1, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        kcp->rx_minrto = 30;
        // kcp->interval = 5;
        break;
    case KcpMode::FastInternet:
        waterLine = 192;
        ikcp_nodelay(kcp, 1, 10, 1, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 512, 512);
        kcp->rx_minrto = 20;
        // kcp->interval = 2;
        break;
    case KcpMode::Ethernet:
        waterLine = 64;
        ikcp_nodelay(kcp, 1, 10, 1, 1);
        ikcp_setmtu(kcp, 1024 * 32);
        ikcp_wndsize(kcp, 128, 128);
        kcp->rx_minrto = 10;
        // kcp->interval = 1;
        break;
    case KcpMode::Loopback:
        waterLine = 64;
        ikcp_nodelay(kcp, 1, 10, 1, 1);
        ikcp_setmtu(kcp, 1024 * 64 - 256);
        ikcp_wndsize(kcp, 128, 128);
        kcp->rx_minrto = 5;
        // kcp->interval = 1;
        break;
    }
}

template<typename Link>
void KcpBase<Link>::setDebugLevel(int level)
{
    if (level > 0) {
        kcp->writelog = [](const char *log, struct IKCPCB *kcp, void *user) {qtng_debug << log;};
        kcp->logmask |= IKCP_LOG_IN_ACK | IKCP_LOG_OUTPUT | IKCP_LOG_IN_DATA | IKCP_LOG_IN_PROBE | IKCP_LOG_IN_WINS;
    }
}

template<typename Link>
void KcpBase<Link>::setSendQueueSize(quint32 sendQueueSize)
{
    waterLine = sendQueueSize;
}

template<typename Link>
quint32 KcpBase<Link>::sendQueueSize() const
{
    return waterLine;
}

template<typename Link>
void KcpBase<Link>::setUdpPacketSize(quint32 udpPacketSize)
{
    if (udpPacketSize < 65535) {
        ikcp_setmtu(kcp, static_cast<int>(udpPacketSize));
    }
}

template<typename Link>
quint32 KcpBase<Link>::udpPacketSize() const
{
    return kcp->mtu;
}

template<typename Link>
quint32 KcpBase<Link>::payloadSizeHint() const
{
    return kcp->mss;
}

template<typename Link>
void KcpBase<Link>::setTearDownTime(float secs)
{
    if (secs > 0) {
        m_tearDownTime = static_cast<quint64>(secs * 1000);
        if (m_tearDownTime < 1000) {
            m_tearDownTime = 1000;
        }
    }
}

template<typename Link>
float KcpBase<Link>::tearDownTime() const
{
    return m_tearDownTime / 1000.0f;
}

template<typename Link>
void KcpBase<Link>::setState(Socket::SocketState state)
{
    this->state = state;
}

template<typename Link>
typename Link::PathID KcpBase<Link>::peerId() const
{
    return remoteId;
}

template<typename Link>
void KcpBase<Link>::close()
{
    close(false);
}

template<typename Link>
void KcpBase<Link>::abort()
{
    close(true);
}

template<typename Link>
qint32 KcpBase<Link>::peek(char *data, qint32 size)
{
    if (state != Socket::ConnectedState) {
        return -1;
    }
    if (waitToReadSize - waitToReadOffset > 0) {
        qint32 result = qMin(size, waitToReadSize - waitToReadOffset);
        memcpy(data, waitToReadBuffer + waitToReadOffset, result);
        return result;
    }
    
    ScopedLock<RLock> l(kcpLock);
    int peeksize = ikcp_peeksize(kcp);
    if (peeksize > 0) {
        peeksize = qMin(static_cast<int>(sizeof(waitToReadBuffer)), peeksize);
        int readBytes = ikcp_recv(kcp, waitToReadBuffer, peeksize);
        Q_ASSERT(readBytes == peeksize);
        waitToReadOffset = 0;
        waitToReadSize = readBytes;

        qint32 result = qMin(size, waitToReadSize);
        memcpy(data, waitToReadBuffer, result);
        return result;
    }
    return 0;
}

template<typename Link>
qint32 KcpBase<Link>::recv(char *data, qint32 size)
{
    return recv(data, size, false);
}

template<typename Link>
qint32 KcpBase<Link>::recvall(char *data, qint32 size)
{
    return recv(data, size, true);
}

template<typename Link>
qint32 KcpBase<Link>::send(const char *data, qint32 size)
{
    qint32 bytesSent = send(data, size, false);
    if (bytesSent == 0 && !isValid()) {
        return -1;
    }
    return bytesSent;
}

template<typename Link>
qint32 KcpBase<Link>::sendall(const char *data, qint32 size)
{
    return send(data, size, true);
}

template<typename Link>
QByteArray KcpBase<Link>::recv(qint32 size)
{
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = recv(bs.data(), bs.size(), false);
    if (bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

template<typename Link>
qint32 KcpBase<Link>::recv(char *data, qint32 size, bool all)
{
    if (size <= 0) {
        return -1;
    }
    qint32 left = size;
    qint32 total = 0;
    while (true) {
        if (waitToReadSize - waitToReadOffset > 0) {
            qint32 len = qMin(left, waitToReadSize - waitToReadOffset);
            memcpy(data + total, waitToReadBuffer + waitToReadOffset, static_cast<size_t>(len));
            total += len;
            waitToReadOffset += len;
            if (!all || total >= size) {
                return total;
            }
            left -= len;
        }
        while (true) {
            {
                ScopedLock<RLock> l(kcpLock);
                int peeksize = ikcp_peeksize(kcp);
                if (peeksize > 0) {
                    peeksize = qMin(static_cast<int>(sizeof(waitToReadBuffer)), peeksize);
                    int readBytes = ikcp_recv(kcp, waitToReadBuffer, peeksize);
                    Q_ASSERT(readBytes == peeksize);
                    waitToReadOffset = 0;
                    waitToReadSize = readBytes;
                    break;
                }
            }
            if (state != Socket::ConnectedState) {
                error = Socket::SocketAccessError;
                errorString = QString::fromLatin1("KcpBase is not connected.");
                return -1;
            }
            receivingQueueNotEmpty.clear();
            if (!receivingQueueNotEmpty.tryWait()) {
                return total > 0 ? total : -1;
            }
        }
    }
}

template<typename Link>
QByteArray KcpBase<Link>::recvall(qint32 size)
{
    QByteArray bs(size, Qt::Uninitialized);
    qint32 bytes = recv(bs.data(), bs.size(), true);
    if (bytes > 0) {
        bs.resize(bytes);
        return bs;
    }
    return QByteArray();
}

template<typename Link>
qint32 KcpBase<Link>::send(const QByteArray &data)
{
    qint32 bytesSent = send(data.data(), data.size(), false);
    if (bytesSent == 0 && !isValid()) {
        return -1;
    } else {
        return bytesSent;
    }
}

template<typename Link>
qint32 KcpBase<Link>::send(const char *data, qint32 size, bool all)
{
    if (size <= 0) {
        return -1;
    }

    sendingQueueEmpty.clear();

    qint32 total = 0;
    do {
        if (state != Socket::ConnectedState) {
            error = Socket::SocketAccessError;
            errorString = QString::fromLatin1("KcpBase is not connected.");
            return -1;
        }
        if (!sendingQueueNotFull.tryWait()) {
            return total > 0 ? total : -1;
        }
        qint32 nextBlockSize = qMin<qint32>(static_cast<qint32>(kcp->mss), size - total);
        int result;
        {
            ScopedLock<RLock> l(kcpLock);
            result = ikcp_send(kcp, data + total, nextBlockSize);
        }
        if (result < 0) {
            qtng_warning << "why ikcp_send error happened? result:" << result << "connectionId:" << connectionId;
            return total > 0 ? total : -1;
        }
        Q_ASSERT(result == nextBlockSize);
        updateStatus();
        total += result;
        if (!all) {
            break;
        }
    } while (total < size);

    updateKcp();
    return total;
}

template<typename Link>
qint32 KcpBase<Link>::sendall(const QByteArray &data)
{
    return send(data.data(), data.size(), true);
}

template<typename Link>
int KcpBase<Link>::kcp_callback(const char *buf, int len, ikcpcb *, void *user)
{
    KcpBase<Link> *p = static_cast<KcpBase<Link> *>(user);
    if (!p || !buf || len > 65535) {
        qtng_warning << "kcp_callback got invalid data.";
        return -1;
    }
    const QByteArray &packet = KcpBase<Link>::makeDataPacket(p->connectionId, buf, len);
    qint32 sentBytes = p->sendRaw(packet.data(), packet.size());
    if (sentBytes != packet.size()) {  // but why this happens?
        if (p->error == Socket::NoError) {
            p->error = Socket::SocketAccessError;
            p->errorString = QString::fromLatin1("can not send udp packet");
        }
#ifdef DEBUG_PROTOCOL
        qtng_warning << "can not send packet to connection:" << p->connectionId;
#endif
        p->close(true);
        return -1;
    }
    return sentBytes;
}

template<typename Link>
QByteArray KcpBase<Link>::makeDataPacket(quint32 connectionId, const char *data, qint32 size)
{
    QByteArray packet(size + 1, Qt::Uninitialized);
    packet.data()[0] = PACKET_TYPE_UNCOMPRESSED_DATA;
    memcpy(packet.data() + 1, data, static_cast<size_t>(size));
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

template<typename Link>
QByteArray KcpBase<Link>::makeShutdownPacket(quint32 connectionId)
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

template<typename Link>
QByteArray KcpBase<Link>::makeKeepalivePacket(quint32 connectionId)
{
    // should be larger than 5 bytes. tail bytes are discard.
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QByteArray packet = randomBytes(QRandomGenerator::global()->bounded(5, 64));
#else
    QByteArray packet = randomBytes(5 + qrand() % (64 - 5));
#endif
    packet.data()[0] = PACKET_TYPE_KEEPALIVE;
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian<quint32>(connectionId, packet.data() + 1);
#else
    qToBigEndian<quint32>(connectionId, reinterpret_cast<uchar *>(packet.data() + 1));
#endif
    return packet;
}

template<typename Link>
QByteArray KcpBase<Link>::makeMultiPathPacket(quint32 connectionId)
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

template<typename Link>
bool KcpBase<Link>::handleDatagram(const char *buf, qint32 len, const LinkPathID &remote)
{
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
            return false;
        }
        lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        updateKcp(); // send ack before info user layer that has receive data can let kcp faster
        receivingQueueNotEmpty.set();
        remoteId = remote;
        return true;
    }
    case PACKET_TYPE_CREATE_MULTIPATH:
        remoteId = remote;
        return true;
    case PACKET_TYPE_CLOSE:
        if (remote == remoteId) {
            close(true);
            // error for return
            return false;
        }
        // ignore if remote is not recored one
        return true;
    case PACKET_TYPE_KEEPALIVE:
        lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
#ifdef DEBUG_PROTOCOL
        qtng_debug << "recv keep alive from" << connectionId << remoteId;
#endif
        remoteId = remote;
        return true;
    default:
        break;
    }
    // ignore if remote is not recored one
    return !(remote == remoteId);
}

template<typename Link>
void KcpBase<Link>::doUpdate()
{
    // in close(), state is set to Socket::UnconnectedState but error = NoError.
    while (state == Socket::ConnectedState || (state == Socket::UnconnectedState && error == Socket::NoError)) {
        quint64 now = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        // now and lastActiveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastActiveTimestamp && (now - lastActiveTimestamp > m_tearDownTime)
            && state == Socket::ConnectedState) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "kcp socket tear down!" << remoteId << "connectionId:" << connectionId;
#endif
            error = Socket::SocketTimeoutError;
            errorString = QString::fromLatin1("kcp is timeout.");
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
            const QByteArray &packet = KcpBase<Link>::makeKeepalivePacket(connectionId);
            if (sendRaw(packet.data(), packet.size()) != packet.size()) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "can not send keep alive packet.";
#endif
                close(true);
                return;
            }
#ifdef DEBUG_PROTOCOL
            qtng_debug << "keep alive packet sent to" << remoteId << "connectionId:" << connectionId;
#endif
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

template<typename Link>
void KcpBase<Link>::updateKcp()
{
    QSharedPointer<Coroutine> t = operations->spawnWithName(
            QString::fromLatin1("update_kcp"), [this] { doUpdate(); }, false);
    kcp->updated = 0;
    forceToUpdate.open();
}

template<typename Link>
void KcpBase<Link>::updateStatus()
{
    int sendingQueueSize = ikcp_waitsnd(kcp);
    if (sendingQueueSize <= 0) {
        sendingQueueNotFull.set();
        sendingQueueEmpty.set();
    } else {
        sendingQueueEmpty.clear();
        if (static_cast<quint32>(sendingQueueSize) > (kcp->snd_wnd << 1)) {
            sendingQueueNotFull.clear();
        } else if (static_cast<quint32>(sendingQueueSize) <= waterLine) {
            sendingQueueNotFull.set();
        }
    }
}

template<typename Link>
MasterKcpBase<Link>::MasterKcpBase(QSharedPointer<Link> link)
    : KcpBase<Link>()
    , link(link)
{
}

template<typename Link>
MasterKcpBase<Link>::~MasterKcpBase()
{
    MasterKcpBase<Link>::close(true);
}

template<typename Link>
bool MasterKcpBase<Link>::isValid() const
{
    return this->state == Socket::ConnectedState || this->state == Socket::BoundState
            || this->state == Socket::ListeningState;
}

template<typename Link>
bool MasterKcpBase<Link>::canBind()
{
    return this->state == Socket::UnconnectedState;
}

template<typename Link>
bool MasterKcpBase<Link>::canConnect()
{
    return this->state == Socket::UnconnectedState || this->state == Socket::BoundState;
}

template<typename Link>
QSharedPointer<KcpBase<Link>> MasterKcpBase<Link>::accept()
{
    if (this->state != Socket::ListeningState) {
        return nullptr;
    }
    startReceivingCoroutine();
    return pendingSlaves.get();
}

template<typename Link>
QSharedPointer<KcpBase<Link>> MasterKcpBase<Link>::accept(const LinkPathID &remote)
{
    if (this->state != Socket::ListeningState || remote.isNull()) {
        return nullptr;
    }
    startReceivingCoroutine();
    QWeakPointer<SlaveKcpBase<Link>> receiverPtr = receiversByLinkPathID.value(remote);
    if (!receiverPtr.isNull()) {
        QSharedPointer<SlaveKcpBase<Link>> receiver = receiverPtr.toStrongRef();
        if (!receiver->isValid()) {
            return nullptr;
        }
    }

    QSharedPointer<SlaveKcpBase<Link>> slave(new SlaveKcpBase<Link>(this, remote, this->mode));
    slave->updateKcp();
    receiversByLinkPathID.insert(remote, slave);
    // the connectionId is generated in server side. accept() is acually a connect().
    // receiversByConnectionId.insert(slave->connectionId, slave);
    return slave;
}

template<typename Link>
bool MasterKcpBase<Link>::close(bool force)
{
    // if `force` is true, must not block. see doUpdate()
    if (this->state == Socket::UnconnectedState) {
        return true;
    } else if (this->state == Socket::ConnectedState) {
        this->state = Socket::UnconnectedState;
        if (!force && this->error == Socket::NoError) {
            if (!this->sendingQueueEmpty.isSet()) {
                this->updateKcp();
                if (!this->sendingQueueEmpty.tryWait()) {
                    return false;
                }
            }
            const QByteArray &packet = KcpBase<Link>::makeShutdownPacket(this->connectionId);
            sendRaw(packet.constData(), packet.size());
        }
    } else if (this->state == Socket::ListeningState) {
        this->state = Socket::UnconnectedState;
        QMap<LinkPathID, QWeakPointer<class SlaveKcpBase<Link>>> receiversByLinkPathID(
                this->receiversByLinkPathID);
        this->receiversByLinkPathID.clear();
        for (QWeakPointer<SlaveKcpBase<Link>> receiverPtr : receiversByLinkPathID) {
            if (!receiverPtr.isNull()) {
                QSharedPointer<SlaveKcpBase<Link>> receiver = receiverPtr;
                receiver->close(force);
            }
        }
        receiversByConnectionId.clear();
    } else {  // BoundState
        this->state = Socket::UnconnectedState;
        this->link->abort();
        return true;
    }

    while (!pendingSlaves.isEmpty()) {
        pendingSlaves.get();
    }
    pendingSlaves.put(nullptr);

    // connected and listen state would do more cleaning work.
    this->operations->killall();
    // always kill operations before release resources.

    if (force) {
        this->link->abort();
    } else {
        this->link->close();
    }
    // awake all pending recv()/send()
    this->receivingQueueNotEmpty.set();
    this->sendingQueueEmpty.set();
    this->sendingQueueNotFull.set();
#ifdef DEBUG_PROTOCOL
    qtng_debug << "MasterKcpBasePrivate::close() done. connectionId:" << this->connectionId;
#endif
    return true;
}

template<typename Link>
bool MasterKcpBase<Link>::listen(int backlog)
{
    if (this->state != Socket::BoundState || backlog <= 0) {
        return false;
    }
    this->state = Socket::ListeningState;
    pendingSlaves.setCapacity(static_cast<quint32>(backlog));
    return true;
}

template<typename Link>
qint32 MasterKcpBase<Link>::peekRaw(char *data, qint32 size)
{
    if (size <= 0) {
        return -1;
    }
    return KcpBase<Link>::peek(data, size);
}

template<typename Link>
qint32 MasterKcpBase<Link>::sendRaw(const char *data, qint32 size)
{
    this->lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    startReceivingCoroutine();
    return this->link->sendto(data, size, this->remoteId);
}

template<typename Link>
qint32 MasterKcpBase<Link>::udpSend(const char *data, qint32 size, const LinkPathID &remote)
{
    return this->link->sendto(data, size, remote);
}

template<typename Link>
quint32 MasterKcpBase<Link>::nextConnectionId()
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

template<typename Link>
void MasterKcpBase<Link>::doReceive()
{
    LinkPathID remote;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    char *data = buf.data();
    while (true) {
        qint32 len = this->link->recvfrom(data, buf.size(), remote);
        if (Q_UNLIKELY(len < 0)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "kcp can not receive udp packet when do receive. len:" << len << remote;
#endif
            MasterKcpBase<Link>::close(true);
            return;
        }
        if (this->link->filter(data, &len, &remote)) {
            continue;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "got invalid kcp packet smaller than 5 bytes." << QByteArray(data, len);
#endif
            continue;
        }

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(data + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar *>(data + 1));
#endif
        if (connectionId == 0) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "the kcp server side returns an invalid packet with zero connection id.";
#endif
            continue;
        }

        if (this->connectionId == 0) {
            this->connectionId = connectionId;
        } else if (connectionId != this->connectionId) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "the kcp server side returns an invalid packet with mismatched connection id.";
#endif
            continue;
        }

        qToBigEndian<quint32>(0, reinterpret_cast<uchar *>(data + 1));
        if (!this->handleDatagram(data, static_cast<quint32>(len), remote)) {
            return;
        }
    }
}

template<typename Link>
void MasterKcpBase<Link>::doAccept()
{
    LinkPathID remote;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    char *data = buf.data();
    while (true) {
        qint32 len = this->link->recvfrom(data, buf.size(), remote);
        if (Q_UNLIKELY(len < 0)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "kcp can not receive udp packet when do accept.";
#endif
            MasterKcpBase<Link>::close(true);
            return;
        }
        if (Q_UNLIKELY(remote.isNull())) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "remote is not valid";
#endif
            continue;
        }
        if (this->link->filter(data, &len, &remote)) {
            continue;
        }
        if (len < 5) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "got invalid kcp packet smaller than 5 bytes.";
#endif
            continue;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 connectionId = qFromBigEndian<quint32>(data + 1);
        qToBigEndian<quint32>(0, data + 1);
#else
        quint32 connectionId = qFromBigEndian<quint32>(reinterpret_cast<uchar *>(data + 1));
        qToBigEndian<quint32>(0, reinterpret_cast<uchar *>(data + 1));
#endif
        bool add = false;
        QWeakPointer<SlaveKcpBase<Link>> receiverPtr = doAccept(connectionId, remote, add);
        if (!receiverPtr) {
            if (!add) {
                continue;
            }
            QSharedPointer<SlaveKcpBase<Link>> slave(
                    new SlaveKcpBase<Link>(this, remote, this->mode));
            if (this->kcp->logmask > 0) {
                slave->setDebugLevel(1);
            }
            slave->connectionId = nextConnectionId();
            if (!slave->handleDatagram(data, static_cast<quint32>(len), remote)) {
                continue;
            }
#ifdef DEBUG_PROTOCOL
            qtng_debug << "new connection coming. connectionId:" << slave->connectionId << remote;
#endif
            if (!link->addSlave(remote, slave->connectionId)) {
                continue;
            }

            receiversByLinkPathID.insert(remote, slave);
            receiversByConnectionId.insert(slave->connectionId, slave);
            pendingSlaves.put(slave);
            continue;
        }
        QSharedPointer<SlaveKcpBase<Link>> receiver = receiverPtr.toStrongRef();
        if (!receiver->handleDatagram(data, len, remote)) {
            receiver->abort();
            continue;
        }
    }
}

template<typename Link>
QWeakPointer<SlaveKcpBase<Link>> MasterKcpBase<Link>::doAccept(quint32 connectionId,
                                                                                   const LinkPathID &remote, bool &add)
{
    QWeakPointer<SlaveKcpBase<Link>> receiverPtr;
    if (connectionId != 0) {  // a multipath packet.
        receiverPtr = receiversByConnectionId.value(connectionId);
        if (!receiverPtr.isNull()) {
            QSharedPointer<SlaveKcpBase<Link>> receiver = receiverPtr.toStrongRef();
            if (connectionId != receiver->connectionId) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "kcp client:" << remote << "sent a invalid connection id ";
#endif
                return QWeakPointer<SlaveKcpBase<Link>>();
            }
            return receiver;
        }
        receiverPtr = receiversByLinkPathID.value(remote);
        if (!receiverPtr.isNull()) {
            QSharedPointer<SlaveKcpBase<Link>> receiver = receiverPtr.toStrongRef();
            if (receiver->connectionId == 0) {
                // only if the slave was created by accept(host, port), we had zero id.
                // if this connectionId is unique in client. we add it to the receiversByConnectionId map.
                // if it is not, say sorry, and disable the multipath feature.
                // only happened in the newly accept(host, port) connections.
                // or remote create new conn with the same port as old, and the old packet is received.
                receiver->connectionId = connectionId;
                receiversByConnectionId.insert(connectionId, receiver);
                return receiver;
            }
        }

        // it must be bad packet.
        const QByteArray &closePacket = KcpBase<Link>::makeShutdownPacket(connectionId);
        if (this->link->sendto(closePacket.data(), closePacket.size(), remote) != closePacket.size()) {
            if (this->error == Socket::NoError) {
                this->error = Socket::SocketResourceError;
                this->errorString = QString::fromLatin1("kcp can not send udp packet.");
            }
#ifdef DEBUG_PROTOCOL
            qtng_debug << this->errorString;
#endif
            MasterKcpBase<Link>::close(true);
        }
#ifdef DEBUG_PROTOCOL
        qtng_debug << "bad packet" << remote << "connectionId:" << connectionId;
#endif
        return QWeakPointer<SlaveKcpBase<Link>>();
    }
    // at beginning, all connectionId is zero
    receiverPtr = receiversByLinkPathID.value(remote);
    if (!receiverPtr.isNull()) {
        return receiverPtr;
    }
    if (pendingSlaves.size() >= pendingSlaves.capacity()) {
        return QWeakPointer<SlaveKcpBase<Link>>();
    }
    // not full. process new connection.
    add = true;
    return QWeakPointer<SlaveKcpBase<Link>>();
}

template<typename Link>
bool MasterKcpBase<Link>::startReceivingCoroutine()
{
    if (!this->operations->get(QString::fromLatin1("receiving")).isNull()) {
        return true;
    }
    switch (this->state) {
    case Socket::UnconnectedState:
    case Socket::BoundState:
    case Socket::ConnectingState:
    case Socket::HostLookupState:
    case Socket::ClosingState:
        return false;
    case Socket::ConnectedState:
        this->operations->spawnWithName(QString::fromLatin1("receiving"), [this] { doReceive(); });
        break;
    case Socket::ListeningState:
        this->operations->spawnWithName(QString::fromLatin1("receiving"), [this] { doAccept(); });
        break;
    }
    return true;
}

template<typename Link>
SlaveKcpBase<Link>::SlaveKcpBase(MasterKcpBase<Link> *parent, const LinkPathID &remote,
                                             KcpMode mode)
    : KcpBase<Link>(mode)
    , originalPathID(remote)
    , parent(parent)
{
    this->remoteId = remote;
    this->state = Socket::ConnectedState;
}

template<typename Link>
SlaveKcpBase<Link>::~SlaveKcpBase()
{
    SlaveKcpBase<Link>::close(true);
}

template<typename Link>
bool SlaveKcpBase<Link>::isValid() const
{
    return this->state == Socket::ConnectedState && !parent.isNull();
}

template<typename Link>
bool SlaveKcpBase<Link>::close(bool force)
{
    // if `force` is true, must not block. it is called by doUpdate()
    if (this->state == Socket::UnconnectedState) {
        return true;
    }
    if (this->state == Socket::ConnectedState) {
        this->state = Socket::UnconnectedState;
        if (!force && this->error != Socket::NoError) {
            if (!this->sendingQueueEmpty.isSet()) {
                this->updateKcp();
                if (!this->sendingQueueEmpty.tryWait()) {
                    return false;
                }
            }
            const QByteArray &packet = KcpBase<Link>::makeShutdownPacket(this->connectionId);
            sendRaw(packet.constData(), packet.size());
        }
    } else {  // there can be no other states.
        this->state = Socket::UnconnectedState;
    }
    this->operations->killall();
    if (!parent.isNull()) {
        parent->receiversByLinkPathID.remove(originalPathID);
        parent->receiversByConnectionId.remove(this->connectionId);
        if (force) {
            parent->link->abortSlave(originalPathID);
        } else {
            parent->link->closeSlave(originalPathID);
        }
        parent.clear();
    }

    // await all pending recv()/send()
    this->receivingQueueNotEmpty.set();
    this->sendingQueueEmpty.set();
    this->sendingQueueNotFull.set();
#ifdef DEBUG_PROTOCOL
    qtng_debug << "slave kcp closed. connetionId:" << this->connectionId;
#endif
    return true;
}

template<typename Link>
bool SlaveKcpBase<Link>::listen(int)
{
    return false;
}

template<typename Link>
QSharedPointer<KcpBase<Link>> SlaveKcpBase<Link>::accept()
{
    return nullptr;
}

template<typename Link>
QSharedPointer<KcpBase<Link>> SlaveKcpBase<Link>::accept(const LinkPathID &)
{
    return nullptr;
}

template<typename Link>
qint32 SlaveKcpBase<Link>::peekRaw(char *data, qint32 size)
{
    if (parent.isNull()) {
        return -1;
    }
    return this->peek(data, size);
}

template<typename Link>
qint32 SlaveKcpBase<Link>::sendRaw(const char *data, qint32 size)
{
    if (parent.isNull()) {
        return -1;
    }
    this->lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    return parent->link->sendto(data, size, this->remoteId);
}

template<typename Link>
qint32 SlaveKcpBase<Link>::udpSend(const char *data, qint32 size, const LinkPathID &remote)
{
    if (parent.isNull()) {
        return -1;
    }
    return parent->link->sendto(data, size, remote);
}

template<typename Link>
void SlaveKcpBase<Link>::doUpdate()
{
    if (parent.isNull()) {
        return;
    }
    // sent first packet to let peer known its connection id
    const QByteArray &multiPathPacket = KcpBase<Link>::makeMultiPathPacket(this->connectionId);
    if (parent->link->sendto(multiPathPacket.data(), multiPathPacket.size(), this->remoteId) != multiPathPacket.size()) {
        if (this->error == Socket::NoError) {
            this->error = Socket::SocketResourceError;
            this->errorString = QString::fromLatin1("kcp can not send udp packet.");
        }
#ifdef DEBUG_PROTOCOL
        qtng_debug << this->errorString;
#endif
        SlaveKcpBase<Link>::close(true);
        return;
    }
    KcpBase<Link>::doUpdate();
}

template<typename Link>
bool SlaveKcpBase<Link>::canBind()
{
    return false;
}

template<typename Link>
bool SlaveKcpBase<Link>::canConnect()
{
    return false;
}

template<typename Link>
class KcpBaseSocketLike : public SocketLike
{
protected:
    explicit KcpBaseSocketLike(QSharedPointer<KcpBase<Link>> kcpBase);
public:
    ~KcpBaseSocketLike();
public:
    virtual HostAddress localAddress() const override { return HostAddress(); }
    virtual quint16 localPort() const override { return 0; }
    virtual HostAddress peerAddress() const override { return HostAddress(); }
    virtual QString peerName() const override { return QString(); }
    virtual quint16 peerPort() const override { return 0; }
    virtual qintptr fileno() const override { return -1; }
    virtual Socket::SocketType type() const override { return Socket::KcpSocket; }

    virtual HostAddress::NetworkLayerProtocol protocol() const override
    {
        return HostAddress::UnknownNetworkLayerProtocol;
    }
    virtual QString localAddressURI() const override { return QString(); }
    virtual QString peerAddressURI() const override { return QString(); }

    virtual QSharedPointer<SocketLike> accept() override { return QSharedPointer<SocketLike>(); }
    virtual Socket *acceptRaw() override { return nullptr; }
    virtual bool bind(const HostAddress &address, quint16 port = 0,
                      Socket::BindMode mode = Socket::DefaultForPlatform) override
    {
        return false;
    }
    virtual bool bind(quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform) override { return false; }
    virtual bool connect(const HostAddress &addr, quint16 port) override { return false; }
    virtual bool connect(const QString &hostName, quint16 port,
                         QSharedPointer<SocketDnsCache> dnsCache = QSharedPointer<SocketDnsCache>()) override
    {
        return false;
    }
    
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override { return false; }
    virtual QVariant option(Socket::SocketOption option) const override { return QVariant(); }

    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual void abort() override;
    virtual void close() override;
    virtual Socket::SocketState state() const override;
    virtual bool listen(int backlog) override;

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
    QSharedPointer<KcpBase<Link>> kcpBase;
};

template<typename Link>
KcpBaseSocketLike<Link>::KcpBaseSocketLike(QSharedPointer<KcpBase<Link>> kcpBase)
    : kcpBase(kcpBase)
{
}

template<typename Link>
KcpBaseSocketLike<Link>::~KcpBaseSocketLike()
{
}

template<typename Link>
Socket::SocketError KcpBaseSocketLike<Link>::error() const
{
    return kcpBase->error;
}

template<typename Link>
QString KcpBaseSocketLike<Link>::errorString() const
{
    return kcpBase->errorString;
}

template<typename Link>
bool KcpBaseSocketLike<Link>::isValid() const
{
    return kcpBase->isValid();
}

template<typename Link>
void KcpBaseSocketLike<Link>::abort()
{
    kcpBase->abort();
}

template<typename Link>
void KcpBaseSocketLike<Link>::close()
{
    kcpBase->close();
}

template<typename Link>
Socket::SocketState KcpBaseSocketLike<Link>::state() const
{
    return kcpBase->state;
}

template<typename Link>
inline bool KcpBaseSocketLike<Link>::listen(int backlog)
{
    return kcpBase->listen(backlog);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::peek(char *data, qint32 size)
{
    return kcpBase->peek(data, size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::peekRaw(char *data, qint32 size)
{
    return kcpBase->peekRaw(data, size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::recv(char *data, qint32 size)
{
    return kcpBase->recv(data, size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::recvall(char *data, qint32 size)
{
    return kcpBase->recvall(data, size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::send(const char *data, qint32 size)
{
    return kcpBase->send(data, size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::sendall(const char *data, qint32 size)
{
    return kcpBase->sendall(data, size);
}

template<typename Link>
QByteArray KcpBaseSocketLike<Link>::recv(qint32 size)
{
    return kcpBase->recv(size);
}

template<typename Link>
QByteArray KcpBaseSocketLike<Link>::recvall(qint32 size)
{
    return kcpBase->recvall(size);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::send(const QByteArray &data)
{
    return kcpBase->send(data);
}

template<typename Link>
qint32 KcpBaseSocketLike<Link>::sendall(const QByteArray &data)
{
    return kcpBase->sendall(data);
}

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_KCP_BASE_P_H
