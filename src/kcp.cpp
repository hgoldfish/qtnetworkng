#include <QtCore/qdatetime.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qendian.h>
#include "../include/kcp.h"
#include "../include/socket_utils.h"
#include "../include/coroutine_utils.h"
#include "./kcp/ikcp.h"
QTNETWORKNG_NAMESPACE_BEGIN

const char PACKET_TYPE_UNCOMPRESSED_DATA = 0x01;
const char PACKET_TYPE_COMPRESSED_DATA = 0x02;
const char PACKET_TYPE_CLOSE= 0X03;
const char PACKET_TYPE_KEEPALIVE = 0x04;


class SlaveKcpSocketPrivate;
class KcpSocketPrivate: public QObject
{
public:
    KcpSocketPrivate(KcpSocket *q);
    virtual ~KcpSocketPrivate() override;
    static KcpSocket *create(KcpSocketPrivate *d, const QHostAddress &addr, quint16 port, KcpSocket::Mode mode) { return new KcpSocket(d, addr, port, mode); }
    static SlaveKcpSocketPrivate *getPrivateHelper(QSharedPointer<KcpSocket> s);
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
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) = 0;
    virtual bool bind(quint16 port, Socket::BindMode mode) = 0;
    virtual bool connect(const QHostAddress &addr, quint16 port) = 0;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) = 0;
    virtual bool close(bool force) = 0;
    virtual bool listen(int backlog) = 0;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) = 0;
    virtual QVariant option(Socket::SocketOption option) const = 0;
public:
    void setMode(KcpSocket::Mode mode);
    qint32 send(const char *data, qint32 size, bool all);
    qint32 recv(char *data, qint32 size, bool all);
    bool handleDatagram(const QByteArray &buf);
    void updateKcp();
    void doUpdate();
    virtual qint32 rawSend(const char *data, qint32 size) = 0;

    QByteArray makeDataPacket(const char *data, qint32 size);
    QByteArray makeShutdownPacket();
    QByteArray makeKeepalivePacket();
protected:
    KcpSocket * const q_ptr;
    Q_DECLARE_PUBLIC(KcpSocket)
public:
    CoroutineGroup *operations;
    QString errorString;
    Socket::SocketState state;
    Socket::SocketError error;

    QSharedPointer<Event> sendingQueueNotFull;
    QSharedPointer<Event> sendingQueueEmpty;
    QSharedPointer<Event> receivingQueueNotEmpty;
    Gate forceToUpdate;
    QByteArray receivingBuffer;

    const quint64 zeroTimestamp;
    quint64 lastActiveTimestamp;
    quint64 lastKeepaliveTimestamp;
    quint64 tearDownTime;
    ikcpcb *kcp;
    quint32 waterLine;

    QHostAddress remoteAddress;
    quint16 remotePort;

    KcpSocket::Mode mode;
    bool compression;
};


static inline QString concat(const QHostAddress &addr, quint16 port)
{
    return addr.toString() + QString::number(port);
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
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    virtual qint32 rawSend(const char *data, qint32 size) override;
public:
    void removeSlave(const QHostAddress &addr, quint16 port) { receivers.remove(concat(addr, port)); }
    void doReceive();
    void doAccept();
    bool startReceivingCoroutine();
public:
    QMap<QString, QPointer<class SlaveKcpSocketPrivate>> receivers;
    QSharedPointer<Socket> rawSocket;
    Queue<QSharedPointer<KcpSocket>> pendingSlaves;
};


class SlaveKcpSocketPrivate: public KcpSocketPrivate
{
public:
    SlaveKcpSocketPrivate(MasterKcpSocketPrivate *parent, const QHostAddress &addr, quint16 port, KcpSocket *q);
    virtual ~SlaveKcpSocketPrivate() override;
public:
    virtual Socket::SocketError getError() const override;
    virtual QString getErrorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;
public:
    virtual QSharedPointer<KcpSocket> accept() override;
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) override;
    virtual bool close(bool force) override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    virtual qint32 rawSend(const char *data, qint32 size) override;
public:
    QPointer<MasterKcpSocketPrivate> parent;
};


SlaveKcpSocketPrivate *KcpSocketPrivate::getPrivateHelper(QSharedPointer<KcpSocket> s)
{
    return static_cast<SlaveKcpSocketPrivate*>(s->d_ptr);
}


int kcp_callback(const char *buf, int len, ikcpcb *, void *user)
{
    KcpSocketPrivate *p = static_cast<KcpSocketPrivate*>(user);
    const QByteArray &packet = p->makeDataPacket(buf, len);
    qint32 sentBytes = -1;
    for (int i = 0; i < 1; ++i) {
        sentBytes = p->rawSend(packet.data(), packet.size());
        if (sentBytes != packet.size()) {
            p->close(true);
        }
    }
    return sentBytes;
}


KcpSocketPrivate::KcpSocketPrivate(KcpSocket *q)
    : q_ptr(q), operations(new CoroutineGroup), state(Socket::UnconnectedState), error(Socket::NoError)
    , sendingQueueNotFull(new Event()), sendingQueueEmpty(new Event()), receivingQueueNotEmpty(new Event())
    , zeroTimestamp(static_cast<quint64>(QDateTime::currentMSecsSinceEpoch())), lastActiveTimestamp(zeroTimestamp)
    , lastKeepaliveTimestamp(zeroTimestamp),tearDownTime(1000 * 30), waterLine(1024 * 16), remotePort(0)
    , mode(KcpSocket::Internet), compression(false)
{
    kcp = ikcp_create(0, this);
    ikcp_setoutput(kcp, kcp_callback);
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
    receivingQueueNotEmpty->clear();
    q->busy.clear();
    q->notBusy.set();
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
        ikcp_nodelay(kcp, 0, 30, 3, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 2048, 2048);
        break;
    case KcpSocket::FastInternet:
        ikcp_nodelay(kcp, 0, 20, 2, 1);
        ikcp_setmtu(kcp, 1400);
        ikcp_wndsize(kcp, 1024, 1024);
        break;
    case KcpSocket::Ethernet:
        ikcp_nodelay(kcp, 1, 10, 2, 1);
        ikcp_setmtu(kcp, 16384);
        ikcp_wndsize(kcp, 64, 64);
        break;
    case KcpSocket::Loopback:
        ikcp_nodelay(kcp, 1, 5, 1, 0);
        ikcp_setmtu(kcp, 32768);
        ikcp_wndsize(kcp, 32, 32);
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
            return -1;
        }
        qint32 nextBlockSize = qMin<qint32>(static_cast<qint32>(kcp->mss), size - count);
        int result = ikcp_send(kcp, data + count, nextBlockSize);
        if (result < 0) {
            qWarning() << "why this happended?";
            updateKcp();
            return count;
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
            return -1;
        }
        int peeksize = ikcp_peeksize(kcp);
        if (peeksize > 0) {
            QByteArray buf(peeksize, Qt::Uninitialized);
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


bool KcpSocketPrivate::handleDatagram(const QByteArray &buf)
{
    if (buf.isEmpty()) {
        return true;
    }
    int dataSize;
    switch(buf.at(0)) {
    case PACKET_TYPE_COMPRESSED_DATA:
    case PACKET_TYPE_UNCOMPRESSED_DATA:
        if (buf.size() < 3) {
            qDebug() << "invalid packet. buf.size() < 3";
            return true;
        }
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
        dataSize = qFromBigEndian<quint16>(buf.constData() + 1);
#else
        dataSize = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(buf.constData() + 1));
#endif
        if (dataSize != buf.size() - 3) {
            qDebug() << "invalid packet. dataSize != buf.size() - 3";
            return true;
        }

        int result;
        if (buf.at(0) == PACKET_TYPE_UNCOMPRESSED_DATA) {
            result = ikcp_input(kcp, buf.data() + 3, dataSize);
        } else {
            const QByteArray &uncompressed = qUncompress(reinterpret_cast<const uchar*>(buf.data() + 3), dataSize);
            result = ikcp_input(kcp, uncompressed.constData(), uncompressed.size());
        }
        if (result < 0) {
            // invalid datagram
            qDebug() << "invalid datagram. kcp returns" << result;
        } else {
            lastActiveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
            receivingQueueNotEmpty->set();
            updateKcp();
        }
        break;
    case PACKET_TYPE_CLOSE:
        close(true);
        break;
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
    Q_Q(KcpSocket);
    while (true) {
        quint64 now = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
        if (now - lastActiveTimestamp > tearDownTime) {
            close(true);
            return;
        }
        quint32 current = static_cast<quint32>(now - zeroTimestamp);  // impossible to overflow.
        ikcp_update(kcp, current);
        quint32 ts = ikcp_check(kcp, current);
        quint32 interval = ts - current;

        if (now - lastKeepaliveTimestamp > 1000 * 5) {
            const QByteArray &packet = makeKeepalivePacket();
            if (rawSend(packet.data(), packet.size()) != packet.size()) {
                close(true);
                return;
            }
        }

        int sendingQueueSize = ikcp_waitsnd(kcp);
        if (sendingQueueSize <= 0) {
            sendingQueueNotFull->set();
            sendingQueueEmpty->set();
            q->busy.clear();
            q->notBusy.set();
        } else {
            sendingQueueEmpty->clear();
            if (static_cast<quint32>(sendingQueueSize) > waterLine) {
                if (static_cast<quint32>(sendingQueueSize) > (waterLine * 1.2)) {
                    sendingQueueNotFull->clear();
                }
                q->busy.set();
                q->notBusy.clear();
            } else {
                sendingQueueNotFull->set();
                q->busy.clear();
                q->notBusy.set();
            }
        }


        forceToUpdate.close();
        try {
            Timeout timeout(interval, 0); Q_UNUSED(timeout);
            bool ok = forceToUpdate.wait();
            if (!ok) {
                return;
            }
        } catch (TimeoutException &) {
            // continue
        }
    }
}


void KcpSocketPrivate::updateKcp()
{
    QSharedPointer<Coroutine> t = operations->spawnWithName("update_kcp", [this] { doUpdate(); }, false);
    forceToUpdate.open();
}


QByteArray KcpSocketPrivate::makeDataPacket(const char *data, qint32 size)
{
    QByteArray packet;

    if (compression) {
        QByteArray compressed = qCompress(reinterpret_cast<const uchar*>(data), size);
        if (compressed.size() < size) {
            packet.reserve(3 + compressed.size());
            packet.append(PACKET_TYPE_COMPRESSED_DATA);
            packet.append(static_cast<char>((compressed.size() >> 8) & 0xff));
            packet.append(static_cast<char>(compressed.size() & 0xff));
            packet.append(compressed);
            return packet;
        }
    }

    packet.reserve(3 + size);
    packet.append(PACKET_TYPE_UNCOMPRESSED_DATA);
    packet.append(static_cast<char>((size >> 8) & 0xff));
    packet.append(static_cast<char>(size & 0xff));
    packet.append(data, size);
    return packet;
}


QByteArray KcpSocketPrivate::makeShutdownPacket()
{
    QByteArray packet;
    packet.append(PACKET_TYPE_CLOSE);
    return packet;
}


QByteArray KcpSocketPrivate::makeKeepalivePacket()
{
    QByteArray packet;
    packet.append(PACKET_TYPE_KEEPALIVE);
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
    MasterKcpSocketPrivate::close(false);
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
    // if `force` is true, must not block. it is called by doUpdate()
    if (state == Socket::UnconnectedState) {
        return true;
    } else if (state == Socket::ConnectedState) {
        state = Socket::UnconnectedState;
        if (!force) {
            updateKcp();
            bool ok = sendingQueueEmpty->wait();
            if (!ok) {
                return false;
            }
            const QByteArray &packet = makeShutdownPacket();
            rawSend(packet.constData(), packet.size());
        }
    } else if (state == Socket::ListeningState) {
        state = Socket::UnconnectedState;
        for (QPointer<SlaveKcpSocketPrivate> receiver: receivers.values()) {
            if (!receiver.isNull()) {
                receiver->close(force);
            }
        }
        receivers.clear();
    } else {  // BoundState
        state = Socket::UnconnectedState;
        rawSocket->close();
        return true;
    }

    rawSocket->close();

    //connected and listen state would do more cleaning work.
    operations->kill("update_kcp");
    operations->kill("receiving");
    // await all pending recv()/send()
    receivingQueueNotEmpty->set();
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
//    q_func()->notBusy->set();
//    q_func()->busy->set();
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


void MasterKcpSocketPrivate::doReceive()
{
    QHostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
            MasterKcpSocketPrivate::close(true);
            return;
        }
//        if (Q_UNLIKELY(addr.toIPv6Address() != remoteAddress.toIPv6Address() || port != remotePort)) {
//            // not my packet.
//            qDebug() << "not my packet:" << addr << remoteAddress << port;
//            continue;
//        }
        if (!handleDatagram(QByteArray(buf.constData(), len))) {
            MasterKcpSocketPrivate::close(true);
            return;
        }
    }
}


void MasterKcpSocketPrivate::doAccept()
{
    QHostAddress addr;
    quint16 port;
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    while (true) {
        qint32 len = rawSocket->recvfrom(buf.data(), buf.size(), &addr, &port);
        if (Q_UNLIKELY(len < 0 || addr.isNull() || port == 0)) {
            MasterKcpSocketPrivate::close(true);
            return;
        }
        const QString &key = concat(addr, port);
        if (receivers.contains(key)) {
            QPointer<SlaveKcpSocketPrivate> receiver = receivers.value(key);
            if (!receiver.isNull()) {
                if (!receiver->handleDatagram(QByteArray(buf.constData(), len))) {
                    receivers.remove(key);
                }
            }
        } else {
            if (pendingSlaves.size() < pendingSlaves.capacity()) {  // not full.
                QSharedPointer<KcpSocket> slave(KcpSocketPrivate::create(this, addr, port, this->mode));
                SlaveKcpSocketPrivate *d = KcpSocketPrivate::getPrivateHelper(slave);
                if (d->handleDatagram(QByteArray(buf.constData(), len))) {
                    receivers.insert(key, d);
                    pendingSlaves.put(slave);
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


bool MasterKcpSocketPrivate::connect(const QHostAddress &addr, quint16 port)
{
    if (state != Socket::UnconnectedState && state != Socket::BoundState) {
        return false;
    }
    remoteAddress = addr;
    remotePort = port;
    state = Socket::ConnectedState;
    return true;
}


bool MasterKcpSocketPrivate::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    if (state != Socket::UnconnectedState && state != Socket::BoundState) {
        return false;
    }
    if (rawSocket->connect(hostName, port, protocol))  {
        remoteAddress = rawSocket->peerAddress();
        remotePort = port;
        state = Socket::ConnectedState;
        return true;
    } else {
        return false;
    }
}


qint32 MasterKcpSocketPrivate::rawSend(const char *data, qint32 size)
{
    lastKeepaliveTimestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    startReceivingCoroutine();
    qint32 len = rawSocket->sendto(data, size, remoteAddress, remotePort);
    return len;
}


bool MasterKcpSocketPrivate::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
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
    SlaveKcpSocketPrivate::close(false);
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
        if (!force) {
            updateKcp();
            bool ok = sendingQueueEmpty->wait();
            if (!ok) {
                return false;
            }
            const QByteArray &packet = makeShutdownPacket();
            rawSend(packet.constData(), packet.size());
        }
    } else {  // there can be no other states.
        state = Socket::UnconnectedState;
    }
    operations->kill("update_kcp");
    if (!parent.isNull()) {
        parent->removeSlave(remoteAddress, remotePort);
        parent.clear();
    }
    // await all pending recv()/send()
    receivingQueueNotEmpty->set();
    sendingQueueEmpty->set();
    sendingQueueNotFull->set();
//    q_func()->notBusy.set();
//    q_func()->busy.set();
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


bool SlaveKcpSocketPrivate::connect(const QHostAddress &, quint16)
{
    return false;
}


bool SlaveKcpSocketPrivate::connect(const QString &, quint16 , Socket::NetworkLayerProtocol)
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

bool SlaveKcpSocketPrivate::bind(QHostAddress &, quint16, Socket::BindMode)
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


void KcpSocket::setCompression(bool compression)
{
    Q_D(KcpSocket);
    d->compression = compression;
}


bool KcpSocket::compression() const
{
    Q_D(const KcpSocket);
    return d->compression;
}


void KcpSocket::setWaterline(quint32 waterline)
{
    Q_D(KcpSocket);
    d->waterLine = waterline;
}


quint32 KcpSocket::waterline() const
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


bool KcpSocket::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
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


bool KcpSocket::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    Q_D(KcpSocket);
    return d->connect(hostName, port, protocol);
}


bool KcpSocket::close()
{
    Q_D(KcpSocket);
    return d->close(false);
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
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) override;
    virtual bool close() override;
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
    return SocketLike::kcpSocket(s->accept());
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port = 0, Socket::BindMode mode = Socket::DefaultForPlatform)
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

bool SocketLikeImpl::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    return s->connect(hostName, port, protocol);
}

bool SocketLikeImpl::close()
{
    return s->close();
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

QSharedPointer<SocketLike> SocketLike::kcpSocket(QSharedPointer<KcpSocket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}

QSharedPointer<SocketLike> SocketLike::kcpSocket(KcpSocket *s)
{
    return QSharedPointer<SocketLikeImpl>::create(QSharedPointer<KcpSocket>(s)).dynamicCast<SocketLike>();
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

