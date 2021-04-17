#include <QtCore/qmap.h>
#include <QtCore/qpointer.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qendian.h>
#include <QtCore/qdatetime.h>
#include "../include/locks.h"
#include "../include/coroutine_utils.h"
#include "../include/data_channel.h"
#include "../include/kcp.h"
#ifndef QTNG_NO_CRYPTO
#include "../include/ssl.h"
#endif

//#define DEBUG_PROTOCOL

QTNETWORKNG_NAMESPACE_BEGIN

const quint8 MAKE_CHANNEL_REQUEST = 1;
const quint8 CHANNEL_MADE_REQUEST = 2;
const quint8 DESTROY_CHANNEL_REQUEST = 3;
const quint8 SLOW_DOWN_REQUEST = 4;
const quint8 GO_THROUGH_REQUEST = 5;
const quint8 KEEPALIVE_REQUEST = 6;


static QByteArray packMakeChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(MAKE_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static QByteArray packChannelMadeRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(CHANNEL_MADE_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static QByteArray packDestoryChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(DESTROY_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static QByteArray packSlowDownRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(SLOW_DOWN_REQUEST, buf);
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static QByteArray packGoThroughRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(GO_THROUGH_REQUEST, buf);
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static QByteArray packKeepaliveRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(KEEPALIVE_REQUEST, buf);
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}


static bool unpackCommand(QByteArray data, quint8 *command, quint32 *channelNumber)
{
    if (data.size() == (sizeof(quint8) + sizeof(quint32))) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(data.constData());
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<const uchar*>(data.constData()));
#endif
        if (*command != MAKE_CHANNEL_REQUEST && *command != CHANNEL_MADE_REQUEST && *command != DESTROY_CHANNEL_REQUEST) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *channelNumber = qFromBigEndian<quint32>(data.constData() + sizeof(quint8));
#else
        *channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(data.constData()) + sizeof(quint8));
#endif
        return true;
    } else if(data.size() == sizeof(quint8)) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(data.constData());
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<const uchar*>(data.constData()));
#endif
        if (*command != GO_THROUGH_REQUEST && *command != SLOW_DOWN_REQUEST && *command != KEEPALIVE_REQUEST) {
            return false;
        }
        return true;
    } else {
        return false;
    }
}


class DataChannelPrivate
{
public:
    DataChannelPrivate(DataChannelPole pole, DataChannel *parent);
    virtual ~DataChannelPrivate();

    // called by the public class DataChannel
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> takeChannel();
    QSharedPointer<VirtualChannel> takeChannel(quint32 channelNumber);
    bool removeChannel(VirtualChannel *channel);
    QByteArray recvPacket();
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet);
    QString toString();

    // must be implemented by subclasses
    virtual void abort();
    virtual bool isBroken() const = 0;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) = 0;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) = 0;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) = 0;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) = 0;
    virtual quint32 headerSize() const = 0;
    virtual QSharedPointer<SocketLike> getBackend() const = 0;

    // called by the subclasses.
    bool handleCommand(const QByteArray &packet);
    bool handleRawPacket(const QByteArray &packet);
    void notifyChannelClose(quint32 channelNumber);
    QByteArray packPacket(quint32 channelNumber, const QByteArray &packet);

    QString name;
    DataChannelPole pole;
    quint32 nextChannelNumber;
    quint32 maxPacketSize;
    quint32 payloadSizeHint;
    Queue<QSharedPointer<VirtualChannel>> pendingChannels;
    QMap<quint32, QWeakPointer<VirtualChannel>> subChannels;
    Queue<QByteArray> receivingQueue;
    Gate goThrough;

    Q_DECLARE_PUBLIC(DataChannel)
    DataChannel * const q_ptr;
    bool broken;

    inline static DataChannelPrivate *getPrivateHelper(QPointer<DataChannel> channel) { return channel.data()->d_func(); }
    inline static DataChannelPrivate *getPrivateHelper(QSharedPointer<DataChannel> channel) { return channel.data()->d_func(); }
};


class WritingPacket
{
public:
    WritingPacket()
        :channelNumber(0) {}
    WritingPacket(quint32 channelNumber, const QByteArray &packet, QSharedPointer<ValueEvent<bool>> done)
        :packet(packet), done(done), channelNumber(channelNumber) {}

    QByteArray packet;
    QSharedPointer<ValueEvent<bool>> done;
    quint32 channelNumber;
    bool isValid()
    {
        return !(channelNumber == 0 && packet.isNull() && done.isNull());
    }
};


class SocketChannelPrivate: public DataChannelPrivate
{
public:
    SocketChannelPrivate(QSharedPointer<SocketLike> connection, DataChannelPole pole, SocketChannel *parent);
    virtual ~SocketChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void abort() override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) override;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;
    virtual quint32 headerSize() const override;
    virtual QSharedPointer<SocketLike> getBackend() const override;
    void doSend();
    void doReceive();
    void doKeepalive();
    HostAddress getPeerAddress();

    const QSharedPointer<SocketLike> connection;
    Queue<WritingPacket> sendingQueue;
    CoroutineGroup *operations;
    qint64 lastActiveTimestamp;
    qint64 lastKeepaliveTimestamp;
    qint64 keepaliveTimeout;
    qint64 keepaliveInterval;

    Q_DECLARE_PUBLIC(SocketChannel)
};


class VirtualChannelPrivate: public DataChannelPrivate
{
public:
    VirtualChannelPrivate(DataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent);
    virtual ~VirtualChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void abort() override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) override;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;
    virtual quint32 headerSize() const override;
    virtual QSharedPointer<SocketLike> getBackend() const override;

    bool handleIncomingPacket(const QByteArray &packet);

    QPointer<DataChannel> parentChannel;
    quint32 channelNumber;

    Q_DECLARE_PUBLIC(VirtualChannel)
};


DataChannelPrivate::DataChannelPrivate(DataChannelPole pole, DataChannel *parent)
    : pole(pole)
    , maxPacketSize(1024 * 64), payloadSizeHint(1400)
    , receivingQueue(1024)  // may consume 1024 * 1024 * 64 bytes.
    , q_ptr(parent)
    , broken(false)
{
    if (pole == DataChannelPole::NegativePole) {
        nextChannelNumber = 0xffffffff;
    } else {
        nextChannelNumber = 2;
    }
}


DataChannelPrivate::~DataChannelPrivate()
{
    // do not uncomment these lines of code
    // these codes lead to bug.
//    for (int i = 0; i < receivingQueue.getting(); ++i) {
//        receivingQueue.put(QByteArray());
//    }
}


QString DataChannelPrivate::toString()
{
    QString pattern = QStringLiteral("<%1 (name = %2, state = %3)>");
    QString clazz, state;
    if (dynamic_cast<VirtualChannel*>(this)) {
        clazz = QStringLiteral("VirtualChannel");
    } else {
        clazz = QStringLiteral("SocketChannel");
    }
    if (broken) {
        state = QStringLiteral("closed");
    } else {
        state = QStringLiteral("ok");
    }
    return pattern.arg(clazz).arg(name).arg(state);
}


void DataChannelPrivate::abort()
{
    Q_ASSERT(broken); // must be called by subclasses's close method.
    // FIXME if close() is called by doReceive(), may cause the queue reports deleting not empty.
    for (quint32 i = 0; i < receivingQueue.getting(); ++i) {
        receivingQueue.put(QByteArray());
    }
    for (quint32 i = 0;i < pendingChannels.getting(); ++i) {
        pendingChannels.put(QSharedPointer<VirtualChannel>());
    }
    goThrough.open();
    for (QMapIterator<quint32, QWeakPointer<VirtualChannel>> itor(subChannels); itor.hasNext();) {
        const QWeakPointer<VirtualChannel> &subChannel = itor.next().value();
        if (!subChannel.isNull()) {
            subChannel.toStrongRef()->d_func()->parentChannel.clear();
            subChannel.toStrongRef()->d_func()->abort();
        }
    }
    subChannels.clear();
}


QSharedPointer<VirtualChannel> DataChannelPrivate::makeChannel()
{
    Q_Q(DataChannel);
    if (isBroken()) {
#ifdef DEBUG_PROTOCOL
        qDebug() << "the data channel is broken, can not make channel.";
#endif
        return QSharedPointer<VirtualChannel>();
    }
    quint32 channelNumber = nextChannelNumber;
    if (pole == NegativePole) {
        --nextChannelNumber;
    } else {
        ++nextChannelNumber;
    }
    sendPacketRawAsync(CommandChannelNumber, packMakeChannelRequest(channelNumber));
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::PositivePole, channelNumber));
    channel->setMaxPacketSize(maxPacketSize - sizeof(quint32));
    channel->setPayloadSizeHint(payloadSizeHint - sizeof(quint32));
    channel->setCapacity(receivingQueue.capacity());
    subChannels.insert(channelNumber, channel);
    return channel;
}


QSharedPointer<VirtualChannel> DataChannelPrivate::takeChannel()
{
    if (isBroken()) {
        return QSharedPointer<VirtualChannel>();
    }
    return pendingChannels.get();
}


QSharedPointer<VirtualChannel> DataChannelPrivate::takeChannel(quint32 channelNumber)
{
    if (isBroken()) {
        return QSharedPointer<VirtualChannel>();
    }
    QList<QSharedPointer<VirtualChannel>> tmp;
    while (!pendingChannels.isEmpty()) {
        QSharedPointer<VirtualChannel> channel = pendingChannels.get();
        if (channel->channelNumber() == channelNumber) {
            for (QSharedPointer<VirtualChannel> t: tmp) {
                pendingChannels.returnsForcely(t);
            }
            return channel;
        } else {
            tmp.prepend(channel);
        }
    }
    return QSharedPointer<VirtualChannel>();
}


QByteArray DataChannelPrivate::recvPacket()
{
    if (receivingQueue.isEmpty() && broken) {
        return QByteArray();
    }
    const QByteArray &packet = receivingQueue.get();
    if (packet.isNull()) {
        return QByteArray();
    }
    if (receivingQueue.size() == (receivingQueue.capacity() / 2)){
        sendPacketRawAsync(CommandChannelNumber, packGoThroughRequest());
    }
    return packet;
}


bool DataChannelPrivate::sendPacket(const QByteArray &packet)
{
    if (static_cast<quint32>(packet.size()) > maxPacketSize) {
        return false;
    }
    if (!goThrough.wait()) {
        return false;
    }
    return sendPacketRaw(DataChannelNumber, packet);
}


bool DataChannelPrivate::sendPacketAsync(const QByteArray &packet)
{
    if (static_cast<quint32>(packet.size()) > maxPacketSize) {
        return false;
    }
    return sendPacketRawAsync(DataChannelNumber, packet);
}


bool DataChannelPrivate::handleCommand(const QByteArray &packet)
{
    Q_Q(DataChannel);
    quint8 command;
    quint32 channelNumber;
    bool isCommand = unpackCommand(packet, &command, &channelNumber);
    if (!isCommand) {
        qWarning() << "invalid command.";
        return false;
    }
    if (command == MAKE_CHANNEL_REQUEST) {
        QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::NegativePole, channelNumber));
        channel->setMaxPacketSize(maxPacketSize - sizeof(quint32));
        channel->setPayloadSizeHint(payloadSizeHint - sizeof(quint32));
        channel->setCapacity(receivingQueue.capacity());
        subChannels.insert(channelNumber, channel);
        sendPacketRawAsync(CommandChannelNumber, packChannelMadeRequest(channelNumber));
        pendingChannels.put(channel);
        return true;
    } else if (command == CHANNEL_MADE_REQUEST) {
        if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (channel.isNull()) {
                subChannels.remove(channelNumber);
            } else {
                return true;
            }
        }
#ifdef DEBUG_PROTOCOL
        qDebug() << "channel is gone." << channelNumber;
#endif
        // the channel is open by me and then closed quickly...
        sendPacketRawAsync(CommandChannelNumber, packDestoryChannelRequest(channelNumber));
        return true;
    } else if (command == DESTROY_CHANNEL_REQUEST) {
        takeChannel(channelNumber); // remove channel from pending channels.
        if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (!channel.isNull()) {
                cleanChannel(channelNumber, false);
                channel.toStrongRef()->d_func()->parentChannel.clear();
                // do not worry, the receiving queue is still ok after aborted.
                channel.toStrongRef()->d_func()->abort();
            }
        }
        return true;
    } else if (command == SLOW_DOWN_REQUEST) {
        goThrough.close();
        return true;
    } else if (command == GO_THROUGH_REQUEST) {
        goThrough.open();
        return true;
    } else if (command == KEEPALIVE_REQUEST) {
        return true;
    } else {
        qWarning() << "unknown command.";
        return false;
    }
}


void DataChannelPrivate::notifyChannelClose(quint32 channelNumber)
{
    if (broken) {
        return;
    }
    sendPacketRawAsync(CommandChannelNumber, packDestoryChannelRequest(channelNumber));
}


SocketChannelPrivate::SocketChannelPrivate(QSharedPointer<SocketLike> connection, DataChannelPole pole, SocketChannel *parent)
    : DataChannelPrivate(pole, parent)
    , connection(connection)
    , sendingQueue(256)
    , operations(new CoroutineGroup())
    , lastActiveTimestamp(QDateTime::currentMSecsSinceEpoch())
    , lastKeepaliveTimestamp(lastActiveTimestamp)
    , keepaliveTimeout(1000 * 10)
    , keepaliveInterval(1000 * 2)
{
    connection->setOption(Socket::LowDelayOption, true);
    connection->setOption(Socket::KeepAliveOption, false); // we do it!
    operations->spawnWithName(QStringLiteral("receiving"), [this] {
        this->doReceive();
    });
    operations->spawnWithName(QStringLiteral("sending"), [this] {
        this->doSend();
    });
    operations->spawnWithName(QStringLiteral("keepalive"), [this] {
        this->doKeepalive();
    });
}


SocketChannelPrivate::~SocketChannelPrivate()
{
    abort();
    delete operations;
}


bool SocketChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet)
{
    if (broken) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done(new ValueEvent<bool>());
    sendingQueue.put(WritingPacket(channelNumber, packet, done));
    bool success = done->wait();
    return success;
}


bool SocketChannelPrivate::sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet)
{
    if (broken) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done;
    sendingQueue.putForcedly(WritingPacket(channelNumber, packet, done));
    return true;
}


void SocketChannelPrivate::doSend()
{
    while (true) {
        WritingPacket writingPacket;
        try {
            writingPacket = sendingQueue.get();
        } catch (CoroutineExitException) {
            return abort();
        } catch (...) {
            return abort();
        }
        if (!writingPacket.isValid()) {
            return abort();
        }
        if (broken) {
            if (!writingPacket.done.isNull()) {
                writingPacket.done->send(false);
            }
            return abort();
        }

        uchar header[sizeof(quint32) + sizeof(quint32)];
        qToBigEndian<quint32>(static_cast<quint32>(writingPacket.packet.size()), header);
        qToBigEndian<quint32>(writingPacket.channelNumber, header + sizeof(quint32));
        QByteArray data;
        data.reserve(static_cast<int>(sizeof(header)) + writingPacket.packet.size());
        data.append(reinterpret_cast<char*>(header), sizeof(header));
        data.append(writingPacket.packet);

        int sentBytes;
        try {
            sentBytes = connection->sendall(data);
        } catch (CoroutineExitException) {
            if (!writingPacket.done.isNull()) {
                writingPacket.done->send(false);
            }
#ifdef DEBUG_PROTOCOL
            qDebug() << "coroutine is killed while sending packet.";
#endif
            return abort();
        } catch(...) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "unhandled exception while sending packet.";
#endif
            return abort();
        }

        if (sentBytes == data.size()) {
            if (!writingPacket.done.isNull()) {
                writingPacket.done->send(true);
            }
            lastKeepaliveTimestamp = QDateTime::currentMSecsSinceEpoch();
        } else {
            if (writingPacket.done.isNull()) {
//                continue; // why do this?
            } else {
                writingPacket.done->send(false);
            }
            return abort();
        }
    }
}


void SocketChannelPrivate::doReceive()
{
    const size_t headerSize = sizeof(quint32) + sizeof(quint32);
    quint32 packetSize;
    quint32 channelNumber;
    QByteArray packet;
    while (true) {
        try {
            QByteArray header = connection->recvall(headerSize);
            if (header.size() != headerSize) {
#ifdef DEBUG_PROTOCOL
                qDebug() << "data channel is disconnected:" << header.size();
#endif
                return abort();
            }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
            packetSize = qFromBigEndian<quint32>(header.data());
            channelNumber = qFromBigEndian<quint32>(header.data() + sizeof(quint32));
#else
            packetSize = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(header.data()));
            channelNumber = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(header.data() + sizeof(quint32)));
#endif
            if (packetSize > maxPacketSize) {
#ifdef DEBUG_PROTOCOL
                qDebug() << QStringLiteral("packetSize %1 is larger than %2").arg(packetSize).arg(maxPacketSize);
#endif
                return abort();
            }
            packet = connection->recvall(static_cast<qint32>(packetSize));
            if (packet.size() != static_cast<int>(packetSize)) {
                qDebug() << "invalid packet does not fit packet size = " << packetSize;
                return abort();
            }
        } catch (CoroutineExitException) {
            return abort();
        } catch (...) {
            return abort();
        }
        if (channelNumber == DataChannelNumber) {
            if (receivingQueue.size() == (receivingQueue.capacity() * 3 / 4)) {
                sendPacketRawAsync(CommandChannelNumber, packSlowDownRequest());
            }
            receivingQueue.putForcedly(packet);
        } else if (channelNumber == CommandChannelNumber) {
            if (!handleCommand(packet)) {
                return abort();
            }
        } else if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (channel.isNull()) {
#ifdef DEBUG_PROTOCOL
                qDebug() << "channel is destroyed and data is abondoned: " << channelNumber;
#endif
                subChannels.remove(channelNumber);
            } else {
                channel.toStrongRef()->d_func()->handleIncomingPacket(packet);
            }
        } else {
#ifdef DEBUG_PROTOCOL
            qDebug() << "channel is destroyed and data is abondoned: " << channelNumber;
#endif
        }
        lastActiveTimestamp = QDateTime::currentMSecsSinceEpoch();
    }
}


void SocketChannelPrivate::doKeepalive()
{
    while (true) {
        Coroutine::sleep(0.2f);
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - lastActiveTimestamp > keepaliveTimeout) {
            return abort();
        }
        if (now - lastKeepaliveTimestamp > keepaliveInterval) {
            lastKeepaliveTimestamp = now;
            sendPacketRawAsync(CommandChannelNumber, packKeepaliveRequest());
        }
    }
}


void SocketChannelPrivate::abort()
{
    if (broken) {
        return;
    }
    broken = true;
    Coroutine *current = Coroutine::current();
    connection->abort();

    while (!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if (!writingPacket.done.isNull()) {
            writingPacket.done->send(false);
        }
    }
    if (operations->get("receiving").data() != current) {
        operations->kill("receiving");
    }
    if (operations->get("sending").data() != current) {
        operations->kill("sending");
    }
    if (operations->get("keepalive").data() != current) {
        operations->kill("keepalive");
    }
    DataChannelPrivate::abort();
}


bool SocketChannelPrivate::isBroken() const
{
    return broken || !connection->isValid();
}


static inline bool alwayTrue(const QByteArray &) {
    return true;
}


void SocketChannelPrivate::cleanChannel(quint32 channelNumber, bool sendDestroyPacket)
{
    int found = subChannels.remove(channelNumber);
    if (found <= 0) {
        return;
    }
    if (sendDestroyPacket) {
        notifyChannelClose(channelNumber);
    }
    cleanSendingPacket(channelNumber, alwayTrue);
}


void SocketChannelPrivate::cleanSendingPacket(quint32 subChannelNumber, std::function<bool (const QByteArray &)> subCheckPacket)
{
    QList<WritingPacket> reserved;
    while (!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if (writingPacket.channelNumber == subChannelNumber && subCheckPacket(writingPacket.packet)) {
            if (!writingPacket.done.isNull()) {
                writingPacket.done.data()->send(false);
            }
        } else {
            reserved.append(writingPacket);
        }
    }
    for (const WritingPacket &writingPacket: reserved) {
        sendingQueue.putForcedly(writingPacket);
    }
}


quint32 SocketChannelPrivate::headerSize() const
{
    return static_cast<int>(sizeof(quint32) + sizeof(quint32));
}


QSharedPointer<SocketLike> SocketChannelPrivate::getBackend() const
{
    return connection;
}


VirtualChannelPrivate::VirtualChannelPrivate(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent)
    :DataChannelPrivate(pole, parent), parentChannel(parentChannel), channelNumber(channelNumber)
{
}


VirtualChannelPrivate::~VirtualChannelPrivate()
{
    abort();
}


bool VirtualChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet)
{
    if (broken || parentChannel.isNull()) {
        return false;
    }
    uchar header[sizeof(quint32)];
    qToBigEndian(channelNumber, header);
    QByteArray data;
    data.reserve(packet.size() + static_cast<int>(sizeof(quint32)));
    data.append(reinterpret_cast<char*>(header), sizeof(quint32));
    data.append(packet);
    return getPrivateHelper(parentChannel)->sendPacketRaw(this->channelNumber, data);
}


bool VirtualChannelPrivate::handleIncomingPacket(const QByteArray &packet)
{
    const int headerSize = sizeof(quint32);
    if (packet.size() < headerSize) {
        return false;
    }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    quint32 channelNumber = qFromBigEndian<quint32>(packet.constData());
#else
    quint32 channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.constData()));
#endif
    const QByteArray &payload = packet.mid(headerSize);
    if (channelNumber == DataChannelNumber) {
        receivingQueue.putForcedly(payload);
        if(receivingQueue.size() == (receivingQueue.capacity() * 3 / 4)) {
            sendPacketRawAsync(CommandChannelNumber, packSlowDownRequest());
        }
        return true;
    } else if (channelNumber == CommandChannelNumber) {
        return handleCommand(payload);
    } else if (subChannels.contains(channelNumber)) {
        QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
        if (channel.isNull()) {
#ifdef DEBUG_PROTOCOL
            qDebug() << QStringLiteral("found invalid channel number %1 while handle incoming packet.").arg(channelNumber);
#endif
            subChannels.remove(channelNumber);
            return false;
        }
        channel.toStrongRef()->d_func()->handleIncomingPacket(payload);
        return true;
    } else {
#ifdef DEBUG_PROTOCOL
        qDebug() << QStringLiteral("found unknown channel number %1 while handle incoming packet.").arg(channelNumber);
#endif
        return false;
    }
}


void VirtualChannelPrivate::abort()
{
    if (broken) {
        return;
    }
    broken = true;
    if (!parentChannel.isNull()) {
        getPrivateHelper(parentChannel)->cleanChannel(channelNumber, true);
    }
    DataChannelPrivate::abort();
}


void VirtualChannelPrivate::cleanChannel(quint32 channelNumber, bool sendDestroyPacket)
{
    int found = subChannels.remove(channelNumber);
    if (broken || parentChannel.isNull() || found <= 0) {
        return;
    }
    if (sendDestroyPacket) {
        notifyChannelClose(channelNumber);
    }
    getPrivateHelper(parentChannel)->cleanSendingPacket(this->channelNumber, [channelNumber](const QByteArray &packet) -> bool{
        const int headerSize = sizeof(quint32);
        if (packet.size() < headerSize) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(packet.constData());
#else
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.constData()));
#endif
        return channelNumberInPacket == channelNumber;
    });
}


void VirtualChannelPrivate::cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray &packet)> subCheckPacket)
{
    if (broken || parentChannel.isNull())
        return;
    getPrivateHelper(parentChannel)->cleanSendingPacket(this->channelNumber, [subChannelNumber, subCheckPacket](const QByteArray &packet) {
        const int headerSize = sizeof(quint32);
        if (packet.size() < headerSize) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(packet.constData());
#else
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.constData()));
#endif
        if (channelNumberInPacket != subChannelNumber) {
            return false;
        }
        return subCheckPacket(packet.mid(headerSize));
    });
}


bool VirtualChannelPrivate::isBroken() const
{
    return broken || parentChannel.isNull() || parentChannel->isBroken();
}


bool VirtualChannelPrivate::sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet)
{
    if (broken || parentChannel.isNull())
        return false;
    uchar header[sizeof(quint32)];
    qToBigEndian(channelNumber, header);

    QByteArray data;
    data.reserve(packet.size() + static_cast<int>(sizeof(quint32)));
    data.append(reinterpret_cast<char*>(header), sizeof(header));
    data.append(packet);
    return getPrivateHelper(parentChannel)->sendPacketRawAsync(this->channelNumber, data);
}


quint32 VirtualChannelPrivate::headerSize() const
{
    return sizeof(quint32);
}


QSharedPointer<SocketLike> VirtualChannelPrivate::getBackend() const
{
    if (broken || parentChannel.isNull()) {
        return QSharedPointer<SocketLike>();
    }
    return getPrivateHelper(parentChannel)->getBackend();
}


SocketChannel::SocketChannel(QSharedPointer<Socket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}


#ifndef QTNG_NO_CRYPTO
SocketChannel::SocketChannel(QSharedPointer<SslSocket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}
#endif


SocketChannel::SocketChannel(QSharedPointer<KcpSocket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}


SocketChannel::SocketChannel(QSharedPointer<SocketLike> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(connection, pole, this))
{
}


void SocketChannel::setKeepaliveTimeout(float timeout)
{
    Q_D(SocketChannel);
    d->keepaliveTimeout = static_cast<qint64>(timeout * 1000);
}


float SocketChannel::keepaliveTimeout() const
{
    Q_D(const SocketChannel);
    return static_cast<float>(d->keepaliveTimeout) / 1000;
}


quint32 SocketChannel::sendingQueueSize() const
{
    Q_D(const SocketChannel);
    return d->sendingQueue.size();
}


VirtualChannel::VirtualChannel(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber)
    :DataChannel(new VirtualChannelPrivate(parentChannel, pole, channelNumber, this))
{

}


DataChannel::DataChannel(DataChannelPrivate *d)
    :d_ptr(d)
{
}


DataChannel::~DataChannel()
{
    delete d_ptr;
}


bool DataChannel::isBroken() const
{
    Q_D(const DataChannel);
    return d->isBroken();
}


bool DataChannel::sendPacket(const QByteArray &packet)
{
    Q_D(DataChannel);
    return d->sendPacket(packet);
}


bool DataChannel::sendPacketAsync(const QByteArray &packet)
{
    Q_D(DataChannel);
    return d->sendPacketAsync(packet);
}


QByteArray DataChannel::recvPacket()
{
    Q_D(DataChannel);
    return d->recvPacket();
}


void DataChannel::abort()
{
    Q_D(DataChannel);
    d->abort();
}


QSharedPointer<VirtualChannel> DataChannel::makeChannel()
{
    Q_D(DataChannel);
    return d->makeChannel();
}


QSharedPointer<VirtualChannel> DataChannel::takeChannel()
{
    Q_D(DataChannel);
    return d->takeChannel();
}


QSharedPointer<VirtualChannel> DataChannel::takeChannel(quint32 channelNumber)
{
    Q_D(DataChannel);
    return d->takeChannel(channelNumber);
}


void DataChannel::setMaxPacketSize(quint32 size)
{
    Q_D(DataChannel);
    if (size < 64) {
        qWarning() << "the max packet size of DataChannel should not lesser than 64.";
    }
    d->maxPacketSize = size;
    d->payloadSizeHint = qMin(d->payloadSizeHint, size - d->headerSize());
}


quint32 DataChannel::maxPacketSize() const
{
    Q_D(const DataChannel);
    return d->maxPacketSize;
}


void DataChannel::setPayloadSizeHint(quint32 payloadSizeHint)
{
    Q_D(DataChannel);
    d->payloadSizeHint = qMin(payloadSizeHint, d->maxPacketSize - d->headerSize());
}


quint32 DataChannel::payloadSizeHint() const
{
    Q_D(const DataChannel);
    return d->payloadSizeHint;
}


void DataChannel::setCapacity(quint32 capacity)
{
    Q_D(DataChannel);
    d->receivingQueue.setCapacity(capacity);
//    SocketChannelPrivate *scp = dynamic_cast<SocketChannelPrivate*>(d);
//    if (scp) {
//        scp->sendingQueue.setCapacity(capacity);
//    }
}


quint32 DataChannel::capacity() const
{
    Q_D(const DataChannel);
    return d->receivingQueue.capacity();
}


quint32 DataChannel::receivingQueueSize() const
{
    Q_D(const DataChannel);
    return d->receivingQueue.size();
}


DataChannelPole DataChannel::pole() const
{
    Q_D(const DataChannel);
    return d->pole;
}


void DataChannel::setName(const QString &name)
{
    Q_D(DataChannel);
    d->name = name;
}


QString DataChannel::name() const
{
    Q_D(const DataChannel);
    return d->name;
}


quint32 VirtualChannel::channelNumber() const
{
    Q_D(const VirtualChannel);
    return d->channelNumber;
}


namespace {

class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<DataChannel> channel);
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual HostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual HostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr	fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual HostAddress::NetworkLayerProtocol protocol() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(const HostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const HostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, QSharedPointer<SocketDnsCache> dnsCache) override;
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
    virtual void close() override;
public:
    QSharedPointer<SocketLike> getBackend() const;
public:
    QByteArray buf;
    QSharedPointer<DataChannel> channel;
};


SocketLikeImpl::SocketLikeImpl(QSharedPointer<DataChannel> channel)
    :channel(channel)
{}


QSharedPointer<SocketLike> SocketLikeImpl::getBackend() const
{
    return DataChannelPrivate::getPrivateHelper(channel)->getBackend();
}


Socket::SocketError SocketLikeImpl::error() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnknownSocketError;
    } else {
        return backend->error();
    }
}


QString SocketLikeImpl::errorString() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return backend->errorString();
    }
}


bool SocketLikeImpl::isValid() const
{
    return !channel->isBroken();
}


HostAddress SocketLikeImpl::localAddress() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress();
    } else {
        return backend->localAddress();
    }
}


quint16 SocketLikeImpl::localPort() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->localPort();
    }
}


HostAddress SocketLikeImpl::peerAddress() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress();
    } else {
        return backend->peerAddress();
    }
}


QString SocketLikeImpl::peerName() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return backend->peerName();
    }
}


quint16 SocketLikeImpl::peerPort() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->peerPort();
    }
}


qintptr	SocketLikeImpl::fileno() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->fileno();
    }
}


Socket::SocketType SocketLikeImpl::type() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnknownSocketType;
    } else {
        return backend->type();
    }
}


Socket::SocketState SocketLikeImpl::state() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnconnectedState;
    } else {
        return backend->state();
    }
}


HostAddress::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress::UnknownNetworkLayerProtocol;
    } else {
        return backend->protocol();
    }
}


Socket *SocketLikeImpl::acceptRaw()
{
    return nullptr;
}


QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    return QSharedPointer<SocketLike>();
}


bool SocketLikeImpl::bind(const HostAddress &, quint16, Socket::BindMode)
{
    return false;
}


bool SocketLikeImpl::bind(quint16, Socket::BindMode)
{
    return false;
}


bool SocketLikeImpl::connect(const HostAddress &, quint16)
{
    return false;
}


bool SocketLikeImpl::connect(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return false;
}


void SocketLikeImpl::abort()
{
    channel->abort();
}


bool SocketLikeImpl::listen(int)
{
    return false;
}


bool SocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return false;
    } else {
        return backend->setOption(option, value);
    }
}


QVariant SocketLikeImpl::option(Socket::SocketOption option) const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QVariant();
    } else {
        return backend->option(option);
    }
}


qint32 SocketLikeImpl::recv(char *data, qint32 size)
{
    if (size <= 0) {
        return -1;
    }
    if (buf.isEmpty()) {
        buf = channel->recvPacket();
        if (buf.isEmpty()) {
            return 0;
        }
    }
    qint32 len = qMin(size, static_cast<qint32>(buf.size()));
    memcpy(data, buf.data(), static_cast<size_t>(len));
    buf.remove(0, len);
    return len;
}


qint32 SocketLikeImpl::recvall(char *data, qint32 size)
{
    if (size <= 0) {
        return -1;
    }
    while (buf.size() < size) {
        const QByteArray &packet = channel->recvPacket();
        if (packet.isEmpty()) {
            break;
        }
        buf.append(packet);
    }
    qint32 len = qMin(size, static_cast<qint32>(buf.size()));
    if (len > 0) {
        memcpy(data, buf.data(), static_cast<size_t>(len));
        buf.remove(0, len);
    }
    return len;
}


qint32 SocketLikeImpl::send(const char *data, qint32 size)
{
    qint32 len = qMin<qint32>(size, static_cast<qint32>(channel->payloadSizeHint()));
    bool ok = channel->sendPacket(QByteArray(data, len));
    return ok ? len: -1;
}


qint32 SocketLikeImpl::sendall(const char *data, qint32 size)
{
    qint32 count = 0;
    qint32 maxPayloadSize = static_cast<qint32>(channel->payloadSizeHint());
    while (count < size) {
        qint32 len = qMin(size - count, maxPayloadSize);
        bool ok = channel->sendPacket(QByteArray(data + count, len));
        if (!ok) {
            break;
        }
        count += len;
    }
    return count;
}


QByteArray SocketLikeImpl::recv(qint32 size)
{
    QByteArray t(size, Qt::Uninitialized);
    qint32 len = recv(t.data(), size);
    if (len <= 0) {
        return QByteArray();
    } else {
        t.resize(len);
        return t;
    }
}


QByteArray SocketLikeImpl::recvall(qint32 size)
{
    QByteArray t(size, Qt::Uninitialized);
    qint32 len = recvall(t.data(), size);
    if (len <= 0) {
        return QByteArray();
    } else {
        t.resize(len);
        return t;
    }
}


qint32 SocketLikeImpl::send(const QByteArray &data)
{
    return send(data.data(), data.size());
}


qint32 SocketLikeImpl::sendall(const QByteArray &data)
{
    return sendall(data.data(), data.size());
}


void SocketLikeImpl::close()
{
    channel->abort();
}


}


QSharedPointer<SocketLike> asSocketLike(QSharedPointer<DataChannel> channel)
{
    return QSharedPointer<SocketLikeImpl>::create(channel).dynamicCast<SocketLike>();
}


QTNETWORKNG_NAMESPACE_END
