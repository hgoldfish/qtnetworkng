#include <QtCore/qmap.h>
#include <QtCore/qpointer.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qendian.h>
#include <QtCore/qdatetime.h>
#include "../include/locks.h"
#include "../include/coroutine_utils.h"
#include "../include/data_channel.h"

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
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
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
    virtual void cleanChannel(quint32 channelNumber) = 0;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) = 0;
    virtual quint32 headerSize() const = 0;

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
    Queue<quint32> pendingChannels;
    QMap<quint32, QWeakPointer<VirtualChannel>> subChannels;
    Queue<QByteArray> receivingQueue;
    Gate goThrough;

    Q_DECLARE_PUBLIC(DataChannel)
    DataChannel * const q_ptr;
    bool broken;

    inline DataChannelPrivate *getPrivateHelper(QPointer<DataChannel> channel) { return channel.data()->d_func(); }
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
    virtual void cleanChannel(quint32 channelNumber) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;
    virtual quint32 headerSize() const override;
    void doSend();
    void doReceive();
    void doKeepalive();
    QHostAddress getPeerAddress();

    const QSharedPointer<SocketLike> connection;
    Queue<WritingPacket> sendingQueue;
    CoroutineGroup *operations;
    qint64 lastActiveTimestamp;
    qint64 lastKeepaliveTimestamp;
    qint64 keepaliveTimeout;

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
    virtual void cleanChannel(quint32 channelNumber) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;
    virtual quint32 headerSize() const override;

    bool handleIncomingPacket(const QByteArray &packet);

    QPointer<DataChannel> parentChannel;
    Gate notPending;
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
    return pattern.arg(clazz, name, state);
}

void DataChannelPrivate::abort()
{
    Q_ASSERT(broken); // must be called by subclasses's close method.
    // FIXME if close() is called by doReceive(), may cause the queue reports deleting not empty.
    for (quint32 i = 0; i < receivingQueue.getting(); ++i) {
        receivingQueue.put(QByteArray());
    }
    goThrough.open();
    for (QMapIterator<quint32, QWeakPointer<VirtualChannel>> itor(subChannels); itor.hasNext();) {
        const QWeakPointer<VirtualChannel> &subChannel = itor.next().value();
        if(!subChannel.isNull()) {
            subChannel.data()->abort();
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
    subChannels.insert(channelNumber, channel);
    return channel;
}


QSharedPointer<VirtualChannel> DataChannelPrivate::takeChannel()
{
    Q_Q(DataChannel);
    if (isBroken()) {
        return QSharedPointer<VirtualChannel>();
    }
    quint32 channelNumber = pendingChannels.get();
    if (!channelNumber) {
        return QSharedPointer<VirtualChannel>();
    }
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::NegativePole, channelNumber));
    channel->setMaxPacketSize(maxPacketSize - sizeof(quint32));
    channel->setPayloadSizeHint(payloadSizeHint - sizeof(quint32));
    subChannels.insert(channelNumber, channel);
    sendPacketRawAsync(CommandChannelNumber, packChannelMadeRequest(channelNumber));
    return channel;
}


QSharedPointer<VirtualChannel> DataChannelPrivate::getChannel(quint32 channelNumber)
{
    Q_Q(DataChannel);
    if (isBroken() || !pendingChannels.contains(channelNumber)) {
        return QSharedPointer<VirtualChannel>();
    }
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::NegativePole, channelNumber));
    channel->setMaxPacketSize(maxPacketSize - sizeof(quint32));
    channel->setPayloadSizeHint(payloadSizeHint - sizeof(quint32));
    subChannels.insert(channelNumber, channel);
    sendPacketRawAsync(CommandChannelNumber, packChannelMadeRequest(channelNumber));
    pendingChannels.remove(channelNumber);
    return channel;
}


QByteArray DataChannelPrivate::recvPacket()
{
    if (receivingQueue.isEmpty() && broken) {
        return QByteArray();
    }
    QByteArray packet = receivingQueue.get();
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
    quint8 command;
    quint32 channelNumber;
    bool isCommand = unpackCommand(packet, &command, &channelNumber);
    if (!isCommand) {
        qWarning() << "invalid command.";
        return false;
    }
    if (command == MAKE_CHANNEL_REQUEST) {
        pendingChannels.put(channelNumber);
        return true;
    } else if (command == CHANNEL_MADE_REQUEST) {
        if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (!channel.isNull()) {
                channel.data()->d_func()->notPending.open();
                return true;
            } else {
#ifdef DEBUG_PROTOCOL
                qDebug() << "channel is gone." << channelNumber;
#endif
                return false;
            }
        } else {
            qWarning() << "channel is not found." << channelNumber;
            return false;
        }
    } else if (command == DESTROY_CHANNEL_REQUEST) {
        if (pendingChannels.contains(channelNumber)) {
            pendingChannels.remove(channelNumber);
        } else if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (!channel.isNull()) {
                channel.data()->abort();
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
    :DataChannelPrivate(pole, parent), connection(connection), sendingQueue(256), operations(new CoroutineGroup()),
      lastActiveTimestamp(QDateTime::currentMSecsSinceEpoch()), lastKeepaliveTimestamp(lastActiveTimestamp),
      keepaliveTimeout(1000 * 10)
{
    connection->setOption(Socket::LowDelayOption, true);
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
                channel.data()->d_func()->handleIncomingPacket(packet);
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
        Coroutine::sleep(1.0);
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - lastActiveTimestamp > keepaliveTimeout) {
            return abort();
        }
        if (now - lastKeepaliveTimestamp > (keepaliveTimeout / 2)) {
            lastKeepaliveTimestamp = now;
            sendPacketRawAsync(CommandChannelNumber, packKeepaliveRequest());
        }
    }
}


void SocketChannelPrivate::abort()
{
    if(broken) {
        return;
    }
    broken = true;
    connection->abort();
    while (!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if (!writingPacket.done.isNull()) {
            writingPacket.done->send(false);
        }
    }
    Coroutine *current = Coroutine::current();
    if(operations->get("receiving").data() != current) {
        operations->kill("receiving");
    }
    if(operations->get("sending").data() != current) {
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


bool alwayTrue(const QByteArray &packet) {
    Q_UNUSED(packet);
    return true;
}


void SocketChannelPrivate::cleanChannel(quint32 channelNumber)
{
    int found = subChannels.remove(channelNumber);
    if (found <= 0) {
        return;
    }

    notifyChannelClose(channelNumber);
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


VirtualChannelPrivate::VirtualChannelPrivate(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent)
    :DataChannelPrivate(pole, parent), parentChannel(parentChannel), channelNumber(channelNumber)
{
    if (pole == NegativePole) {
        notPending.open();
    } else {
        notPending.close();
    }
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
    if (!notPending.wait()) {
        return false;
    }
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
        channel.data()->d_func()->handleIncomingPacket(payload);
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
        getPrivateHelper(parentChannel)->cleanChannel(channelNumber);
    }
    if (!notPending.isOpen()) {
        notPending.open();
    }
    DataChannelPrivate::abort();
}


void VirtualChannelPrivate::cleanChannel(quint32 channelNumber)
{
    int found = subChannels.remove(channelNumber);
    if (broken || parentChannel.isNull()) {
        return;
    }
    if (found > 0) {
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


SocketChannel::SocketChannel(QSharedPointer<Socket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(SocketLike::rawSocket(connection), pole, this))
{
}


#ifndef QTNG_NO_CRYPTO
SocketChannel::SocketChannel(QSharedPointer<SslSocket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(SocketLike::sslSocket(connection), pole, this))
{
}
#endif


SocketChannel::SocketChannel(QSharedPointer<KcpSocket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(SocketLike::kcpSocket(connection), pole, this))
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


QSharedPointer<VirtualChannel> DataChannel::getChannel(quint32 channelNumber)
{
    Q_D(DataChannel);
    return d->getChannel(channelNumber);
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
class StreamLikeImpl: public StreamLike
{
public:
    StreamLikeImpl(QSharedPointer<DataChannel> channel);
public:
    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
public:
    QByteArray buf;
    QSharedPointer<DataChannel> channel;
};


StreamLikeImpl::StreamLikeImpl(QSharedPointer<DataChannel> channel)
    :channel(channel) {}


qint32 StreamLikeImpl::recv(char *data, qint32 size)
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

qint32 StreamLikeImpl::recvall(char *data, qint32 size)
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


qint32 StreamLikeImpl::send(const char *data, qint32 size)
{
    qint32 len = qMin<qint32>(size, static_cast<qint32>(channel->payloadSizeHint()));
    bool ok = channel->sendPacket(QByteArray(data, len));
    return ok ? len: -1;
}


qint32 StreamLikeImpl::sendall(const char *data, qint32 size)
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


QByteArray StreamLikeImpl::recv(qint32 size)
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


QByteArray StreamLikeImpl::recvall(qint32 size)
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

qint32 StreamLikeImpl::send(const QByteArray &data)
{
    return send(data.data(), data.size());
}

qint32 StreamLikeImpl::sendall(const QByteArray &data)
{
    return sendall(data.data(), data.size());
}

}

QSharedPointer<StreamLike> asStream(QSharedPointer<DataChannel> channel)
{
    return QSharedPointer<StreamLikeImpl>::create(channel).dynamicCast<StreamLike>();
}

QTNETWORKNG_NAMESPACE_END
