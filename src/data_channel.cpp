#include <QtCore/qmap.h>
#include <QtCore/qpointer.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qendian.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qscopeguard.h>
#include "../include/locks.h"
#include "../include/coroutine_utils.h"
#include "../include/data_channel.h"
#include "../include/kcp.h"
#ifndef QTNG_NO_CRYPTO
#  include "../include/ssl.h"
#endif

#include "debugger.h"

QTNG_LOGGER("qtng.data_channel");

//#define DEBUG_PROTOCOL

QTNETWORKNG_NAMESPACE_BEGIN

const quint8 MAKE_CHANNEL_REQUEST = 1;
const quint8 CHANNEL_MADE_REQUEST = 2;
const quint8 DESTROY_CHANNEL_REQUEST = 3;
const quint8 SLOW_DOWN_REQUEST = 4;
const quint8 GO_THROUGH_REQUEST = 5;
const quint8 KEEPALIVE_REQUEST = 6;
const quint32 DefaultPacketSize = 1024 * 64;
const quint32 DefaultPayloadSize = 1400;

static QByteArray packMakeChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(MAKE_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static QByteArray packChannelMadeRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(CHANNEL_MADE_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static QByteArray packDestoryChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
    qToBigEndian(DESTROY_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static QByteArray packSlowDownRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(SLOW_DOWN_REQUEST, buf);
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static QByteArray packGoThroughRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(GO_THROUGH_REQUEST, buf);
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static QByteArray packKeepaliveRequest()
{
    uchar buf[sizeof(quint8)];
    qToBigEndian(KEEPALIVE_REQUEST, buf);
    return QByteArray(reinterpret_cast<char *>(buf), sizeof(buf));
}

static bool unpackCommand(QByteArray data, quint8 *command, quint32 *channelNumber)
{
    if (data.size() == (sizeof(quint8) + sizeof(quint32))) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(data.constData());
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<const uchar *>(data.constData()));
#endif
        if (*command != MAKE_CHANNEL_REQUEST && *command != CHANNEL_MADE_REQUEST
            && *command != DESTROY_CHANNEL_REQUEST) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *channelNumber = qFromBigEndian<quint32>(data.constData() + sizeof(quint8));
#else
        *channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data.constData()) + sizeof(quint8));
#endif
        return true;
    } else if (data.size() == sizeof(quint8)) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(data.constData());
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<const uchar *>(data.constData()));
#endif
        if (*command != GO_THROUGH_REQUEST && *command != SLOW_DOWN_REQUEST && *command != KEEPALIVE_REQUEST) {
            return false;
        }
        return true;
    } else {
        return false;
    }
}

enum class BlockFlag
{
    NonBlock,
    Block_And_Not_Wait_Sent,
    Block_Until_Sent,
};

class DataChannelPrivate
{
public:
    DataChannelPrivate(DataChannelPole pole, DataChannel *parent);
    virtual ~DataChannelPrivate();

    // called by the public class DataChannel
    QSharedPointer<VirtualChannel> makeChannelInternal(DataChannelPole pole, quint32 channelNumber);
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> takeChannel();
    QSharedPointer<VirtualChannel> takeChannel(quint32 channelNumber);
    QSharedPointer<VirtualChannel> peekChannel(quint32 channelNumber);
    QByteArray recvPacket();
    bool sendPacket(const QByteArray &packet, bool waitSent);
    bool sendPacketAsync(const QByteArray &packet);
    QString toString() const;

    // must be implemented by subclasses
    virtual void abort(DataChannel::ChannelError reason);
    virtual bool isBroken() const = 0;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &payload, BlockFlag blocking) = 0;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) = 0;
    virtual void cleanSendingPacket(quint32 subChannelNumber,
                                    std::function<bool(const QByteArray &)> subCheckPacket) = 0;
    virtual quint32 maxPayloadSize() const = 0;
    virtual quint32 payloadSizeHint() const = 0;
    virtual quint32 headerSize() const = 0;
    virtual QSharedPointer<SocketLike> getBackend() const = 0;

    // called by the subclasses.
    bool handleCommand(const QByteArray &packet);
    void notifyChannelClose(quint32 channelNumber);
    DataChannel::ChannelError handleIncomingPacket(quint32 channelNumber, const QByteArray &payload);

    QString name;
    DataChannelPole pole;
    quint32 nextChannelNumber;
    QMap<quint32, QWeakPointer<VirtualChannel>> subChannels;
    Queue<QSharedPointer<VirtualChannel>> pendingChannels;
    Queue<QByteArray> receivingQueue;
    Gate goThrough;
    DataChannel::ChannelError error;

    QSharedPointer<DataChannel> pluggedChannel;

    Q_DECLARE_PUBLIC(DataChannel)
    DataChannel * const q_ptr;

    inline static DataChannelPrivate *getPrivateHelper(QPointer<DataChannel> channel)
    {
        return channel.data()->d_func();
    }
    inline static DataChannelPrivate *getPrivateHelper(QSharedPointer<DataChannel> channel)
    {
        return channel.data()->d_func();
    }
};

class WritingPacket
{
public:
    WritingPacket()
        : channelNumber(0)
    {
    }
    WritingPacket(quint32 channelNumber, const QByteArray &packet, QSharedPointer<ValueEvent<bool>> done)
        : packet(packet)
        , done(done)
        , channelNumber(channelNumber)
    {
    }

    QByteArray packet;
    QSharedPointer<ValueEvent<bool>> done;
    quint32 channelNumber;
    bool isValid() { return !(channelNumber == 0 && packet.isNull() && done.isNull()); }
};

class SocketChannelPrivate : public DataChannelPrivate
{
public:
    SocketChannelPrivate(QSharedPointer<SocketLike> connection, DataChannelPole pole, SocketChannel *parent);
    virtual ~SocketChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void abort(DataChannel::ChannelError reason) override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet, BlockFlag blocking) override;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber,
                                    std::function<bool(const QByteArray &)> subCheckPacket) override;
    virtual quint32 maxPayloadSize() const override;
    virtual quint32 payloadSizeHint() const override;
    virtual quint32 headerSize() const override;
    virtual QSharedPointer<SocketLike> getBackend() const override;
    void doSend();
    void doReceive();
    void doKeepalive();

    const QSharedPointer<SocketLike> connection;
    Queue<WritingPacket> sendingQueue;
    CoroutineGroup *operations;
    quint32 _maxPayloadSize;
    quint32 _payloadSizeHint;
    qint64 lastActiveTimestamp;
    qint64 lastKeepaliveTimestamp;
    qint64 keepaliveTimeout;
    qint64 keepaliveInterval;

    Q_DECLARE_PUBLIC(SocketChannel)
};

class VirtualChannelPrivate : public DataChannelPrivate
{
public:
    VirtualChannelPrivate(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber,
                          VirtualChannel *parent);
    virtual ~VirtualChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void abort(DataChannel::ChannelError reason) override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet, BlockFlag blocking) override;
    virtual void cleanChannel(quint32 channelNumber, bool sendDestroyPacket) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber,
                                    std::function<bool(const QByteArray &)> subCheckPacket) override;
    virtual quint32 maxPayloadSize() const override;
    virtual quint32 payloadSizeHint() const override;
    virtual quint32 headerSize() const override;
    virtual QSharedPointer<SocketLike> getBackend() const override;

    QPointer<DataChannel> parentChannel;
    quint32 channelNumber;

    Q_DECLARE_PUBLIC(VirtualChannel)
};

DataChannelPrivate::DataChannelPrivate(DataChannelPole pole, DataChannel *parent)
    : pole(pole)
    , receivingQueue(1024)  // may consume 1024 * maxPayloadSize bytes.
    , error(DataChannel::NoError)
    , q_ptr(parent)
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

QString DataChannelPrivate::toString() const
{
    Q_Q(const DataChannel);
    QString pattern = QString::fromLatin1("<%1 (name = %2, error = %3, capacity = %4, queue_size = %5)>");
    QString clazz;
    if (dynamic_cast<const VirtualChannelPrivate *>(this)) {
        clazz = QString::fromLatin1("VirtualChannel");
    } else {
        clazz = QString::fromLatin1("SocketChannel");
    }
    return pattern.arg(clazz)
            .arg(name.isEmpty() ? QString::fromLatin1("unamed") : name)
            .arg(q->errorString())
            .arg(receivingQueue.capacity())
            .arg(receivingQueue.size());
}

void DataChannelPrivate::abort(DataChannel::ChannelError reason)
{
    Q_ASSERT(error != DataChannel::NoError);  // must be called by subclasses's close method.
    if (!pluggedChannel.isNull()) {
        getPrivateHelper(pluggedChannel)->abort(reason);
        pluggedChannel.clear();
    }

    for (quint32 i = 0; i < receivingQueue.getting(); ++i) {
        receivingQueue.put(QByteArray());
    }
    for (quint32 i = 0; i < pendingChannels.getting(); ++i) {
        pendingChannels.put(QSharedPointer<VirtualChannel>());
    }
    goThrough.open();
    for (QMapIterator<quint32, QWeakPointer<VirtualChannel>> itor(subChannels); itor.hasNext();) {
        const QWeakPointer<VirtualChannel> &subChannel = itor.next().value();
        if (!subChannel.isNull()) {
            QSharedPointer<VirtualChannel> strong = subChannel.toStrongRef();
            strong->d_func()->parentChannel.clear();
            strong->d_func()->abort(this->error);
        }
    }
    subChannels.clear();
}

DataChannel::ChannelError DataChannelPrivate::handleIncomingPacket(quint32 channelNumber, const QByteArray &payload)
{
    if (!pluggedChannel.isNull()) {
        if (!getPrivateHelper(pluggedChannel)->sendPacketRaw(channelNumber, payload, BlockFlag::Block_Until_Sent)) {
            return DataChannel::PluggedChannelError;
        } else {
            return DataChannel::NoError;
        }
    }

    if (channelNumber == DataChannelNumber) {
        if (receivingQueue.size() == (receivingQueue.capacity() * 3 / 4)) {
            sendPacketRaw(CommandChannelNumber, packSlowDownRequest(), BlockFlag::Block_And_Not_Wait_Sent);
        }
        receivingQueue.put(payload);
    } else if (channelNumber == CommandChannelNumber) {
        if (!handleCommand(payload)) {
            return DataChannel::InvalidCommand;
        } else {
            return DataChannel::NoError;
        }
    } else if (subChannels.contains(channelNumber)) {
        QSharedPointer<VirtualChannel> channel = subChannels.value(channelNumber).toStrongRef();
        if (channel.isNull()) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "channel is destroyed and data is abandoned: " << channelNumber;
#endif
            subChannels.remove(channelNumber);
        } else {
            const int headerSize = sizeof(quint32);
            if (payload.size() < headerSize) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "the sub channel got an too small packet: " << channelNumber << payload.size()
                           << headerSize;
#endif
                return DataChannel::InvalidPacket;
            }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
            quint32 channelNumber = qFromBigEndian<quint32>(payload.constData());
#else
            quint32 channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(payload.constData()));
#endif
            const QByteArray &packet = payload.mid(headerSize);
            DataChannel::ChannelError handlePacketResult =
                    channel->d_func()->handleIncomingPacket(channelNumber, packet);
            if (handlePacketResult != DataChannel::NoError) {
#ifdef DEBUG_PROTOCOL
                qtng_debug << "the sub channel got an too small packet: " << channelNumber << payload.size()
                           << headerSize;
#endif
                getPrivateHelper(channel)->abort(handlePacketResult);
            }
        }
    } else {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "channel is destroyed and data is abandoned: " << channelNumber;
#endif
    }
    return DataChannel::NoError;
}

QSharedPointer<VirtualChannel> DataChannelPrivate::makeChannelInternal(DataChannelPole pole, quint32 channelNumber)
{
    Q_Q(DataChannel);
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, pole, channelNumber));
    channel->d_func()->receivingQueue.setCapacity(receivingQueue.capacity());
    subChannels.insert(channelNumber, channel);
    return channel;
}

QSharedPointer<VirtualChannel> DataChannelPrivate::makeChannel()
{
    if (isBroken()) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "the data channel is broken, can not make channel.";
#endif
        return QSharedPointer<VirtualChannel>();
    }
    quint32 channelNumber = nextChannelNumber;
    nextChannelNumber += this->pole;
    QSharedPointer<VirtualChannel> channel = makeChannelInternal(DataChannelPole::PositivePole, channelNumber);
    sendPacketRaw(CommandChannelNumber, packMakeChannelRequest(channelNumber), BlockFlag::NonBlock);
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

    QSharedPointer<VirtualChannel> found;
    QList<QSharedPointer<VirtualChannel>> tmp;
    while (!pendingChannels.isEmpty()) {
        QSharedPointer<VirtualChannel> channel = pendingChannels.get();
        if (Q_UNLIKELY(channel.isNull())) {
            return QSharedPointer<VirtualChannel>();
        } else if (channel->channelNumber() == channelNumber) {
            found = channel;
            break;
        } else {
            tmp.append(channel);
        }
    }
    for (int i = tmp.size() - 1; i >= 0; i--) {
        pendingChannels.returnsForcely(tmp.at(i));
    }
    return found;
}

QSharedPointer<VirtualChannel> DataChannelPrivate::peekChannel(quint32 channelNumber)
{
    if (isBroken()) {
        return QSharedPointer<VirtualChannel>();
    }
    QSharedPointer<VirtualChannel> found;
    QList<QSharedPointer<VirtualChannel>> tmp;
    while (!pendingChannels.isEmpty()) {
        QSharedPointer<VirtualChannel> channel = pendingChannels.get();
        tmp.append(channel);
        if (channel && channel->channelNumber() == channelNumber) {
            found = channel;
            break;
        }
    }
    for (int i = tmp.size() - 1; i >= 0; i--) {
        pendingChannels.returnsForcely(tmp.at(i));
    }
    return found;
}

QByteArray DataChannelPrivate::recvPacket()
{
    if (receivingQueue.isEmpty() && error != DataChannel::NoError) {
        return QByteArray();
    }
    const QByteArray &packet = receivingQueue.get();
    if (packet.isNull()) {
        return QByteArray();
    }
    if (receivingQueue.size() == (receivingQueue.capacity() / 2)) {
        sendPacketRaw(CommandChannelNumber, packGoThroughRequest(), BlockFlag::NonBlock);
    }
    return packet;
}

bool DataChannelPrivate::sendPacket(const QByteArray &packet, bool waitSent)
{
    if (!goThrough.tryWait()) {
        return false;
    }
    return sendPacketRaw(DataChannelNumber, packet, waitSent ? BlockFlag::Block_Until_Sent : BlockFlag::Block_And_Not_Wait_Sent);
}

bool DataChannelPrivate::sendPacketAsync(const QByteArray &packet)
{
    return sendPacketRaw(DataChannelNumber, packet, BlockFlag::NonBlock);
}

bool DataChannelPrivate::handleCommand(const QByteArray &packet)
{
    quint8 command;
    quint32 channelNumber;
    bool isCommand = unpackCommand(packet, &command, &channelNumber);
    if (!isCommand) {
        qtng_warning << "invalid command.";
        return false;
    }
    if (command == MAKE_CHANNEL_REQUEST) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "make channel request:" << channelNumber;
#endif
        if (subChannels.contains(channelNumber)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "the peer is making an exists channel channel:" << channelNumber;
#endif
            return false;
        }
        QSharedPointer<VirtualChannel> channel = makeChannelInternal(DataChannelPole::NegativePole, channelNumber);
        sendPacketRaw(CommandChannelNumber, packChannelMadeRequest(channelNumber), BlockFlag::NonBlock);
        pendingChannels.put(channel);
        return true;
    } else if (command == CHANNEL_MADE_REQUEST) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "channel made request:" << channelNumber;
#endif
        if (subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if (channel.isNull()) {
                subChannels.remove(channelNumber);
            } else {
                return true;
            }
        }
#ifdef DEBUG_PROTOCOL
        qtng_debug << "channel is gone." << channelNumber;
#endif
        // the channel is open by me and then closed quickly...
        sendPacketRaw(CommandChannelNumber, packDestoryChannelRequest(channelNumber), BlockFlag::NonBlock);
        return true;
    } else if (command == DESTROY_CHANNEL_REQUEST) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "destroy channel request:" << channelNumber;
#endif
        QSharedPointer<VirtualChannel> strong = peekChannel(channelNumber); // not remove channel from pending channels.
        if (strong.isNull() && subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            cleanChannel(channelNumber, false);
            if (!channel.isNull()) {
                strong = channel.toStrongRef();
            }
        }
        if (strong) {
            strong->d_func()->parentChannel.clear();
            // the receiving queue is still ok after aborted.
            strong->d_func()->abort(DataChannel::RemotePeerClosedError);
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
    } else if (command < 32) {
        // if command < 32, this command must be processed.
        qtng_warning << "unknown command.";
        return false;
    } else {
        qtng_info << "unknown optional command, you might upgrade your qtng.";
        return true;
    }
}

void DataChannelPrivate::notifyChannelClose(quint32 channelNumber)
{
    if (error != DataChannel::NoError) {
        return;
    }
    sendPacketRaw(CommandChannelNumber, packDestoryChannelRequest(channelNumber), BlockFlag::NonBlock);
}

SocketChannelPrivate::SocketChannelPrivate(QSharedPointer<SocketLike> connection, DataChannelPole pole,
                                           SocketChannel *parent)
    : DataChannelPrivate(pole, parent)
    , connection(connection)
    , sendingQueue(256)
    , operations(new CoroutineGroup())
    , _maxPayloadSize(DefaultPacketSize - sizeof(quint32) * 2)
    , _payloadSizeHint(DefaultPayloadSize)  // tcp fragment size.
    , lastActiveTimestamp(QDateTime::currentMSecsSinceEpoch())
    , lastKeepaliveTimestamp(lastActiveTimestamp)
    , keepaliveTimeout(-1)
    , keepaliveInterval(1000 * 2)
{
    // connection->setOption(Socket::LowDelayOption, true);
    connection->setOption(Socket::KeepAliveOption, false);  // we do it!
    operations->spawnWithName(QString::fromLatin1("receiving"), [this] { this->doReceive(); });
    operations->spawnWithName(QString::fromLatin1("sending"), [this] { this->doSend(); });
    operations->spawnWithName(QString::fromLatin1("keepalive"), [this] { this->doKeepalive(); });
}

SocketChannelPrivate::~SocketChannelPrivate()
{
    SocketChannelPrivate::abort(DataChannel::UserShutdown);
    delete operations;
}

bool SocketChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet, BlockFlag blocking)
{
    if (error != DataChannel::NoError || packet.isEmpty()) {
        return false;
    }
    if (static_cast<quint32>(packet.size()) > _maxPayloadSize) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "the packet size is too large." << packet.size() << _maxPayloadSize;
#endif
        return false;
    }
    switch (blocking) {
    case BlockFlag::NonBlock:
        sendingQueue.putForcedly(WritingPacket(channelNumber, packet, QSharedPointer<ValueEvent<bool>>()));
        return true;
    case BlockFlag::Block_And_Not_Wait_Sent:
        sendingQueue.put(WritingPacket(channelNumber, packet, QSharedPointer<ValueEvent<bool>>()));
        return true;
    case BlockFlag::Block_Until_Sent: {
        QSharedPointer<ValueEvent<bool>> done(new ValueEvent<bool>());
        sendingQueue.put(WritingPacket(channelNumber, packet, done));
        bool success = done->tryWait();
        return success;
    }
    default:
        Q_UNREACHABLE();
        break;
    }
}

void SocketChannelPrivate::doSend()
{
    const int maxSendSize = 64 * 1024;
    int count = 0;
    QByteArray buf(maxSendSize, Qt::Uninitialized);
    while (true) {
        QList<WritingPacket> writingPackets;
        auto clean = qScopeGuard([&writingPackets] {
            for (WritingPacket &writingPacket : writingPackets) {
                if (!writingPacket.done.isNull()) {
                    writingPacket.done->send(false);
                }
            }
        });
        try {
            WritingPacket writingPacket = sendingQueue.get();
            if (!writingPacket.isValid()) {
                Q_ASSERT(error != DataChannel::NoError);
                return;
            }
            writingPackets.append(writingPacket);
#define CHANNEL_HEAD_SIZE (sizeof(quint32) + sizeof(quint32))
            count = CHANNEL_HEAD_SIZE + writingPacket.packet.size();
            while (count + CHANNEL_HEAD_SIZE < maxSendSize && !sendingQueue.isEmpty()) {
                WritingPacket writingPacket = sendingQueue.peek();
                if (!writingPacket.isValid()) {
                    break;
                }
                if (count + CHANNEL_HEAD_SIZE + writingPacket.packet.size() > maxSendSize) {
                    break;
                }
                count += CHANNEL_HEAD_SIZE + writingPacket.packet.size();
                sendingQueue.get();
                writingPackets.append(writingPacket);
            }
        } catch (CoroutineExitException) {
            Q_ASSERT(error != DataChannel::NoError);
            return;
        } catch (...) {
            return abort(DataChannel::UnknownError);
        }
        if (error != DataChannel::NoError) {
            return;
        }
        buf.reserve(count);
        char *p = buf.data();
        for (WritingPacket &writingPacket : writingPackets) {
            qToBigEndian<quint32>(static_cast<quint32>(writingPacket.packet.size()), p);
            p += sizeof(quint32);
            qToBigEndian<quint32>(writingPacket.channelNumber, p);
            p += sizeof(quint32);
            memcpy(p, writingPacket.packet.data(), writingPacket.packet.size());
            p += writingPacket.packet.size();
        }

        int sentBytes;
        try {
            sentBytes = connection->sendall(buf.data(), count);
        } catch (CoroutineExitException) {
            Q_ASSERT(error != DataChannel::NoError);
            return;
        } catch (...) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "unhandled exception while sending packet.";
#endif
            return abort(DataChannel::UnknownError);
        }

        if (sentBytes == count) {
            clean.dismiss();
            for (WritingPacket &writingPacket : writingPackets) {
                if (!writingPacket.done.isNull()) {
                    writingPacket.done->send(true);
                }
            }
            lastKeepaliveTimestamp = QDateTime::currentMSecsSinceEpoch();
        } else {
            return abort(DataChannel::SendingError);
        }
    }
}

void SocketChannelPrivate::doReceive()
{
    const size_t headerSize = sizeof(quint32) + sizeof(quint32);
    quint32 payloadSize;
    quint32 channelNumber;
    QByteArray payload;
    while (true) {
        try {
            const QByteArray &header = connection->recvall(headerSize);
            if (header.size() != headerSize) {
                return abort(DataChannel::ReceivingError);
            }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
            payloadSize = qFromBigEndian<quint32>(header.data());
            channelNumber = qFromBigEndian<quint32>(header.data() + sizeof(quint32));
#else
            payloadSize = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(header.data()));
            channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(header.data() + sizeof(quint32)));
#endif
            if (payloadSize > _maxPayloadSize) {
#ifdef DEBUG_PROTOCOL
                qtng_debug
                        << QString::fromLatin1("packetSize %1 is larger than %2").arg(payloadSize).arg(_maxPayloadSize);
#endif
                return abort(DataChannel::PakcetTooLarge);
            }
            payload = connection->recvall(static_cast<qint32>(payloadSize));
            if (payload.size() != static_cast<int>(payloadSize)) {
                qtng_debug << "invalid packet does not fit packet size:" << payloadSize << payload.size();
                return abort(DataChannel::InvalidPacket);
            }
        } catch (CoroutineExitException) {
            Q_ASSERT(error != DataChannel::NoError);
            return;
        } catch (...) {
            return abort(DataChannel::UnknownError);
        }
        DataChannel::ChannelError handlePacketResult = handleIncomingPacket(channelNumber, payload);
        if (handlePacketResult != DataChannel::NoError) {
            return abort(handlePacketResult);
        }
        lastActiveTimestamp = QDateTime::currentMSecsSinceEpoch();
    }
}

void SocketChannelPrivate::doKeepalive()
{
    while (true) {
        Coroutine::sleep(0.5f);
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        // now and lastActiveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (keepaliveTimeout > 0 && now > lastActiveTimestamp && (now - lastActiveTimestamp > keepaliveTimeout)) {
#ifdef DEBUG_PROTOCOL
            qtng_debug << "channel is timeout." << connection->peerAddressURI() << "receivingQueue size:" << receivingQueue.size();
            for (QSharedPointer<VirtualChannel> channel : subChannels) {
                qtng_debug << "sub channel:" << channel->channelNumber() << "receivingQueue size:" << channel->d_func()->receivingQueue.size();
            }
#endif
            return abort(DataChannel::KeepaliveTimeoutError);
        }
        // now and lastKeepaliveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastKeepaliveTimestamp && (now - lastKeepaliveTimestamp > keepaliveInterval)
            && sendingQueue.isEmpty()) {
            lastKeepaliveTimestamp = now;
            QSharedPointer<ValueEvent<bool>> done;
#ifdef DEBUG_PROTOCOL
            qtng_debug << "sending keepalive packet." << connection->peerAddressURI();
#endif
            sendingQueue.putForcedly(WritingPacket(CommandChannelNumber, packKeepaliveRequest(), done));
        }
    }
}

void SocketChannelPrivate::abort(DataChannel::ChannelError reason)
{
    if (error != DataChannel::NoError) {
        return;
    }
    error = reason;
#ifdef DEBUG_PROTOCOL
    qtng_debug << "socket data channel abort:" << error;
#endif
    Coroutine *current = Coroutine::current();
    connection->abort();

    while (!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if (!writingPacket.done.isNull()) {
            writingPacket.done->send(false);
        }
    }
    if (operations->get(QString::fromLatin1("receiving")).data() != current) {
        operations->kill(QString::fromLatin1("receiving"));
    }
    if (operations->get(QString::fromLatin1("sending")).data() != current) {
        operations->kill(QString::fromLatin1("sending"));
    }
    if (operations->get(QString::fromLatin1("keepalive")).data() != current) {
        operations->kill(QString::fromLatin1("keepalive"));
    }
    DataChannelPrivate::abort(reason);
}

bool SocketChannelPrivate::isBroken() const
{
    return error != DataChannel::NoError || !connection->isValid();
}

static inline bool alwayTrue(const QByteArray &)
{
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

void SocketChannelPrivate::cleanSendingPacket(quint32 subChannelNumber,
                                              std::function<bool(const QByteArray &)> subCheckPacket)
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
    for (const WritingPacket &writingPacket : reserved) {
        sendingQueue.putForcedly(writingPacket);
    }
}

quint32 SocketChannelPrivate::maxPayloadSize() const
{
    return _maxPayloadSize;
}

quint32 SocketChannelPrivate::payloadSizeHint() const
{
    return _payloadSizeHint;
}

quint32 SocketChannelPrivate::headerSize() const
{
    return static_cast<int>(sizeof(quint32) + sizeof(quint32));
}

QSharedPointer<SocketLike> SocketChannelPrivate::getBackend() const
{
    return connection;
}

VirtualChannelPrivate::VirtualChannelPrivate(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber,
                                             VirtualChannel *parent)
    : DataChannelPrivate(pole, parent)
    , parentChannel(parentChannel)
    , channelNumber(channelNumber)
{
}

VirtualChannelPrivate::~VirtualChannelPrivate()
{
    VirtualChannelPrivate::abort(DataChannel::UserShutdown);
}

bool VirtualChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet, BlockFlag blocking)
{
    if (error != DataChannel::NoError || parentChannel.isNull() || packet.isEmpty()) {
#ifdef DEBUG_PROTOCOL
        qtng_debug << "the packet is empty?" << (error != DataChannel::NoError) << parentChannel.isNull()
                   << packet.isEmpty();
#endif
        return false;
    }
    uchar header[sizeof(quint32)];
    qToBigEndian(channelNumber, header);
    QByteArray data;
    data.reserve(packet.size() + static_cast<int>(sizeof(quint32)));
    data.append(reinterpret_cast<char *>(header), sizeof(quint32));
    data.append(packet);
    return getPrivateHelper(parentChannel)->sendPacketRaw(this->channelNumber, data, blocking);
}

void VirtualChannelPrivate::abort(DataChannel::ChannelError reason)
{
    if (error != DataChannel::NoError) {
        return;
    }
    error = reason;
    if (!parentChannel.isNull()) {
        getPrivateHelper(parentChannel)->cleanChannel(channelNumber, true);
    }
    DataChannelPrivate::abort(reason);
}

void VirtualChannelPrivate::cleanChannel(quint32 channelNumber, bool sendDestroyPacket)
{
    int found = subChannels.remove(channelNumber);
    if (error != DataChannel::NoError || parentChannel.isNull() || found <= 0) {
        return;
    }
    if (sendDestroyPacket) {
        notifyChannelClose(channelNumber);
    }
    getPrivateHelper(parentChannel)
            ->cleanSendingPacket(this->channelNumber, [channelNumber](const QByteArray &packet) -> bool {
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

void VirtualChannelPrivate::cleanSendingPacket(quint32 subChannelNumber,
                                               std::function<bool(const QByteArray &packet)> subCheckPacket)
{
    if (error != DataChannel::NoError || parentChannel.isNull()) {
        return;
    }
    getPrivateHelper(parentChannel)
            ->cleanSendingPacket(this->channelNumber, [subChannelNumber, subCheckPacket](const QByteArray &packet) {
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
    return error != DataChannel::NoError || parentChannel.isNull() || parentChannel->isBroken();
}

quint32 VirtualChannelPrivate::maxPayloadSize() const
{
    if (isBroken()) {
        return 1400;
    } else {
        return parentChannel->maxPayloadSize() - sizeof(quint32);
    }
}

quint32 VirtualChannelPrivate::payloadSizeHint() const
{
    if (isBroken()) {
        return 1400;
    } else {
        return parentChannel->payloadSizeHint() - sizeof(quint32);
    }
}

quint32 VirtualChannelPrivate::headerSize() const
{
    return sizeof(quint32);
}

QSharedPointer<SocketLike> VirtualChannelPrivate::getBackend() const
{
    if (error != DataChannel::NoError || parentChannel.isNull()) {
        return QSharedPointer<SocketLike>();
    }
    return getPrivateHelper(parentChannel)->getBackend();
}

SocketChannel::SocketChannel(QSharedPointer<Socket> connection, DataChannelPole pole)
    : DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}

#ifndef QTNG_NO_CRYPTO
SocketChannel::SocketChannel(QSharedPointer<SslSocket> connection, DataChannelPole pole)
    : DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}
#endif

SocketChannel::SocketChannel(QSharedPointer<KcpSocket> connection, DataChannelPole pole)
    : DataChannel(new SocketChannelPrivate(asSocketLike(connection), pole, this))
{
}

SocketChannel::SocketChannel(QSharedPointer<SocketLike> connection, DataChannelPole pole)
    : DataChannel(new SocketChannelPrivate(connection, pole, this))
{
}

void SocketChannel::setMaxPacketSize(quint32 size)
{
    Q_D(SocketChannel);
    if (size == 0) {
        size = DefaultPacketSize;
    } else if (size < 64) {
        qtng_warning << "the max packet size of DataChannel should not lesser than 64.";
        return;
    }
    d->_maxPayloadSize = size - sizeof(quint32) - sizeof(quint32);
    d->_payloadSizeHint = qMin(d->_payloadSizeHint, d->_maxPayloadSize);
}

void SocketChannel::setPayloadSizeHint(quint32 payloadSizeHint)
{
    Q_D(SocketChannel);
    if (payloadSizeHint == 0) {
        payloadSizeHint = DefaultPayloadSize;
    } else if (payloadSizeHint < 64) {
        qtng_warning << "the payload size hint of DataChannel should not lesser than 64.";
        return;
    }
    d->_payloadSizeHint = qMin(payloadSizeHint, d->_maxPayloadSize);
}

void SocketChannel::setKeepaliveTimeout(float timeout)
{
    Q_D(SocketChannel);
    if (timeout > 0) {
        d->keepaliveTimeout = static_cast<qint64>(timeout * 1000);
        if (d->keepaliveTimeout < 1000) {
            d->keepaliveTimeout = 1000;
        }
    } else {
        d->keepaliveTimeout = -1;
    }
}

float SocketChannel::keepaliveTimeout() const
{
    Q_D(const SocketChannel);
    return static_cast<float>(d->keepaliveTimeout) / 1000;
}

void SocketChannel::setKeepaliveInterval(float keepaliveInterval)
{
    Q_D(SocketChannel);
    d->keepaliveInterval = static_cast<qint64>(keepaliveInterval * 1000);
    if (d->keepaliveInterval < 200) {
        d->keepaliveInterval = 200;
    }
}

float SocketChannel::keepaliveInterval() const
{
    Q_D(const SocketChannel);
    return static_cast<float>(d->keepaliveInterval) / 1000;
}

quint32 SocketChannel::sendingQueueSize() const
{
    Q_D(const SocketChannel);
    return d->sendingQueue.size();
}

QSharedPointer<SocketLike> SocketChannel::connection() const
{
    Q_D(const SocketChannel);
    return d->connection;
}

VirtualChannel::VirtualChannel(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber)
    : DataChannel(new VirtualChannelPrivate(parentChannel, pole, channelNumber, this))
{
}

quint32 VirtualChannel::channelNumber() const
{
    Q_D(const VirtualChannel);
    return d->channelNumber;
}

DataChannel::DataChannel(DataChannelPrivate *d)
    : d_ptr(d)
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

bool DataChannel::sendPacket(const QByteArray &packet, bool waitSent/* = true*/)
{
    Q_D(DataChannel);
    return d->sendPacket(packet, waitSent);
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
    d->abort(DataChannel::UserShutdown);
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

DataChannel::ChannelError DataChannel::error() const
{
    Q_D(const DataChannel);
    return d->error;
}

QString DataChannel::errorString() const
{
    Q_D(const DataChannel);
    switch (d->error) {
    case RemotePeerClosedError:
        return QString::fromLatin1("The remote peer closed the connection");
    case KeepaliveTimeoutError:
        return QString::fromLatin1("The remote peer didn't send keepalive packet for a long time.");
    case ReceivingError:
        return QString::fromLatin1("Can not receive packet from remote peer");
    case SendingError:
        return QString::fromLatin1("Can not send packet to remote peer.");
    case InvalidPacket:
        return QString::fromLatin1("Can not parse packet header.");
    case InvalidCommand:
        return QString::fromLatin1("Can not parse command or unknown command.");
    case UserShutdown:
        return QString::fromLatin1("Programmer shutdown channel manually.");
    case PluggedChannelError:
        return QString::fromLatin1("The plugged channel has error.");
    case PakcetTooLarge:
        return QString::fromLatin1("The packet is too large.");
    case UnknownError:
        return QString::fromLatin1("Caught unknown error.");
    case ProgrammingError:
        return QString::fromLatin1("The QtNetwork programmer do a stupid thing.");
    case NoError:
        return QString();
    default:
        Q_UNREACHABLE();
    }
}

QString DataChannel::toString() const
{
    Q_D(const DataChannel);
    return d->toString();
}

quint32 DataChannel::maxPacketSize() const
{
    Q_D(const DataChannel);
    return d->maxPayloadSize() + d->headerSize();
}

quint32 DataChannel::maxPayloadSize() const
{
    Q_D(const DataChannel);
    return d->maxPayloadSize();
}

quint32 DataChannel::payloadSizeHint() const
{
    Q_D(const DataChannel);
    return d->payloadSizeHint();
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

namespace {

class DataChannelSocketLikeImpl : public SocketLike
{
public:
    DataChannelSocketLikeImpl(QSharedPointer<DataChannel> channel);
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
    virtual void abort() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;
public:
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
    virtual void close() override;
public:
    QSharedPointer<SocketLike> getBackend() const;
public:
    QByteArray buf;
    QSharedPointer<DataChannel> channel;
};

DataChannelSocketLikeImpl::DataChannelSocketLikeImpl(QSharedPointer<DataChannel> channel)
    : channel(channel)
{
}

QSharedPointer<SocketLike> DataChannelSocketLikeImpl::getBackend() const
{
    return DataChannelPrivate::getPrivateHelper(channel)->getBackend();
}

Socket::SocketError DataChannelSocketLikeImpl::error() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnknownSocketError;
    } else {
        return backend->error();
    }
}

QString DataChannelSocketLikeImpl::errorString() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return backend->errorString();
    }
}

bool DataChannelSocketLikeImpl::isValid() const
{
    return !channel->isBroken();
}

HostAddress DataChannelSocketLikeImpl::localAddress() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress();
    } else {
        return backend->localAddress();
    }
}

quint16 DataChannelSocketLikeImpl::localPort() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->localPort();
    }
}

HostAddress DataChannelSocketLikeImpl::peerAddress() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress();
    } else {
        return backend->peerAddress();
    }
}

QString DataChannelSocketLikeImpl::peerName() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return backend->peerName();
    }
}

quint16 DataChannelSocketLikeImpl::peerPort() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->peerPort();
    }
}

qintptr DataChannelSocketLikeImpl::fileno() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return 0;
    } else {
        return backend->fileno();
    }
}

Socket::SocketType DataChannelSocketLikeImpl::type() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnknownSocketType;
    } else {
        return backend->type();
    }
}

Socket::SocketState DataChannelSocketLikeImpl::state() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return Socket::UnconnectedState;
    } else {
        return backend->state();
    }
}

HostAddress::NetworkLayerProtocol DataChannelSocketLikeImpl::protocol() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return HostAddress::UnknownNetworkLayerProtocol;
    } else {
        return backend->protocol();
    }
}

QString DataChannelSocketLikeImpl::localAddressURI() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return QLatin1String("datachannel+") + backend->localAddressURI();
    }
}

QString DataChannelSocketLikeImpl::peerAddressURI() const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QString();
    } else {
        return QLatin1String("datachannel+") + backend->peerAddressURI();
    }
}

Socket *DataChannelSocketLikeImpl::acceptRaw()
{
    return nullptr;
}

QSharedPointer<SocketLike> DataChannelSocketLikeImpl::accept()
{
    return QSharedPointer<SocketLike>();
}

bool DataChannelSocketLikeImpl::bind(const HostAddress &, quint16, Socket::BindMode)
{
    return false;
}

bool DataChannelSocketLikeImpl::bind(quint16, Socket::BindMode)
{
    return false;
}

bool DataChannelSocketLikeImpl::connect(const HostAddress &, quint16)
{
    return false;
}

bool DataChannelSocketLikeImpl::connect(const QString &, quint16, QSharedPointer<SocketDnsCache>)
{
    return false;
}

void DataChannelSocketLikeImpl::abort()
{
    channel->abort();
}

bool DataChannelSocketLikeImpl::listen(int)
{
    return false;
}

bool DataChannelSocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return false;
    } else {
        return backend->setOption(option, value);
    }
}

QVariant DataChannelSocketLikeImpl::option(Socket::SocketOption option) const
{
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return QVariant();
    } else {
        return backend->option(option);
    }
}

qint32 DataChannelSocketLikeImpl::peek(char *data, qint32 size) 
{
    if (size <= 0) {
        return -1;
    }
    qint32 len = qMin(size, static_cast<qint32>(buf.size()));
    memcpy(data, buf.data(), static_cast<size_t>(len));
    return len;
}

qint32 DataChannelSocketLikeImpl::peekRaw(char *data, qint32 size)
{
    if (size <= 0) {
        return -1;
    }
    QSharedPointer<SocketLike> backend = getBackend();
    if (backend.isNull()) {
        return -1;
    }
    return backend->peekRaw(data, size);
}

qint32 DataChannelSocketLikeImpl::recv(char *data, qint32 size)
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

qint32 DataChannelSocketLikeImpl::recvall(char *data, qint32 size)
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

qint32 DataChannelSocketLikeImpl::send(const char *data, qint32 size)
{
    qint32 len = qMin<qint32>(size, static_cast<qint32>(channel->maxPayloadSize()));
    bool ok = channel->sendPacket(QByteArray(data, len));
    return ok ? len : -1;
}

qint32 DataChannelSocketLikeImpl::sendall(const char *data, qint32 size)
{
    qint32 count = 0;
    qint32 maxPayloadSize = static_cast<qint32>(channel->maxPayloadSize());
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

QByteArray DataChannelSocketLikeImpl::recv(qint32 size)
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

QByteArray DataChannelSocketLikeImpl::recvall(qint32 size)
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

qint32 DataChannelSocketLikeImpl::send(const QByteArray &data)
{
    return send(data.data(), data.size());
}

qint32 DataChannelSocketLikeImpl::sendall(const QByteArray &data)
{
    return sendall(data.data(), data.size());
}

void DataChannelSocketLikeImpl::close()
{
    channel->abort();
}

}  // namespace

void exchange(QSharedPointer<DataChannel> incoming, QSharedPointer<DataChannel> outgoing)
{
    DataChannelPrivate *incomingPrivate = DataChannelPrivate::getPrivateHelper(incoming);
    DataChannelPrivate *outgoingPrivate = DataChannelPrivate::getPrivateHelper(outgoing);

    while (!incomingPrivate->receivingQueue.isEmpty()) {
        const QByteArray &packet = incomingPrivate->receivingQueue.get();
        outgoingPrivate->sendPacketRaw(DataChannelNumber, packet, BlockFlag::NonBlock);
    }
    while (!outgoingPrivate->receivingQueue.isEmpty()) {
        const QByteArray &packet = outgoingPrivate->receivingQueue.get();
        incomingPrivate->sendPacketRaw(DataChannelNumber, packet, BlockFlag::NonBlock);
    }

    incomingPrivate->pluggedChannel = outgoing;
    outgoingPrivate->pluggedChannel = incoming;
    try {
        // the receiving queue of incoming and outgoing is always empty while exchanging.
        // if not, may be one of those peers is aborted. then we quit.
        while (!incoming->recvPacket().isEmpty()) { }
        while (!outgoing->recvPacket().isEmpty()) { }
    } catch (...) {
        incoming->abort();
        outgoing->abort();
        throw;
    }
}

QSharedPointer<SocketLike> asSocketLike(QSharedPointer<DataChannel> channel)
{
    return QSharedPointer<DataChannelSocketLikeImpl>::create(channel).dynamicCast<SocketLike>();
}

QTNETWORKNG_NAMESPACE_END
