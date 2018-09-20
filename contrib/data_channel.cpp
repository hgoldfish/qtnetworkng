#include <QtCore/QMap>
#include <QtCore/QDataStream>
#include <QtCore/QPointer>
#include <QtCore/QWeakPointer>
#include <QtCore/QtEndian>
#include "../include/locks.h"
#include "../include/coroutine_utils.h"
#include "./data_pack.h"
#include "./data_channel.h"

#define DEBUG_PROTOCOL

QTNETWORKNG_NAMESPACE_BEGIN

const quint8 MAKE_CHANNEL_REQUEST = 1;
const quint8 CHANNEL_MADE_REQUEST = 2;
const quint8 DESTROY_CHANNEL_REQUEST = 3;
const quint8 SLOW_DOWN_REQUEST = 4;
const quint8 GO_THROUGH_REQUEST = 5;

QByteArray packMakeChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(MAKE_CHANNEL_REQUEST, static_cast<void*>(buf));
    qToBigEndian(channelNumber, static_cast<void*>(buf + sizeof(quint8)));
#else
    qToBigEndian(MAKE_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
#endif
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}

QByteArray packChannelMadeRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(CHANNEL_MADE_REQUEST, static_cast<void*>(buf));
    qToBigEndian(channelNumber, static_cast<void*>(buf + sizeof(quint8)));
#else
    qToBigEndian(CHANNEL_MADE_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
#endif
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}

QByteArray packDestoryChannelRequest(quint32 channelNumber)
{
    uchar buf[sizeof(quint8) + sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(DESTROY_CHANNEL_REQUEST, static_cast<void*>(buf));
    qToBigEndian(channelNumber, static_cast<void*>(buf + sizeof(quint8)));
#else
    qToBigEndian(DESTROY_CHANNEL_REQUEST, buf);
    qToBigEndian(channelNumber, buf + sizeof(quint8));
#endif
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}

QByteArray packSlowDownRequest()
{
    uchar buf[sizeof(quint8)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(SLOW_DOWN_REQUEST, static_cast<void*>(buf));
#else
    qToBigEndian(SLOW_DOWN_REQUEST, buf);
#endif
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}

QByteArray packGoThroughRequest()
{
    uchar buf[sizeof(quint8)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(GO_THROUGH_REQUEST, static_cast<void*>(buf));
#else
    qToBigEndian(GO_THROUGH_REQUEST, buf);
#endif
    return QByteArray(reinterpret_cast<char*>(buf), sizeof(buf));
}

bool unpackCommand(QByteArray data, quint8 *command, quint32 *channelNumber)
{
    if(data.size() == (sizeof(quint8) + sizeof(quint32))) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(reinterpret_cast<void*>(data.data()));
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<uchar*>(data.data()));
#endif
        if(*command != MAKE_CHANNEL_REQUEST && *command != CHANNEL_MADE_REQUEST && *command != DESTROY_CHANNEL_REQUEST) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *channelNumber = qFromBigEndian<quint32>(reinterpret_cast<void*>(data.data() + sizeof(quint8)));
#else
        *channelNumber = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(data.data()) + sizeof(quint8));
#endif
        return true;
    } else if(data.size() == sizeof(quint8)) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        *command = qFromBigEndian<quint8>(reinterpret_cast<void*>(data.data()));
#else
        *command = qFromBigEndian<quint8>(reinterpret_cast<uchar*>(data.data()));
#endif
        if(*command != GO_THROUGH_REQUEST && *command != SLOW_DOWN_REQUEST) {
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
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
    bool removeChannel(VirtualChannel *channel);
    QByteArray recvPacket();
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet);
    QString toString();

    // must be implemented by subclasses
    virtual void close();
    virtual bool isBroken() const = 0;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) = 0;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) = 0;
    virtual void cleanChannel(quint32 channelNumber) = 0;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) = 0;

    // called by the subclasses.
    bool handleCommand(const QByteArray &packet);
    bool handleRawPacket(const QByteArray &packet);
    void notifyChannelClose(quint32 channelNumber);
    QByteArray packPacket(quint32 channelNumber, const QByteArray &packet);

    QString name;
    DataChannelPole pole;
    bool broken;
    quint32 nextChannelNumber;
    int maxPacketSize;
    QSet<quint32> pendingChannels;
    QMap<quint32, QWeakPointer<VirtualChannel>> subChannels;
    Queue<QByteArray> receivingQueue;
    Gate goThrough;

    Q_DECLARE_PUBLIC(DataChannel)
    DataChannel * const q_ptr;

    inline DataChannelPrivate *getPrivateHelper(QPointer<DataChannel> channel) { return channel.data()->d_ptr; }
};

class WritingPacket
{
public:
    WritingPacket()
        :channelNumber(0) {}
    WritingPacket(quint32 channelNumber, const QByteArray &packet, const QSharedPointer<ValueEvent<bool>> &done)
        :channelNumber(channelNumber), packet(packet), done(done) {}
    quint32 channelNumber;
    QByteArray packet;
    QSharedPointer<ValueEvent<bool>> done;
    bool isValid()
    {
        return !(channelNumber == 0 && packet.isNull() && done.isNull());
    }
};

class SocketChannelPrivate: public DataChannelPrivate
{
public:
    SocketChannelPrivate(const QSharedPointer<SocketLike> connection, DataChannelPole pole, SocketChannel *parent);
    virtual ~SocketChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void close() override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) override;
    virtual void cleanChannel(quint32 channelNumber) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;
    void doSend();
    void doReceive();
    QHostAddress getPeerAddress();

    const QSharedPointer<SocketLike> connection;
    Queue<WritingPacket> sendingQueue;
    CoroutineGroup *operations;

    Q_DECLARE_PUBLIC(SocketChannel)
};

class VirtualChannelPrivate: public DataChannelPrivate
{
public:
    VirtualChannelPrivate(DataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent);
    virtual ~VirtualChannelPrivate() override;
    virtual bool isBroken() const override;
    virtual void close() override;
    virtual bool sendPacketRaw(quint32 channelNumber, const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet) override;
    virtual void cleanChannel(quint32 channelNumber) override;
    virtual void cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray&)> subCheckPacket) override;

    bool handleIncomingPacket(const QByteArray &packet);

    QPointer<DataChannel> parentChannel;
    quint32 channelNumber;
    Gate notPending;

    Q_DECLARE_PUBLIC(VirtualChannel)
};


DataChannelPrivate::DataChannelPrivate(DataChannelPole pole, DataChannel *parent)
    : pole(pole)
    , broken(false)
    , maxPacketSize(1024 * 64)
    , receivingQueue(1024)
    , q_ptr(parent)
{
    if(pole == DataChannelPole::NegativePole) {
        nextChannelNumber = 0xffffffff;
    } else {
        nextChannelNumber = 2;
    }
}

DataChannelPrivate::~DataChannelPrivate()
{
//    for(int i = 0; i < receivingQueue.getting(); ++i) {
//        receivingQueue.put(QByteArray());
//    }
}

QString DataChannelPrivate::toString()
{
    QString pattern = QStringLiteral("<%1 (name = %2, state = %3)>");
    QString clazz, state;
    if(dynamic_cast<VirtualChannel*>(this)) {
        clazz = QStringLiteral("VirtualChannel");
    } else {
        clazz = QStringLiteral("SocketChannel");
    }
    if(broken) {
        state = QStringLiteral("closed");
    } else {
        state = QStringLiteral("ok");
    }
    return pattern.arg(clazz, name, state);
}

void DataChannelPrivate::close()
{
    Q_ASSERT(broken); // must be called by other close method.
    for(int i = 0; i < receivingQueue.getting(); ++i) {
        receivingQueue.put(QByteArray());
    }
    goThrough.open();
    for(QMapIterator<quint32, QWeakPointer<VirtualChannel>> itor(subChannels); itor.hasNext();) {
        const QWeakPointer<VirtualChannel> &subChannel = itor.next().value();
        if(!subChannel.isNull()) {
            subChannel.data()->close();
        }
    }
    subChannels.clear();
}

QSharedPointer<VirtualChannel> DataChannelPrivate::makeChannel()
{
    Q_Q(DataChannel);
    if (isBroken()) {
        qDebug() << "the data channel is broken, can not make channel.";
        return QSharedPointer<VirtualChannel>();
    }
    nextChannelNumber += qint32(pole);
    quint32 channelNumber = nextChannelNumber;
    sendPacketRawAsync(CommandChannelNumber, packMakeChannelRequest(channelNumber));
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::PositivePole, channelNumber));
    subChannels.insert(channelNumber,channel);
    return channel;
}


QSharedPointer<VirtualChannel> DataChannelPrivate::getChannel(quint32 channelNumber)
{
    Q_Q(DataChannel);
    if(isBroken() || !pendingChannels.contains(channelNumber)) {
        return QSharedPointer<VirtualChannel>();
    }
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::NegativePole, channelNumber));
    subChannels.insert(channelNumber, channel);
    sendPacketRawAsync(CommandChannelNumber, packChannelMadeRequest(channelNumber));
    pendingChannels.remove(channelNumber);
    return channel;
}

QByteArray DataChannelPrivate::recvPacket()
{
    if(receivingQueue.isEmpty() && broken) {
        return QByteArray();
    }
    QByteArray packet = receivingQueue.get();
    if(packet.isNull()) {
        return QByteArray();
    }
    if(receivingQueue.size() == receivingQueue.getCapacity() - 1){
        sendPacketRawAsync(CommandChannelNumber, packGoThroughRequest());
    }
    return packet;
}

bool DataChannelPrivate::sendPacket(const QByteArray &packet)
{
    if(packet.size() > maxPacketSize) {
        return false;
    }
    goThrough.wait();
    return sendPacketRaw(DataChannelNumber, packet);
}

bool DataChannelPrivate::sendPacketAsync(const QByteArray &packet)
{
    if(packet.size() > maxPacketSize) {
        return false;
    }
    return sendPacketRawAsync(DataChannelNumber, packet);
}

bool DataChannelPrivate::handleCommand(const QByteArray &packet)
{
    quint8 command;
    quint32 channelNumber;
    bool isCommand = unpackCommand(packet, &command, &channelNumber);
    if(!isCommand) {
        qWarning() << "invalid command.";
        return false;
    }
    if(command == MAKE_CHANNEL_REQUEST) {
        pendingChannels.insert(channelNumber);
        return true;
    } else if(command == CHANNEL_MADE_REQUEST) {
        if(subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if(!channel.isNull()) {
                channel.data()->d_func()->notPending.open();
                return true;
            }
        } else {
            qWarning() << "channel is not found." << channelNumber;
            return false;
        }
    } else if(command == DESTROY_CHANNEL_REQUEST) {
        if(pendingChannels.contains(channelNumber)) {
            pendingChannels.remove(channelNumber);
        } else if(subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if(!channel.isNull()) {
                channel.data()->close();
            }
        }
        return true;
    } else if(command == SLOW_DOWN_REQUEST) {
        goThrough.close();
        return true;
    } else if(command == GO_THROUGH_REQUEST) {
        goThrough.open();
        return true;
    }
}

void DataChannelPrivate::notifyChannelClose(quint32 channelNumber)
{
    if(broken) {
        return;
    }
    sendPacketRawAsync(CommandChannelNumber, packDestoryChannelRequest(channelNumber));
}

SocketChannelPrivate::SocketChannelPrivate(const QSharedPointer<SocketLike> connection, DataChannelPole pole, SocketChannel *parent)
    :DataChannelPrivate(pole, parent), connection(connection), sendingQueue(1024), operations(new CoroutineGroup())
{
    connection->setOption(Socket::LowDelayOption, true);
    operations->spawnWithName(QString::fromLatin1("receivingCoroutine"), [this]{
        this->doReceive();
    });
    operations->spawnWithName(QString::fromLatin1("writingCoroutine"), [this]{
        this->doSend();
    });
}

SocketChannelPrivate::~SocketChannelPrivate()
{
    close();
    delete operations;
}

bool SocketChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet)
{
    if(broken) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done(new ValueEvent<bool>());
    sendingQueue.put(WritingPacket(channelNumber, packet, done));
    bool success = done->wait();
    return success;
}

bool SocketChannelPrivate::sendPacketRawAsync(quint32 channelNumber, const QByteArray &packet)
{
    if(broken) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done;
    sendingQueue.put(WritingPacket(channelNumber, packet, done));
    return true;
}

void SocketChannelPrivate::doSend()
{
    while(true) {
        WritingPacket writingPacket;
        try {
            writingPacket = sendingQueue.get();
        } catch (CoroutineExitException) {
            return close();
        } catch (...) {
            return close();
        }
        if(!writingPacket.isValid()) {
            return close();
        }
        if(broken) {
            if(!writingPacket.done.isNull()) {
                writingPacket.done->send(false);
            }
            return close();
        }

        uchar header[sizeof(quint32) + sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        qToBigEndian((quint32)writingPacket.packet.size(), static_cast<void*>(header));
        qToBigEndian(writingPacket.channelNumber, static_cast<void*>(header + sizeof(quint32)));
#else
        qToBigEndian((quint32)writingPacket.packet.size(), header);
        qToBigEndian(writingPacket.channelNumber, header + sizeof(quint32));
#endif
        QByteArray data;
        data.reserve(sizeof(header) + writingPacket.packet.size());
        data.append(reinterpret_cast<char*>(header), sizeof(header));
        data.append(writingPacket.packet);

        int sentBytes;
        try {
            sentBytes = connection->sendall(data);
        } catch(CoroutineExitException) {
            if(!writingPacket.done.isNull()) {
                writingPacket.done->send(false);
            }
#ifdef DEBUG_PROTOCOL
            qDebug() << "coroutine is killed while sending packet.";
#endif
            return close();
        } catch(...) {
#ifdef DEBUG_PROTOCOL
            qDebug() << "unhandled exception while sending packet.";
#endif
            return close();
        }

        if(sentBytes == data.size()) {
            if(!writingPacket.done.isNull()) {
                writingPacket.done->send(true);
            }
        } else {
            if(writingPacket.done.isNull()) {
//                continue; // why do this?
            } else {
                writingPacket.done->send(false);
            }
            return close();
        }
    }
}

void SocketChannelPrivate::doReceive()
{
    const size_t headerSize = sizeof(quint32) + sizeof(quint32);
    quint32 packetSize;
    quint32 channelNumber;
    QByteArray packet;
    while(true) {
        try {
            QByteArray header = connection->recvall(headerSize);
            if(header.size() != headerSize) {
                return close();
            }
    #if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
            packetSize = qFromBigEndian<quint32>(reinterpret_cast<void*>(header.data()));
            channelNumber = qFromBigEndian<quint32>(reinterpret_cast<void*>(header.data() + sizeof(quint32)));
    #else
            packetSize = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(header.data()));
            channelNumber = qFromBigEndian<quint32>(reinterpret_cast<uchar*>(header.data() + sizeof(quint32)));
    #endif
            if(static_cast<int>(packetSize) > maxPacketSize) {
    #ifdef DEBUG_PROTOCOL
                qDebug() << QStringLiteral("packetSize %1 is larger than %2").arg(packetSize).arg(maxPacketSize);
    #endif
                return close();
            }
            packet = connection->recvall(packetSize);
            if(packet.size() != static_cast<int>(packetSize)) {
                qDebug() << "invalid packet does not fit packet size = " << packetSize;
                return close();
            }
        } catch (CoroutineExitException) {
            return close();
        } catch (...) {
            return close();
        }
        if(channelNumber == DataChannelNumber) {
            if(receivingQueue.size() > receivingQueue.getCapacity() - 1) {
                sendPacketRawAsync(CommandChannelNumber, packSlowDownRequest());
            }
            receivingQueue.put(packet);
        } else if(channelNumber == CommandChannelNumber) {
            if(!handleCommand(packet)) {
                return close();
            }
        } else if(subChannels.contains(channelNumber)) {
            QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
            if(channel.isNull()) {
                qDebug() << "unknown channel number: " << channelNumber;
                subChannels.remove(channelNumber);
            } else {
                channel.data()->d_func()->handleIncomingPacket(packet);
            }
        } else {
            qDebug() << "packet is dropped for unknown channel number:" << channelNumber;
        }
    }
}

void SocketChannelPrivate::close()
{
    if(broken) {
        return;
    }
    broken = true;
    connection->close();
    while(!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if(!writingPacket.done.isNull()) {
            writingPacket.done->send(false);
        }
    }
    if(operations->get("receivingCoroutine") != Coroutine::current()) {
        operations->kill("receivingCoroutine");
    }
    if(operations->get("writingCoroutine") != Coroutine::current()) {
        operations->kill("writingCoroutine");
    }
    DataChannelPrivate::close();
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
    if(found <= 0) {
        return;
    }

    notifyChannelClose(channelNumber);
    cleanSendingPacket(channelNumber, alwayTrue);
}

void SocketChannelPrivate::cleanSendingPacket(quint32 subChannelNumber, std::function<bool (const QByteArray &)> subCheckPacket)
{
    QList<WritingPacket> reserved;
    while(!sendingQueue.isEmpty()) {
        const WritingPacket &writingPacket = sendingQueue.get();
        if(writingPacket.channelNumber == subChannelNumber && subCheckPacket(writingPacket.packet)) {
            if(!writingPacket.done.isNull()) {
                writingPacket.done.data()->send(false);
            }
        } else {
            reserved.append(writingPacket);
        }
    }
    for(const WritingPacket &writingPacket: reserved) {
        sendingQueue.put(writingPacket);
    }
}


VirtualChannelPrivate::VirtualChannelPrivate(DataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent)
    :DataChannelPrivate(pole, parent), parentChannel(parentChannel), channelNumber(channelNumber)
{
    if(pole == NegativePole) {
        notPending.open();
    } else {
        notPending.close();
    }
}

VirtualChannelPrivate::~VirtualChannelPrivate()
{
    close();
}

bool VirtualChannelPrivate::sendPacketRaw(quint32 channelNumber, const QByteArray &packet)
{
    if(broken || parentChannel.isNull()) {
        return false;
    }
    notPending.wait();
    if(broken || parentChannel.isNull()) {
        return false;
    }
    uchar header[sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(channelNumber, static_cast<void*>(header));
#else
    qToBigEndian(channelNumber, header);
#endif
    QByteArray data;
    data.reserve(packet.size() + sizeof(quint32));
    data.append(reinterpret_cast<char*>(header), sizeof(quint32));
    data.append(packet);
    return getPrivateHelper(parentChannel)->sendPacketRaw(this->channelNumber, data);
}

bool VirtualChannelPrivate::handleIncomingPacket(const QByteArray &packet)
{
    const int headerSize = sizeof(quint32);
    if(packet.size() < headerSize) {
        return false;
    }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    quint32 channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const void*>(packet.data()));
#else
    quint32 channelNumber = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.data()));
#endif
    const QByteArray &payload = packet.mid(headerSize);
    if(channelNumber == DataChannelNumber) {
        receivingQueue.put(payload);
        if(receivingQueue.size() > (receivingQueue.getCapacity() - 1)) {
            sendPacketRawAsync(CommandChannelNumber, packSlowDownRequest());
        }
        return true;
    } else if(channelNumber == CommandChannelNumber) {
        return handleCommand(payload);
    } else if(subChannels.contains(channelNumber)) {
        QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
        if(channel.isNull()) {
            qDebug() << QStringLiteral("found invalid channel number %1 while handle incoming packet.").arg(channelNumber);
            subChannels.remove(channelNumber);
            return false;
        }
        channel.data()->d_func()->handleIncomingPacket(payload);
        return true;
    } else {
        qDebug() << QStringLiteral("found unknown channel number %1 while handle incoming packet.").arg(channelNumber);
        return false;
    }

}

void VirtualChannelPrivate::close()
{
    if(broken) {
        return;
    }
    broken = true;
    if(!parentChannel.isNull()) {
        getPrivateHelper(parentChannel)->cleanChannel(channelNumber);
    }
    if(!notPending.isOpen()) {
        notPending.open();
    }
    DataChannelPrivate::close();
}

void VirtualChannelPrivate::cleanChannel(quint32 channelNumber)
{
    int found = subChannels.remove(channelNumber);
    if(broken || parentChannel.isNull()) {
        return;
    }
    if(found > 0) {
        notifyChannelClose(channelNumber);
    }
    getPrivateHelper(parentChannel)->cleanSendingPacket(this->channelNumber, [channelNumber](const QByteArray &packet) -> bool{
        const int headerSize = sizeof(quint32);
        if(packet.size() < headerSize) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const void*>(packet.data()));
#else
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.data()));
#endif

        return channelNumberInPacket == channelNumber;
    });
}


void VirtualChannelPrivate::cleanSendingPacket(quint32 subChannelNumber, std::function<bool(const QByteArray &packet)> subCheckPacket)
{
    if(broken || parentChannel.isNull())
        return;
    getPrivateHelper(parentChannel)->cleanSendingPacket(this->channelNumber, [subChannelNumber, subCheckPacket](const QByteArray &packet) {
        const int headerSize = sizeof(quint32);
        if(packet.size() < headerSize) {
            return false;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const void*>(packet.data()));
#else
        quint32 channelNumberInPacket = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(packet.data()));
#endif
        if(channelNumberInPacket != subChannelNumber) {
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
    if(broken || parentChannel.isNull())
        return false;
    uchar header[sizeof(quint32)];
#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(channelNumber, static_cast<void*>(header));
#else
    qToBigEndian(channelNumber, header);
#endif

    QByteArray data;
    data.reserve(packet.size() + sizeof(quint32));
    data.append(reinterpret_cast<char*>(header), sizeof(header));
    data.append(packet);
    return getPrivateHelper(parentChannel)->sendPacketRawAsync(this->channelNumber, data);
}


SocketChannel::SocketChannel(const QSharedPointer<Socket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(SocketLike::rawSocket(connection), pole, this))
{
}


#ifdef QTNETWOKRNG_USE_SSL
SocketChannel::SocketChannel(const QSharedPointer<SslSocket> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(SocketLike::sslSocket(connection), pole, this))
{
}
#endif


SocketChannel::SocketChannel(const QSharedPointer<SocketLike> connection, DataChannelPole pole)
    :DataChannel(new SocketChannelPrivate(connection, pole, this))
{
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


void DataChannel::close()
{
    Q_D(DataChannel);
    d->close();
}


QSharedPointer<VirtualChannel> DataChannel::makeChannel()
{
    Q_D(DataChannel);
    return d->makeChannel();
}


QSharedPointer<VirtualChannel> DataChannel::getChannel(quint32 channelNumber)
{
    Q_D(DataChannel);
    return d->getChannel(channelNumber);
}


void DataChannel::setMaxPacketSize(int size)
{
    Q_D(DataChannel);
    d->maxPacketSize = size;
}


int DataChannel::maxPacketSize() const
{
    Q_D(const DataChannel);
    return d->maxPacketSize;
}


void DataChannel::setCapacity(int capacity)
{
    Q_D(DataChannel);
    d->receivingQueue.setCapacity(capacity);
}


int DataChannel::capacity()
{
    Q_D(DataChannel);
    return d->receivingQueue.getCapacity();
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

QTNETWORKNG_NAMESPACE_END
