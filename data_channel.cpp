#include <QMap>
#include <QDataStream>
#include <QPointer>
#include <QWeakPointer>
#include <QtEndian>
#include "locks.h"
#include "datapack.h"
#include "data_channel.h"
#include "coroutine_utils.h"

void noop(){}

struct MakeChannelRequest: public CommonHeader
{
    MakeChannelRequest(){command = 1;}
    quint32 channelNumber;
    void pack(QDataStream &ds) const { ds << channelNumber; }
    void unpack(QDataStream &ds) { ds >> channelNumber; }
};

struct MakeChannelResponse: public CommonHeader
{
    MakeChannelResponse(){command = 1;}
    bool success;
    void pack(QDataStream &ds) const { ds << success; }
    void unpack(QDataStream &ds) {ds >> success; }
};

struct DestroyChannelRequest: public CommonHeader
{
    DestroyChannelRequest(){command = 2;}
    quint32 channelNumber;
    void pack(QDataStream &ds) const { ds << channelNumber; }
    void unpack(QDataStream &ds) { ds >> channelNumber; }
};

struct DestroyChannelResponse: public CommonHeader
{
    DestroyChannelResponse(){command = 2;}
    bool success;
    void pack(QDataStream &ds) const { ds << success; }
    void unpack(QDataStream &ds) {ds >> success; }
};

const quint32 CommandChannelNumber = 0;
const quint32 DataChannelNumber = 1;

struct BaseDataChannelPrivate
{
    BaseDataChannelPrivate(DataChannelPole pole, BaseDataChannel *parent);
    virtual ~BaseDataChannelPrivate();

    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
    bool removeChannel(VirtualChannel *channel);

    virtual void close();
    virtual bool isBroken() const = 0;
    virtual bool sendPacketRaw(const QByteArray &packet) = 0;
    virtual bool sendPacketRawAsync(const QByteArray &packet, std::function<void()> callback) = 0;

    bool handleCommand(QByteArray &packet);
    bool handleRawPacket(QByteArray &packet);
    QByteArray packPacket(quint32 channelNumber, const QByteArray &packet);

    DataChannelPole pole;
    quint32 nextChannelNumber;
    quint64 nextRequestId;
    QMap<quint32, QSharedPointer<VirtualChannel>> pendingChannels;
    QMap<quint32, QWeakPointer<VirtualChannel>> subChannels;
    Queue<QByteArray> readingQueue;
    BaseDataChannel * const q_ptr;
    Q_DECLARE_PUBLIC(BaseDataChannel)

    static BaseDataChannelPrivate *getPrivateHelper(BaseDataChannel* q)
    {
        return q->d_func();
    }
};

struct WritingPacket
{
    QByteArray packet;
    std::function<void()> callback;
};

struct SocketChannelPrivate: public BaseDataChannelPrivate
{
    SocketChannelPrivate(QSocketNg *socket, DataChannelPole pole, SocketChannel *parent);
    virtual bool isBroken() const override;
    virtual void close() override;
    virtual bool sendPacketRaw(const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(const QByteArray &packet, std::function<void()> callback) override;

    QByteArray recvPacketRaw();
    void fetchPackets();
    void sendPacketsAsync();

    RLock writeLock;
    QSocketNg *socket;
    CoroutineGroup operations;
    Queue<WritingPacket> writingQueue;

    Q_DECLARE_PUBLIC(SocketChannel)
};

struct VirtualChannelPrivate: public BaseDataChannelPrivate
{
    VirtualChannelPrivate(BaseDataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent);
    virtual bool isBroken() const override;
    virtual void close() override;
    virtual bool sendPacketRaw(const QByteArray &packet) override;
    virtual bool sendPacketRawAsync(const QByteArray &packet, std::function<void()> callback) override;

    QPointer<BaseDataChannel> parentChannel;
    quint32 channelNumber;
    bool broken;
    Q_DECLARE_PUBLIC(VirtualChannel)
};


BaseDataChannelPrivate::BaseDataChannelPrivate(DataChannelPole pole, BaseDataChannel *parent)
    :pole(pole), nextRequestId(100), readingQueue(1024), q_ptr(parent)
{
    if(pole == DataChannelPole::NegativePole)
    {
        nextChannelNumber = 0xffffffff;
    }
    else
    {
        nextChannelNumber = 2;
    }
}

BaseDataChannelPrivate::~BaseDataChannelPrivate()
{
    close();
}

void BaseDataChannelPrivate::close()
{
    QMap<quint32, QSharedPointer<VirtualChannel>> t1 = pendingChannels;
    QMap<quint32, QWeakPointer<VirtualChannel>> t2 = subChannels;
    QMapIterator<quint32, QSharedPointer<VirtualChannel>> itor1(t1);
    while(itor1.hasNext())
    {
        itor1.next();
        QSharedPointer<VirtualChannel> channel = itor1.value();
        channel->close();
    }
    QMapIterator<quint32, QWeakPointer<VirtualChannel>> itor2(t2);
    while(itor2.hasNext())
    {
        itor2.next();
        QWeakPointer<VirtualChannel> channel = itor2.value();
        if(!channel.isNull())
            channel.data()->close();
    }
    pendingChannels.clear();
    subChannels.clear();
}

bool BaseDataChannelPrivate::handleRawPacket(QByteArray &packet)
{
    if(static_cast<quint32>(packet.size()) < sizeof(quint32))
    {
        return false;
    }
    quint32 channelNumber = qFromBigEndian<quint32>((uchar*) packet.data());
    packet.remove(0, sizeof(quint32));

    if(channelNumber == CommandChannelNumber)
    {
        return handleCommand(packet);
    }
    else if(channelNumber == DataChannelNumber)
    {
        readingQueue.put(packet);
        return true;
    }
    else
    {
        QWeakPointer<VirtualChannel> channel = subChannels.value(channelNumber);
        if(channel.isNull())
        {
            qDebug("got invalid channel number.");
            return false;
        }
        else
        {
            return channel.data()->d_func()->handleRawPacket(packet);
        }
    }
}

QSharedPointer<VirtualChannel> BaseDataChannelPrivate::getChannel(quint32 channelNumber)
{
    if(pendingChannels.contains(channelNumber))
    {
        QSharedPointer<VirtualChannel> channel = pendingChannels.take(channelNumber);
        subChannels.insert(channelNumber, channel);
        return channel;
    }
    return subChannels.value(channelNumber).toStrongRef();
}

QSharedPointer<VirtualChannel> BaseDataChannelPrivate::makeChannel()
{
    Q_Q(BaseDataChannel);
    nextChannelNumber += qint32(pole);
    quint32 channelNumber = nextChannelNumber;
    MakeChannelRequest request;
    request.channelNumber = channelNumber;
    request.requestId = nextRequestId++;
    sendPacketRawAsync(packPacket(CommandChannelNumber, pack(request)), noop);
    QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::PositivePole, channelNumber));
    subChannels.insert(channelNumber,channel);
    return channel;
}

bool BaseDataChannelPrivate::removeChannel(VirtualChannel *channel)
{
    QMutableMapIterator<quint32, QWeakPointer<VirtualChannel>> itor(subChannels);
    while(itor.hasNext())
    {
        QWeakPointer<VirtualChannel> subChannel = itor.next().value();
        if(!subChannel.isNull() && subChannel.data() == channel)
        {
            itor.remove();
            return true;
        }
    }
    return false;
}

bool BaseDataChannelPrivate::handleCommand(QByteArray &packet)
{
    Q_Q(BaseDataChannel);
    try
    {
        CommonHeader header = peekHeader(packet);
        switch(header.command)
        {
        case 1: // MakeChannel
        {
            MakeChannelRequest request = unpack<MakeChannelRequest>(packet);
            MakeChannelResponse response;
            response.requestId = request.requestId;
            if(subChannels.contains(request.channelNumber))
            {
                response.success = false;
                sendPacketRawAsync(packPacket(CommandChannelNumber, pack(response)), noop);
                qDebug() << "found duplicated channel number:" << request.channelNumber;
                return true;
            }
            response.success = true;
            sendPacketRawAsync(packPacket(CommandChannelNumber, pack(response)), noop);
            QSharedPointer<VirtualChannel> channel(new VirtualChannel(q, DataChannelPole::NegativePole, request.channelNumber));
            pendingChannels.insert(request.channelNumber, channel);
            return true;
        }
        case 2: // Destory Channel
        {
            DestroyChannelRequest request = unpack<DestroyChannelRequest>(packet);
            DestroyChannelResponse response;
            response.requestId = request.requestId;
            QWeakPointer<VirtualChannel> channel = subChannels.value(request.channelNumber);
            if(channel.isNull())
            {
                response.success = false;
                sendPacketRawAsync(packPacket(CommandChannelNumber, pack(response)), noop);
                qDebug() << "channel number is not found." << request.channelNumber;
                return true;
            }
            channel.data()->close();
            response.success = true;
            sendPacketRawAsync(packPacket(CommandChannelNumber, pack(response)), noop);
            return true;
        }
        default:
            return false;
        }
    }
    catch(DataPackException &e)
    {
        Q_UNUSED(e);
        qDebug("can not unpack packet while handling command.");
        return false;
    }
}

QByteArray BaseDataChannelPrivate::packPacket(quint32 channelNumber, const QByteArray &packet)
{
    if(static_cast<quint32>(packet.size()) > 0xffffffff)
    {
        qDebug("can not send packet large than 0xffffffff bytes.");
        return QByteArray();
    }
    const int headerSize = sizeof(quint32) + sizeof(quint32);
    char header[headerSize];

    qToBigEndian(channelNumber, (uchar*) header + 0);
    qToBigEndian(packet.size() + sizeof(quint32), (uchar*) header + sizeof(quint32));

    QByteArray buf;
    buf.reserve(headerSize + packet.size());
    buf.append(header, headerSize);
    buf.append(packet);
    return buf;
}


SocketChannelPrivate::SocketChannelPrivate(QSocketNg *socket, DataChannelPole pole, SocketChannel *parent)
    :BaseDataChannelPrivate(pole, parent), socket(socket), writingQueue(1024)
{
    operations.spawnWithName(QString::fromLatin1("readingCoroutine"), [this]{this->fetchPackets();});
    operations.spawnWithName(QString::fromLatin1("writingCoroutine"), [this]{this->sendPacketsAsync();});
}


void SocketChannelPrivate::fetchPackets()
{
    while(socket->isValid())
    {
        QByteArray packet = recvPacketRaw();
        if(packet.isEmpty())
        {
            close();
            return;
        }
        bool success = handleRawPacket(packet);
        if(!success)
        {
            close();
            return;
        }
    }
}

void SocketChannelPrivate::sendPacketsAsync()
{
    while(socket->isValid())
    {
        const WritingPacket &writingPacket = writingQueue.get();
        if(!sendPacketRaw(writingPacket.packet))
            return;
        writingPacket.callback();
    }
}

void SocketChannelPrivate::close()
{
    operations.killall();
    socket->close();
    BaseDataChannelPrivate::close();
}

bool SocketChannelPrivate::isBroken() const
{
    return !socket->isValid();
}

bool SocketChannelPrivate::sendPacketRaw(const QByteArray &packet)
{
    ScopedLock<RLock> l(writeLock);
    Q_UNUSED(l);
    qint64 sent = socket->sendall(packet);
    return sent == packet.size();
}

bool SocketChannelPrivate::sendPacketRawAsync(const QByteArray &packet, std::function<void ()> callback)
{
    WritingPacket writingPacket = {packet, callback};
    writingQueue.put(writingPacket);
    return true;
}

QByteArray SocketChannelPrivate::recvPacketRaw()
{
    char header[sizeof(quint32)];
    qint64 n = socket->recv(header, sizeof(quint32));
    if(n < static_cast<qint64>(sizeof(quint32)))
    {
        return QByteArray();
    }
    quint32 packetSize = qFromBigEndian<quint32>((uchar*)header);

    QByteArray buf;
    buf.resize(packetSize);
    n = socket->recv(buf.data(), packetSize);
    if(n < packetSize)
    {
        return QByteArray();
    }
    return buf;
}

VirtualChannelPrivate::VirtualChannelPrivate(BaseDataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber, VirtualChannel *parent)
    :BaseDataChannelPrivate(pole, parent), parentChannel(parentChannel), channelNumber(channelNumber)
{

}

void VirtualChannelPrivate::close()
{
    Q_Q(VirtualChannel);
    broken = true;
    if(!parentChannel.isNull())
    {
        getPrivateHelper(parentChannel.data())->removeChannel(q);
    }
    BaseDataChannelPrivate::close();
}

bool VirtualChannelPrivate::isBroken() const
{
    return broken || parentChannel.isNull() || parentChannel->isBroken();
}

bool VirtualChannelPrivate::sendPacketRaw(const QByteArray &packet)
{
    Q_ASSERT(!parentChannel.isNull());
    return getPrivateHelper(parentChannel.data())->sendPacketRaw(packPacket(this->channelNumber, packet));
}

bool VirtualChannelPrivate::sendPacketRawAsync(const QByteArray &packet, std::function<void ()> callback)
{
    Q_ASSERT(!parentChannel.isNull());
    return getPrivateHelper(parentChannel.data())->sendPacketRawAsync(packPacket(this->channelNumber, packet), callback);
}

SocketChannel::SocketChannel(QSocketNg *socket, DataChannelPole pole)
    :BaseDataChannel(new SocketChannelPrivate(socket, pole, this))
{

}

VirtualChannel::VirtualChannel(BaseDataChannel *parentChannel, DataChannelPole pole, quint32 channelNumber)
    :BaseDataChannel(new VirtualChannelPrivate(parentChannel, pole, channelNumber, this))
{

}

BaseDataChannel::BaseDataChannel(BaseDataChannelPrivate *d)
    :d_ptr(d)
{
}

BaseDataChannel::~BaseDataChannel()
{
    delete d_ptr;
}


bool BaseDataChannel::isBroken() const
{
    const Q_D(BaseDataChannel);
    return d->isBroken();
}

bool BaseDataChannel::sendPacket(const QByteArray &packet)
{
    Q_D(BaseDataChannel);
    if(d->isBroken())
        return false;
    return d->sendPacketRaw(d->packPacket(DataChannelNumber, packet));
}

bool BaseDataChannel::sendPacketAsync(const QByteArray &packet, std::function<void ()> callback)
{
    Q_D(BaseDataChannel);
    if(d->isBroken())
        return false;
    return d->sendPacketRawAsync(d->packPacket(DataChannelNumber, packet), callback);
}

QByteArray BaseDataChannel::recvPacket()
{
    Q_D(BaseDataChannel);
    if(d->isBroken() && d->readingQueue.isEmpty())
        return QByteArray();
    return d->readingQueue.get();
}

void BaseDataChannel::close()
{
    Q_D(BaseDataChannel);
    d->close();
}

QSharedPointer<VirtualChannel> BaseDataChannel::makeChannel()
{
    Q_D(BaseDataChannel);
    if(d->isBroken())
        return QSharedPointer<VirtualChannel>();
    return d->makeChannel();
}

QSharedPointer<VirtualChannel> BaseDataChannel::getChannel(quint32 channelNumber)
{
    Q_D(BaseDataChannel);
    if(d->isBroken())
        return QSharedPointer<VirtualChannel>();
    return d->getChannel(channelNumber);
}
