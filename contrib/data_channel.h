#ifndef DATA_CHANNEL_H
#define DATA_CHANNEL_H

#include <QObject>
#include <QSharedPointer>
#include "socket_ng.h"

void noop();

enum DataChannelPole {
    PositivePole = 1,
    NegativePole = -1
};

class VirtualChannel;

class BaseDataChannelPrivate;
class BaseDataChannel: public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(BaseDataChannel)
public:
    virtual ~BaseDataChannel();
public:
    bool isBroken() const;
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet, std::function<void()> callback = noop);
    QByteArray recvPacket();
    void close();
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
    void setBufferSize(int bufferSize);
protected:
    BaseDataChannel(BaseDataChannelPrivate *d);
    BaseDataChannelPrivate * const d_ptr;
private:
    Q_DECLARE_PRIVATE(BaseDataChannel)
};

class SocketChannelPrivate;
class SocketChannel: public BaseDataChannel
{
    Q_OBJECT
    Q_DISABLE_COPY(SocketChannel)
public:
    SocketChannel(QSocketNg *socket, DataChannelPole pole);
private:
    Q_DECLARE_PRIVATE(SocketChannel)
};

class VirtualChannelPrivate;
class VirtualChannel: public BaseDataChannel
{
    Q_OBJECT
    Q_DISABLE_COPY(VirtualChannel)
protected:
    VirtualChannel(BaseDataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber);
private:
    Q_DECLARE_PRIVATE(VirtualChannel)
    friend class BaseDataChannelPrivate;
};

#endif // DATA_CHANNEL_H
