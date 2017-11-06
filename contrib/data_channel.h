#ifndef DATA_CHANNEL_H
#define DATA_CHANNEL_H

#include <QObject>
#include <QSharedPointer>
#include "../include/socket_ng.h"

enum DataChannelPole {
    PositivePole = 1,
    NegativePole = -1,
};

enum SystemChannelNubmer {
    CommandChannelNumber = 0,
    DataChannelNumber = 1,
};

class DisconnectedException: public std::exception {};

class VirtualChannel;
class DataChannelPrivate;

class DataChannel: public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(DataChannel)

public:
    DataChannel(DataChannelPrivate *d);
    virtual ~DataChannel();
public:
    QString toString() const;
    void setMaxPacketSize(int size);
    int maxPacketSize() const;
    void setCapacity(int capacity);
    int capacity();
    DataChannelPole pole() const;

    bool isBroken() const;
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet);
    QByteArray recvPacket();
    void close();
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
protected:
    Q_DECLARE_PRIVATE(DataChannel)
    DataChannelPrivate * const d_ptr;
};

class SocketChannelPrivate;
class SocketChannel: public DataChannel
{
    Q_OBJECT
    Q_DISABLE_COPY(SocketChannel)
public:
    SocketChannel(QSocketNg *socket, DataChannelPole pole);
private:
    Q_DECLARE_PRIVATE(SocketChannel)
};

class VirtualChannelPrivate;
class VirtualChannel: public DataChannel
{
    Q_OBJECT
    Q_DISABLE_COPY(VirtualChannel)
protected:
    VirtualChannel(DataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber);
private:
    Q_DECLARE_PRIVATE(VirtualChannel)
    friend class DataChannelPrivate;
    friend class SocketChannelPrivate;
};

#endif // DATA_CHANNEL_H
