#ifndef QTNG_DATA_CHANNEL_H
#define QTNG_DATA_CHANNEL_H

#include <QtCore/qobject.h>
#include <QtCore/qsharedpointer.h>
#include "socket.h"
#include "socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

enum DataChannelPole {
    PositivePole = 1,
    NegativePole = -1,
};

enum SystemChannelNubmer {
    CommandChannelNumber = 0,
    DataChannelNumber = 1,
};


class VirtualChannel;
class DataChannelPrivate;
class DataChannel: public QObject
{
    Q_DISABLE_COPY(DataChannel)
public:
    DataChannel(DataChannelPrivate *d);
    virtual ~DataChannel();
public:
    QString toString() const;
    void setMaxPacketSize(quint32 size);
    quint32 maxPacketSize() const;                      // packet with size > maxPacketSize is an error.
    void setPayloadSizeHint(quint32 payloadSizeHint);   // usually set to tcp/udp mtu.
    quint32 payloadSizeHint() const;                    // should be <= maxPacketSize - headerSize
    void setCapacity(quint32 packets);                  // channel blocked if there are n packets not read.
    quint32 capacity() const;                           // so, a data channel may consume `maxPacketSize * capacity` bytes of receiving buffer memory.
    quint32 receivingQueueSize() const;
    DataChannelPole pole() const;
    void setName(const QString &name);
    QString name() const;
    QString errorString() const;

    bool isBroken() const;
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet);
    QByteArray recvPacket();
    void abort();
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> takeChannel();
    QSharedPointer<VirtualChannel> takeChannel(quint32 channelNumber);
protected:
    DataChannelPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(DataChannel)
};


class SocketChannelPrivate;
class SocketChannel: public DataChannel
{
    Q_DISABLE_COPY(SocketChannel)
public:
    SocketChannel(QSharedPointer<Socket> socket, DataChannelPole pole);
#ifndef QTNG_NO_CRYPTO
    SocketChannel(QSharedPointer<class SslSocket> socket, DataChannelPole pole);
#endif
    SocketChannel(QSharedPointer<KcpSocket> socket, DataChannelPole pole);
    SocketChannel(QSharedPointer<SocketLike> socket, DataChannelPole pole);
public:
    void setKeepaliveTimeout(float timeout);
    float keepaliveTimeout() const;
    quint32 sendingQueueSize() const;
private:
    Q_DECLARE_PRIVATE(SocketChannel)
};


class VirtualChannelPrivate;
class VirtualChannel: public DataChannel
{
    Q_DISABLE_COPY(VirtualChannel)
public:
    quint32 channelNumber() const;
protected:
    VirtualChannel(DataChannel* parentChannel, DataChannelPole pole, quint32 channelNumber);
private:
    Q_DECLARE_PRIVATE(VirtualChannel)
    friend class DataChannelPrivate;
    friend class SocketChannelPrivate;
};


void exchange(QSharedPointer<DataChannel> incoming, QSharedPointer<DataChannel> outgoing);


QSharedPointer<SocketLike> asSocketLike(QSharedPointer<DataChannel> channel);


inline QSharedPointer<SocketLike> asSocketLike(QSharedPointer<VirtualChannel> channel)
{
    return asSocketLike(channel.dynamicCast<DataChannel>());
}


inline QSharedPointer<SocketLike> asSocketLike(QSharedPointer<SocketChannel> channel)
{
    return asSocketLike(channel.dynamicCast<DataChannel>());
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_DATA_CHANNEL_H
