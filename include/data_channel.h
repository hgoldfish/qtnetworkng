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

class DisconnectedException: public std::exception {};

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
    void setMaxPacketSize(int size);
    int maxPacketSize() const;
    void setCapacity(int capacity);
    int capacity();
    DataChannelPole pole() const;
    void setName(const QString &name);
    QString name() const;

    bool isBroken() const;
    bool sendPacket(const QByteArray &packet);
    bool sendPacketAsync(const QByteArray &packet);
    QByteArray recvPacket();
    void close();
    QSharedPointer<VirtualChannel> makeChannel();
    QSharedPointer<VirtualChannel> takeChannel();
    QSharedPointer<VirtualChannel> getChannel(quint32 channelNumber);
protected:
    Q_DECLARE_PRIVATE(DataChannel)
    DataChannelPrivate * const d_ptr;
};

class SocketChannelPrivate;
class SocketChannel: public DataChannel
{
    Q_DISABLE_COPY(SocketChannel)
public:
    SocketChannel(QSharedPointer<Socket> socket, DataChannelPole pole);
#ifndef QTNG_NO_CRYPTO
    SocketChannel(QSharedPointer<SslSocket> socket, DataChannelPole pole);
#endif
    SocketChannel(QSharedPointer<KcpSocket> socket, DataChannelPole pole);
    SocketChannel(QSharedPointer<SocketLike> socket, DataChannelPole pole);
public:
    void setKeepaliveTimeout(float timeout);
    float keepaliveTimeout() const;
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

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_DATA_CHANNEL_H
