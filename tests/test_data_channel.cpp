#include <QCoreApplication>
#include <QDebug>
#include "qtnetworkng.h"


class ServerCoroutine: public QCoroutine
{
public:
    ServerCoroutine()
    {
        setObjectName("server");
    }

    ~ServerCoroutine()
    {
        qDebug() << "delete server.";
    }

    virtual void run()
    {
        QSocketNg server;
        bool success = server.bind((quint16)7923, QSocketNg::ReuseAddressHint);
        if(!success) {
            qDebug() << "port is used.";
            return;
        }
        server.listen(5);
        QSocketNg *request = server.accept();
        if(!request) {
            qDebug() << "bad request.";
            return;
        }
        SocketChannel channel(request, NegativePole);
        channel.setName("server_channel");
        QByteArray t = channel.recvPacket();
        quint32 channelNumber = t.toUInt();
        qDebug() << channelNumber;
        QSharedPointer<VirtualChannel> subChannel = channel.getChannel(channelNumber);
        if(subChannel.isNull()) {
            return;
        }
        while(true) {
            const QByteArray &packet = subChannel->recvPacket();
            if(packet.isEmpty()) {
                break;
            }
            qDebug() << packet;
        }
    }
};


class ClientCoroutine: public QCoroutine
{
public:
    ClientCoroutine()
    {
        setObjectName("client");
    }

    virtual void run()
    {
        QSocketNg *client = new QSocketNg();
        bool success = client->connect(QHostAddress::LocalHost, 7923);
        if(!success) {
            return;
        }
        SocketChannel channel(client, PositivePole);
        channel.setName("client_channel");
        QSharedPointer<VirtualChannel> subChannel = channel.makeChannel();
        channel.sendPacket(QByteArray::number(subChannel->channelNumber()));
        for(int i = 0; i < 5; ++i) {
            subChannel->sendPacket(QByteArray::number(i));
        }
        subChannel->sendPacket(QByteArray());
    }
};

int main(int argc, char** argv) //simple_data_channel
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    CoroutineGroup operations;
    operations.start(new ServerCoroutine);
    operations.start(new ClientCoroutine);
    operations.joinall();
    return 0;
}
