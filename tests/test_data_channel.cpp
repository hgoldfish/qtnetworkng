#include <QCoreApplication>
#include <QDebug>
#include "qtnetworkng.h"


class ServerCoroutine: public qtng::QCoroutine
{
public:
    ServerCoroutine()
    {
        setObjectName("server");
    }

    ~ServerCoroutine()
    {
//        qDebug() << "delete server.";
    }

    virtual void run()
    {
        qtng::QSocketNg server;
        bool success = server.bind((quint16)7923, qtng::QSocketNg::ReuseAddressHint);
        if(!success) {
            qDebug() << "port is used.";
            return;
        }
        server.listen(5);
        qtng::QSocketNg *request = server.accept();
        if(!request) {
            qDebug() << "bad request.";
            return;
        }
        qtng::SocketChannel channel(QSharedPointer<qtng::QSocketNg>(request), qtng::NegativePole);
        channel.setName("server_channel");
        QByteArray t = channel.recvPacket();
        quint32 channelNumber = t.toUInt();
        qDebug() << "got subchannel number:" << channelNumber;
        QSharedPointer<qtng::VirtualChannel> subChannel = channel.getChannel(channelNumber);
        if(subChannel.isNull()) {
            return;
        }
        qDebug() << "exit server.";
        return;
//        channel.close();
        while(true) {
            const QByteArray &packet = subChannel->recvPacket();
            if(packet.isEmpty()) {
                break;
            }
            qDebug() << packet;
        }
    }
};


class ClientCoroutine: public qtng::QCoroutine
{
public:
    ClientCoroutine()
    {
        setObjectName("client");
    }

    virtual void run()
    {
        QSharedPointer<qtng::QSocketNg> client = QSharedPointer<qtng::QSocketNg>::create();
        bool success = client->connect(QHostAddress::LocalHost, 7923);
        if(!success) {
            return;
        }
        qtng::SocketChannel channel(client, qtng::PositivePole);
        channel.setName("client_channel");
        QSharedPointer<qtng::VirtualChannel> subChannel = channel.makeChannel();
        channel.sendPacket(QByteArray::number(subChannel->channelNumber()));
        for(int i = 0; i < 5; ++i) {
            success = subChannel->sendPacket(QByteArray::number(i));
            if(!success) {
                qDebug() << "exit client.";
                return;
            }
        }
        success = subChannel->sendPacket(QByteArray());
        qDebug() << "exit client.";
    }
};

int main(int argc, char** argv) //simple_data_channel
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    qtng::CoroutineGroup operations;
    operations.start(new ServerCoroutine);
    operations.start(new ClientCoroutine);
    operations.joinall();
    return 0;
}
