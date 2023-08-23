#include <QtCore/qcoreapplication.h>
#include "../qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    HttpSession session;
    session.setDebugLevel(1);
    WebSocketConfiguration config;
    config.setProtocols(QStringList() << "chat");
    QSharedPointer<WebSocketConnection> req = session.ws("ws://localhost:8765");
    if (req.isNull()) {
        qDebug() << "can not connect to localhost.";
        return 1;
    }
    QStringList longTextList;
    for (int i = 0; i < 1; ++i)
        longTextList.append(QString::fromUtf8("fish is here."));
    const QString &s = longTextList.join(QString());
    for (int i = 0; i < 10; ++i) {
        bool ok = req->send(s);
        if (!ok) {
            qDebug() << "can not send packet.";
            return 2;
        }
        WebSocketConnection::FrameType type;
        const QByteArray &packet = req->recv(&type);
        if (packet.isEmpty()) {
            qDebug() << "can not receive packet.";
            return 3;
        }
        qInfo() << "echo:" << packet;
    }
    req->close();
    return 0;
}
