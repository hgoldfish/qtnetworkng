#include <QtCore/qcoreapplication.h>
#include "qtnetworkng.h"

using namespace qtng;

class WebSocketRequestHandler : public BaseHttpRequestHandler
{
public:
    virtual void doGET() override;
};

void WebSocketRequestHandler::doGET()
{
    if (path != QString::fromUtf8("/")) {
        sendError(HttpStatus::NotFound);
        return;
    }
    if (!switchToWebSocket()) {
        sendError(HttpStatus::NotImplemented);
        return;
    }
    qDebug() << webSocketProtocols();
    endHeader();

    WebSocketConnection conn(request, body, WebSocketConnection::Server);
    conn.setDebugLevel(1);
    WebSocketConnection::FrameType type;
    while (true) {
        const QByteArray &packet = conn.recv(&type);
        if (packet.isEmpty()) {
            qDebug() << "received empty packet.";
            return;
        }
        qDebug() << type << packet;
        if (type == WebSocketConnection::Binary) {
            if (!conn.send(packet)) {
                qDebug() << "can not send echo packet.";
                return;
            }
        } else {
            Q_ASSERT(WebSocketConnection::Text);
            if (!conn.send(QString::fromUtf8(packet))) {
                qDebug() << "can not send echo packet.";
                return;
            }
        }
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TcpServer<WebSocketRequestHandler> httpd(HostAddress::AnyIPv4, 8765);
    return httpd.serveForever() ? 0 : 1;
}
