#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

using namespace qtng;

class HttpServer: public TcpServer<SimpleHttpRequestHandler>
{
public:
    HttpServer(const QHostAddress &serverAddress, quint16 serverPort)
        :TcpServer(serverAddress, serverPort) {}
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    HttpServer httpd(QHostAddress(QHostAddress::Any), 8000);
    httpd.serveForever();
    return 0;
}
