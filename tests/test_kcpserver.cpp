#include <QtCore/qcoreapplication.h>
#include <stdio.h>
#include "qtnetworkng.h"

using namespace qtng;

class QtL2Handler : public BaseRequestHandler
{
public:
    virtual void handle() override { qDebug() << "got request:" << request->peerAddressURI(); }
};

int main(int argc, char **argv)
{
    // comment out the next line to use more effective libev/libev-win instead of Qt eventloop.
    QCoreApplication app(argc, argv);
    KcpServer<QtL2Handler> server(HostAddress::AnyIPv4, 7943);
    return !server.serveForever();
    // the serveForever() equals the next two line.
    // server.start();
    // return startQtLoop();
}
