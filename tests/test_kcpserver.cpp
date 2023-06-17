#include <QtCore/qcoreapplication.h>
#include <QElapsedTimer>
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
    QCoreApplication app(argc, argv);
    KcpServer<QtL2Handler> server(HostAddress::LocalHost, 7943);
    server.start();
    return startQtLoop();
}
