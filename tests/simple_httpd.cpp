#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    SimpleHttpServer httpd(HostAddress(HostAddress::Any), 8000);
    httpd.serveForever();
    return 0;
}
