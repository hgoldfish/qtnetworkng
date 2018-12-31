#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    SimpleHttpsServer httpd(QHostAddress(QHostAddress::Any), 8000);
    httpd.serveForever();
    return 0;
}
