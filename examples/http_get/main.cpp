#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("http://news.163.com/");
    qDebug() << r.html();
    return 0;
}
