#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

int main()
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("http://news.163.com/");
    qDebug() << r.html();
    return 0;
}
