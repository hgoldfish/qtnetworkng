#include <QtCore/QCoreApplication>
#include "qtnetworkng.h"

int main()
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("http://news.163.com/");
    if (r.isOk()) {
        qDebug() << r.html();
    } else {
        qDebug() << r.error()->what();
    }
    return 0;
}
