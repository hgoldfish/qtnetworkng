#include <QtCore/qdebug.h>
#include "qtnetworkng.h"

int main(int argc, char **argv)
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("https://news.163.com/");
    if (r.isOk()) {
        qDebug() << r.html();
    } else {
        qDebug() << r.error()->what();
    }
    return 0;
}
