#include <QtCore/qdebug.h>
#include "qtnetworkng.h"

int main()
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("http://example.com/");
    if (r.isOk()) {
        qDebug() << r.html();
    } else {
        qDebug() << r.error()->what();
    }
    return 0;
}
