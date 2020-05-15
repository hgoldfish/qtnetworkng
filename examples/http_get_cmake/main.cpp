#include "qtnetworkng.h"

int main(int argc, char **argv)
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("https://news.163.com/");
    qDebug() << r.html();
    return 0;
}
