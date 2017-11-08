#include <QDebug>
#include <QCoreApplication>
#include <QList>
#include <QTime>
#include "qtnetworkng.h"

class GetNeteaseCoroutine: public QCoroutine
{
public:
    GetNeteaseCoroutine(Session *session);
    virtual void run();
private:
    Session *session;
};


GetNeteaseCoroutine::GetNeteaseCoroutine(Session *session)
    :session(session) {}


void GetNeteaseCoroutine::run()
{
    QTimeout out(5000);Q_UNUSED(out);
    try{
        Response response = session->get(QString::fromUtf8("http://www.163.com/"));
        qDebug() << response.html();
    } catch(RequestException &e) {
        qDebug() << "got exception: " << e.what();
    }

}



int get_netease(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    CoroutineGroup operations;
    Session session;

    for(int i = 0; i < 500; ++i)
    {
        QCoroutine *coroutine = new GetNeteaseCoroutine(&session);
        coroutine->setObjectName(QString::fromUtf8("get_netease_%1").arg(i + 1));
        operations.add(coroutine);
        coroutine->start();
    }
    operations.joinall();
    qDebug() << operations.size();
    return 0;
}
