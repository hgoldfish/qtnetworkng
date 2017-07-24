#include <QDebug>
#include <QCoreApplication>
#include <QList>
#include "socket_ng.h"
#include "http_ng.h"
#include "coroutine_utils.h"

class GetBaiduCoroutine: public QCoroutine
{
public:
    GetBaiduCoroutine(Session *session);
    virtual void run();
private:
    Session *session;
};


GetBaiduCoroutine::GetBaiduCoroutine(Session *session)
    :session(session) {}


void GetBaiduCoroutine::run()
{
    //QTimeout out(1000);
    //Q_UNUSED(out);
    qDebug() << "start coroutine";
    try{
        Response response = session->get(QString::fromUtf8("http://news.baidu.com/"));
        //Response response = session->get(QString::fromUtf8("http://127.0.0.1:8000/"));
        qDebug() << response.html();
    } catch(RequestException &e) {
        qDebug() << "got exception: " << e.what();
    }

}

class SleepCoroutine: public QCoroutine
{
public:
    virtual void run();
};

void SleepCoroutine::run()
{
    sleep(1000);
    qDebug() << this << 1;
    sleep(1000);
    qDebug() << this << 2;
    sleep(1000);
    qDebug() << this << 3;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    CoroutineGroup operations;
    Session session;
    for(int i = 0; i < 3; ++i)
    {
        QCoroutine *coroutine = new GetBaiduCoroutine(&session);
        //QCoroutine *coroutine = new SleepCoroutine();
        coroutine->setObjectName(QString::fromUtf8("get_baidu_%1").arg(i + 1));
        operations.add(coroutine);
        coroutine->start();
    }
    operations.joinall();
    return 0;
}
