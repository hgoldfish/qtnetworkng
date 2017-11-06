#include <QDebug>
#include <QCoreApplication>
#include <QList>
#include <QTime>
#include "qtnetworkng.h"

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
//    QTimeout out(5000);Q_UNUSED(out);

    qDebug() << "start coroutine";
    try{
        //Response response = session->get(QString::fromUtf8("http://news.baidu.com/"));
        Response response = session->get(QString::fromUtf8("http://127.0.0.1/"));
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
    session.setMaxConnectionsPerServer(0);

    QList<int> l;
    for(int i = 0; i < 100; ++i) {
        l.append(i);
    }

    quint64 total = 0;
    Semaphore semp(500);
    QTime timer;
    timer.start();
    while(true) {
        semp.acquire();
        total += 1;
        operations.spawn([&session, &semp, &timer, total] {
            try {
                Response response = session.get(QString::fromUtf8("http://127.0.0.1:8000/"));
                float rps = total * 1.0 / timer.elapsed() * 1000;
                //qDebug() << total << ":" << rps << response.html();
            } catch (RequestException &e) {
                //qDebug() << total << ":" << "failed";
            }
            semp.release();
        });
    }

//    for(int i = 0; i < 500; ++i)
//    {
//        QCoroutine *coroutine = new GetBaiduCoroutine(&session);
////        QCoroutine *coroutine = new SleepCoroutine();
//        coroutine->setObjectName(QString::fromUtf8("get_baidu_%1").arg(i + 1));
//        operations.add(coroutine);
//        coroutine->start();
//        coroutine->join();
//    }
//    operations.joinall();
//    qDebug() << operations.size();
    return 0;
}
