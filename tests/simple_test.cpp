#include <QDebug>
#include <QCoreApplication>
#include <QList>
#include <QTime>
#include "qtnetworkng.h"

class GetNeteaseCoroutine: public qtng::QCoroutine
{
public:
    GetNeteaseCoroutine(qtng::HttpSession *session);
    virtual void run();
private:
    qtng::HttpSession *session;
};


GetNeteaseCoroutine::GetNeteaseCoroutine(qtng::HttpSession *session)
    :session(session) {}


void GetNeteaseCoroutine::run()
{
    qtng::QTimeout out(5000);Q_UNUSED(out);
    try{
        qtng::HttpResponse response = session->get(QStringLiteral("https://www.baidu.com/"));
        qDebug() << response.html();
    } catch(qtng::RequestException &e) {
        qDebug() << "got exception: " << e.what();
    }

}



int get_baidu(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    qtng::CoroutineGroup operations;
    qtng::HttpSession session;

    for(int i = 0; i < 500; ++i)
    {
        qtng::QCoroutine *coroutine = new GetNeteaseCoroutine(&session);
        coroutine->setObjectName(QString::fromUtf8("get_baidu%1").arg(i + 1));
        operations.add(coroutine);
        coroutine->start();
    }
    operations.joinall();
    qDebug() << operations.size();
    return 0;
}
