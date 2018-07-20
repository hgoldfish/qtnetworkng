#include <QDebug>
#include <QList>
#include <QTime>
#include "qtnetworkng.h"

class GetNeteaseCoroutine: public qtng::Coroutine
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
    qtng::Timeout out(5000);Q_UNUSED(out);
    try{
        qtng::HttpResponse response = session->get("https://news.163.com/");
        qDebug() << response.html().size();
    } catch(qtng::RequestException &e) {
        qDebug() << "got exception: " << e.what();
    } catch(...) {
        qDebug() << "got unexpected exception.";
    }
}

int main(int argc, char *argv[])
{
    qtng::CoroutineGroup operations;
    qtng::HttpSession session;
    // session.setDebugLevel(2);

    for(int i = 0; i < 100; ++i) {
        qtng::Coroutine *coroutine = new GetNeteaseCoroutine(&session);
        coroutine->setObjectName(QStringLiteral("get_netease_%1").arg(i + 1));
        operations.add(coroutine);
        coroutine->start();
    }
    operations.joinall();
    return 0;
}
