#include <QCoreApplication>
#include "qtnetworkng.h"

class SleepCoroutine: public qtng::Coroutine
{
public:
    virtual void run();
};

void SleepCoroutine::run()
{
    sleep(1);
    qDebug() << this << 1;
    sleep(1);
    qDebug() << this << 2;
    sleep(1);
    qDebug() << this << 3;
}

int main(int argc, char **argv)
{
    qtng::CoroutineGroup operations;
    operations.start(new SleepCoroutine);
    operations.joinall();
    return 0;
}
