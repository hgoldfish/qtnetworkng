#include <QCoreApplication>
#include "qtnetworkng.h"

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


int sleep_coroutines(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    CoroutineGroup operations;
    operations.start(new SleepCoroutine);
    operations.joinall();
    return 0;
}
