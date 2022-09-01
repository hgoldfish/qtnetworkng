#include "qtnetworkng.h"

using namespace qtng;

void output(QSharedPointer<RLock> lock, const QString &name)
{
    ScopedLock<RLock> l(*lock);    // acquire lock now, release before function returns. comment out this line and try again later.
    qDebug() << name << 1;
    Coroutine::sleep(1.0);
    qDebug() << name << 2;
}


int main(int argc, char **argv)
{
    QSharedPointer<RLock> lock(new RLock);
    CoroutineGroup operations;
    operations.spawn([lock]{
        output(lock, "first");
    });
    operations.spawn([lock]{
        output(lock, "second");
    });
    operations.joinall();
    return 0;
}
