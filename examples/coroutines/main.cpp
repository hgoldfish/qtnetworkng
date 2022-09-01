#include <QtCore/qcoreapplication.h>
#include "qtnetworkng.h"


using namespace qtng;


struct MyCoroutine: public Coroutine
{
    MyCoroutine(const QString &name)
        : name(name) {}
    void run() override {
        for (int i = 0; i < 3; ++i) {
            qDebug() << name << i;
            // switch to eventloop coroutine, will switch back in 100 ms.
            msleep(100);
        }
    }
    QString name;
};


int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    MyCoroutine coroutine1("coroutine1");
    MyCoroutine coroutine2("coroutine2");
    coroutine1.start();
    coroutine2.start();
    // switch to the main coroutine
    coroutine1.join();
    // switch to the second coroutine to finish it.
    coroutine2.join();
    return 0;
}
