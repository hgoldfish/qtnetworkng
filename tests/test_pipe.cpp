#include <QtTest>
#include "../qtnetworkng.h"

using namespace qtng;

class TestPipe : public QObject
{
    Q_OBJECT
private slots:
    void testBasic();
};

const char test_str[] = "fish is here.";

void TestPipe::testBasic()
{
    QSharedPointer<Pipe> pipe = QSharedPointer<Pipe>::create();
    CoroutineGroup workers;
    workers.spawn([pipe] {
        QSharedPointer<FileLike> f = pipe->fileToWrite();
        for (int i = 0; i < 100; ++i)
            f->write(test_str, sizeof(test_str));
    });
    workers.spawn([pipe] {
        QSharedPointer<QIODevice> d = pipe->deviceToRead();
        d->waitForReadyRead(-1);
        QVERIFY(d->read(2048).size() == (sizeof(test_str) * 100));
    });
    workers.joinall();
}

QTEST_MAIN(TestPipe)
#include "test_pipe.moc"
