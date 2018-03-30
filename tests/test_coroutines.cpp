#include <QtTest>
#include "qtnetworkng.h"

using namespace qtng;

class TestCoroutines: public QObject
{
    Q_OBJECT
private slots:
    void testStart();
    void testKill();
    void testKillall();
};


void TestCoroutines::testStart()
{
    QSharedPointer<Event> event(new Event);
    QSharedPointer<Coroutine> c(Coroutine::spawn([event]{
        event->set();
    }));
    c->join();
    QVERIFY(event->isSet());
}

void TestCoroutines::testKill()
{
    QSharedPointer<Event> event(new Event);
    QSharedPointer<Coroutine> c(Coroutine::spawn([event]{
        Coroutine::sleep(100);
        event->set();
    }));
    Coroutine::sleep(10);
    c->kill();
    c->join();
    QVERIFY(!event->isSet());
}

void TestCoroutines::testKillall()
{
    CoroutineGroup operations;
    operations.spawn([]{
        Coroutine::sleep(100);
    });
    Coroutine::sleep(10);
    operations.killall();
    QVERIFY(operations.isEmpty());
}

//QTEST_MAIN(TestCoroutines)

#include "test_coroutines.moc"
