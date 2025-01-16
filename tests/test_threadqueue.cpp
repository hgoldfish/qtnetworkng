#include <QtTest>
#include "qtnetworkng.h"


using namespace qtng;

class TestThreadQueue: public QObject
{
    Q_OBJECT
private slots:
    void testBasic();
    void testMultiProducer();
    void testCoroutineConsumer();
};


void TestThreadQueue::testBasic()
{
    QSharedPointer<ThreadQueue<QByteArray>> queue(new ThreadQueue<QByteArray>(8));
    QScopedPointer<QThread> producer(QThread::create([queue] {
        for (int i = 0; i < 100; ++i) {
            queue->put(QByteArray::number(i));
        }
    }));
    QSharedPointer<Event> done = QSharedPointer<Event>::create();
    QScopedPointer<QThread> consumer(QThread::create([queue, done] {
        for (int i = 0; i < 100; ++i) {
            const QByteArray &e = queue->get();
            if (e != QByteArray::number(i)) {
                return;
            }
        }
        done->set();
    }));

    producer->start();
    consumer->start();
    producer->wait();
    consumer->wait();
    QVERIFY(done->isSet());
}


void TestThreadQueue::testMultiProducer()
{
    QSharedPointer<ThreadQueue<QByteArray>> queue(new ThreadQueue<QByteArray>(8));
    QList<QSharedPointer<QThread>> producers;

    const int ProducerNumber = 100;
    const int Blocks = 1000;

    for (int i = 0; i < ProducerNumber; ++i) {
        int base = i * Blocks;
        QSharedPointer<QThread> producer(QThread::create([Blocks, queue, base] {
            for (int i = 0; i < Blocks; ++i) {
                queue->put(QByteArray::number(base + i));
            }
        }));
        producer->start();
        producers.append(producer);
    }

    QSharedPointer<Event> done = QSharedPointer<Event>::create();
    QScopedPointer<QThread> consumer(QThread::create([ProducerNumber, Blocks, queue, done] {
        for (int i = 0; i < ProducerNumber * Blocks; ++i) {
            const QByteArray &e = queue->get();
            if (e.isNull()) {
                return;
            }
        }
        done->set();
    }));
    consumer->start();

    for (int i = 0; i < ProducerNumber; ++i) {
        producers.at(i)->wait();
    }
    consumer->wait();
    QVERIFY(done->isSet());
}


void TestThreadQueue::testCoroutineConsumer()
{
    QSharedPointer<ThreadQueue<QByteArray>> queue(new ThreadQueue<QByteArray>(8));
    QList<QSharedPointer<Event>> producers;

    const int ProducerNumber = 100;
    const int Blocks = 1000;

    for (int i = 0; i < ProducerNumber; ++i) {
        int base = i * Blocks;
        QSharedPointer<Event> producer = spawnInThread([Blocks, queue, base] {
            for (int i = 0; i < Blocks; ++i) {
                queue->put(QByteArray::number(base + i));
            }
        });
        producers.append(producer);
    }

    QSharedPointer<Event> done = QSharedPointer<Event>::create();
    QScopedPointer<Coroutine> consumer(Coroutine::spawn([ProducerNumber, Blocks, queue, done] {
        for (int i = 0; i < ProducerNumber * Blocks; ++i) {
            const QByteArray &e = queue->get();
            if (e.isNull()) {
                return;
            }
        }
        done->set();
    }));

    consumer->join();
    for (int i = 0; i < ProducerNumber; ++i) {
        producers.at(i)->tryWait();
    }

    QVERIFY(done->isSet());
}

QTEST_MAIN(TestThreadQueue)
#include "test_threadqueue.moc"
