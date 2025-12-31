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
    void testPeekMultiThread();
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

void TestThreadQueue::testPeekMultiThread()
{
    QSharedPointer<ThreadQueue<QByteArray>> queue(new ThreadQueue<QByteArray>(1024));
    QAtomicInt peekEmptyCount(0);
    QAtomicInt peekNoneEmptyCount(0);
    QAtomicInt running(1);

    const int ProducerNumber = 1;
    const int PeekerNumber = 8;
    const int ConsumerNumber = 1;
    const int Blocks = 1000000;

    // peek 线程：不断调用 peek 接口
    QList<QSharedPointer<QThread>> peekers;
    for (int i = 0; i < PeekerNumber; ++i) {
        QSharedPointer<QThread> peeker(QThread::create([queue, &peekNoneEmptyCount, &peekEmptyCount, &running] {
            while (running.loadAcquire()) {
                int count = queue->peek().size();
                if (count > 0) {
                    peekNoneEmptyCount.fetchAndAddRelaxed(1);
                } else {
                    peekEmptyCount.fetchAndAddRelaxed(1);
                }
            }
        }));
        peeker->start();
        peekers.append(peeker);
    }

    // 消费者线程：不断从队列中取出数据
    QList<QSharedPointer<QThread>> consumers;
    for (int i = 0; i < ConsumerNumber; ++i) {
        QSharedPointer<QThread> consumer(QThread::create([queue, Blocks] {
            while (true) {
                QByteArray e = queue->get();
                if (e.isNull()) {
                    break;
                }
            }
            queue->put(QByteArray());
        }));
        consumer->start();
        consumers.append(consumer);
    }

    // 生产者线程：不断向队列中添加数据
    QList<QSharedPointer<QThread>> producers;
    for (int i = 0; i < ProducerNumber; ++i) {
        int base = i * Blocks;
        QSharedPointer<QThread> producer(QThread::create([Blocks, queue, base] {
            for (int j = 0; j < Blocks; ++j) {
                queue->put(QByteArray::number(base + j));
                if (j % 1000 == 0) {
                    Coroutine::msleep(1);
                }
            }
        }));
        producer->start();
        producers.append(producer);
    }

    // 等待所有生产者完成
    for (const auto &producer : producers) {
        producer->wait();
    }
    for (const auto &producer : producers) {
        queue->put(QByteArray());
    }

    // 等待所有消费者完成
    for (const auto &consumer : consumers) {
        consumer->wait();
    }

    // 停止 peeker 线程
    running.storeRelease(0);
    for (const auto &peeker : peekers) {
        peeker->wait();
    }

    qDebug() << "Peek NoneEmpty count:" << peekNoneEmptyCount.loadAcquire();
    qDebug() << "Peek Empty count:" << peekEmptyCount.loadAcquire();
}

QTEST_MAIN(TestThreadQueue)
#include "test_threadqueue.moc"
