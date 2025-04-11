#include <QtTest>
#include "../qtnetworkng.h"

using namespace qtng;

class TestLmdb : public QObject
{
    QString dbPath;
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();
    // void testBaisc();
    void testReserve();
    void testPut();
protected:
    QSharedPointer<Lmdb> db;
};

void TestLmdb::initTestCase()
{
    dbPath = QDir::currentPath() + "/test";
    qDebug() << dbPath;
    db = LmdbBuilder(dbPath).maxMapSize(1 << 30).maxReaders(10).writeMap(true).create();
    QVERIFY(db);
}

void TestLmdb::cleanupTestCase()
{
    db.clear();
    QFile::remove(dbPath);
    QFile::remove(dbPath + "-lock");
}

/*
void TestLmdb::testBaisc()
{
    class SimpleClass {
    public:
        int a = 0;
        int b = 0;
    };
    int a = QRandomGenerator::global()->bounded(10000);
    int b = QRandomGenerator::global()->bounded(10000);
    {
        QSharedPointer<Transaction> transaction = db->toWrite();
        QVERIFY(transaction);
        Database &db = transaction->db("test");
        Database::iterator it = db.reserve("simple_class", sizeof(SimpleClass));
        QVERIFY(!!it);
        SimpleClass *simple = new(it.data())SimpleClass();
        simple->a = a;
        simple->b = b;
        transaction->commit();
    }
    {
        QSharedPointer<const Transaction> transaction = db->toRead();
        QVERIFY(transaction);
        const Database &db = transaction->db("test");
        Database::const_iterator it = db.find("simple_class");
        QVERIFY(!!it);
        SimpleClass *simple = (SimpleClass *)it.data();
        QCOMPARE(simple->a, a);
        QCOMPARE(simple->b, b);
    }
}
*/

void TestLmdb::testReserve()
{
    QSharedPointer<Transaction> transaction = db->toWrite();
    QVERIFY(transaction);
    Database &db = transaction->db("test-reserve");
    QSet<char *> addrList;
    QByteArray v(1024, 't');
    for (int i = 0; i < 1024 * 64; ++i) {
        const QByteArray &k = QByteArray::number(i);
        Database::iterator itor = db.reserve(k, v.size());
        QVERIFY(!!itor);
        char *addr = itor.data();
        memcpy(addr, k.constData(), k.size());
        // QVERIFY(!addrList.contains(addr));
        //        if (addrList.contains(addr)) {
        //            qDebug() << reinterpret_cast<qint64>(addr);
        //        }
        addrList.insert(addr);
    }
    qDebug() << addrList.size();
    for (int i = 0; i < 1024 * 64; ++i) {
        const QByteArray &k = QByteArray::number(i);
        Database::iterator itor = db.find(k);
        QVERIFY(QByteArray(itor.data(), k.size()) == k);
    }
    transaction->abort();
}

void TestLmdb::testPut()
{
    QSharedPointer<Transaction> transaction = db->toWrite();
    QVERIFY(transaction);
    Database &db = transaction->db("test-put");
    QMap<QByteArray, QByteArray> testData;
    QRandomGenerator *r = QRandomGenerator::global();
    for (int i = 0; i < 1024 * 64; ++i) {
        const QByteArray &k = QByteArray::number(i);
        const QByteArray &v = qtng::randomBytes(1024 - r->bounded(256));
        testData.insert(k, v);
        Database::iterator itor = db.reserve(k, v.size());
        QVERIFY(!!itor);
        memcpy(itor.data(), v.constData(), v.size());
    }
    for (int i = 0; i < 1024 * 64; ++i) {
        const QByteArray &k = QByteArray::number(i);
        Database::iterator itor = db.find(k);
        QVERIFY(!!itor);
        QVERIFY(itor.value() == testData.value(k));
    }
    transaction->abort();
}

QTEST_MAIN(TestLmdb)
#include "test_lmdb.moc"
