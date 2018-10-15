#include <limits>
#include <QtTest>
#include "qtnetworkng.h"

using namespace qtng;

class TestMsgPack: public QObject
{
    Q_OBJECT
private slots:
    void testUInt8();
    void testInt8();
    void testUInt16();
    void testInt16();
    void testUInt32();
    void testInt32();
    void testUInt64();
    void testInt64();
    void testFloat();
    void testDouble();
    void testString();
    void testByteArray();
    void testDateTime();
};


void TestMsgPack::testUInt8()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        os << static_cast<quint8>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        quint8 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<quint16>(t), i);
    }
}


void TestMsgPack::testInt8()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        os << static_cast<qint8>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        qint8 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<qint16>(t), i);
    }
}

void TestMsgPack::testUInt16()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        os << static_cast<quint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint32 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        os << static_cast<quint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        quint16 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint32 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        quint16 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<quint32>(t), i);
    }
}


void TestMsgPack::testInt16()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        os << static_cast<qint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint32 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        os << static_cast<qint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        qint16 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint32 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        qint16 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<qint32>(t), i);
    }
}


void TestMsgPack::testUInt32()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        os << static_cast<quint32>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint32 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        os << static_cast<quint32>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint64 i = std::numeric_limits<quint32>::min(); i <= std::numeric_limits<quint32>::max(); i += 256 * 256) {
        os << static_cast<quint32>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (quint32 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        quint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint32 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        quint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint64 i = std::numeric_limits<quint32>::min(); i <= std::numeric_limits<quint32>::max(); i += 256 * 256) {
        quint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<quint64>(t), i);
    }
}


void TestMsgPack::testInt32()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        os << static_cast<qint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint32 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        os << static_cast<qint16>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint64 i = std::numeric_limits<qint32>::min(); i <= std::numeric_limits<qint32>::max(); i += 256 * 256) {
        os << static_cast<qint32>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (qint32 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        qint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint32 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        qint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint64 i = std::numeric_limits<qint32>::min(); i <= std::numeric_limits<qint32>::max(); i += 256 * 256) {
        qint32 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(static_cast<qint64>(t), i);
    }
}


void TestMsgPack::testUInt64()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (quint16 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        os << static_cast<quint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint32 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        os << static_cast<quint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint64 i = std::numeric_limits<quint32>::min(); i <= std::numeric_limits<quint32>::max(); i += 256 * 256) {
        os << static_cast<quint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (quint64 i = std::numeric_limits<quint64>::min(); i < std::numeric_limits<quint64>::max() - 0x100000000000000L; i += 0x100000000000000L) {
        os << static_cast<quint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (quint64 i = std::numeric_limits<quint8>::min(); i <= std::numeric_limits<quint8>::max(); ++i) {
        quint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint64 i = std::numeric_limits<quint16>::min(); i <= std::numeric_limits<quint16>::max(); i += 256) {
        quint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint64 i = std::numeric_limits<quint32>::min(); i <= std::numeric_limits<quint32>::max(); i += 256 * 256) {
        quint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (quint64 i = std::numeric_limits<quint64>::min(); i < std::numeric_limits<quint64>::max() - 0x100000000000000L; i += 0x100000000000000L) {
        quint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
}


void TestMsgPack::testInt64()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (qint16 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        os << static_cast<qint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint32 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        os << static_cast<qint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint64 i = std::numeric_limits<qint32>::min(); i <= std::numeric_limits<qint32>::max(); i += 256 * 256) {
        os << static_cast<qint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    for (qint64 i = std::numeric_limits<qint64>::min(); i < std::numeric_limits<qint64>::max() - 0x100000000000000L; i += 0x100000000000000L) {
        os << static_cast<qint64>(i);
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (qint64 i = std::numeric_limits<qint8>::min(); i <= std::numeric_limits<qint8>::max(); ++i) {
        qint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint64 i = std::numeric_limits<qint16>::min(); i <= std::numeric_limits<qint16>::max(); i += 256) {
        qint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint64 i = std::numeric_limits<qint32>::min(); i <= std::numeric_limits<qint32>::max(); i += 256 * 256) {
        qint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
    for (qint64 i = std::numeric_limits<qint64>::min(); i < std::numeric_limits<qint64>::max() - 0x100000000000000L; i += 0x100000000000000L) {
        qint64 t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QCOMPARE(t, i);
    }
}


void TestMsgPack::testFloat()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (float f = 0; f < 1.0; f += 0.01) {
        os << f;
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (float f = 0; f < 1.0; f += 0.01) {
        float t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QVERIFY(qFuzzyCompare(t, f));
    }
}


void TestMsgPack::testDouble()
{
    QByteArray bs;
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    for (double f = 0; f < 1.0; f += 0.01) {
        os << f;
        QVERIFY(os.status() == MsgPackStream::Ok);
    }
    MsgPackStream is(bs);
    for (double f = 0; f < 1.0; f += 0.01) {
        double t;
        is >> t;
        QVERIFY(is.status() == MsgPackStream::Ok);
        QVERIFY(qFuzzyCompare(t, f));
    }
}

void TestMsgPack::testString()
{
    QByteArray bs;
    const QString &uuid = QUuid::createUuid().toString();
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    os << uuid;
    QVERIFY(os.status() == MsgPackStream::Ok);
    MsgPackStream is(bs);
    QString t;
    is >> t;
    QVERIFY(is.status() == MsgPackStream::Ok);
    QCOMPARE(uuid, t);
}

void TestMsgPack::testByteArray()
{
    QByteArray bs;
    const QByteArray &uuid = QUuid::createUuid().toByteArray();
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    os << uuid;
    QVERIFY(os.status() == MsgPackStream::Ok);
    MsgPackStream is(bs);
    QByteArray t;
    is >> t;
    QVERIFY(is.status() == MsgPackStream::Ok);
    QCOMPARE(uuid, t);
}

void TestMsgPack::testDateTime()
{
    QByteArray bs;
    const QDateTime &dt = QDateTime::currentDateTime();
    MsgPackStream os(&bs, QIODevice::WriteOnly);
    os << dt;
    QVERIFY(os.status() == MsgPackStream::Ok);
    MsgPackStream is(bs);
    QDateTime t;
    is >> t;
    QVERIFY(is.status() == MsgPackStream::Ok);
    QCOMPARE(dt, t);
}

QTEST_MAIN(TestMsgPack)
#include "test_msgpack.moc"
