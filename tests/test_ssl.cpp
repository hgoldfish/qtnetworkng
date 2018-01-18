#include <QtTest>
#include "qtsslng.h"
#include "qtnetworkng.h"

using namespace qtng;

class TestSsl: public QObject
{
    Q_OBJECT
private slots:
    void testSimple();
    void testGetBaidu();
};


void TestSsl::testSimple()
{
    SslSocket s;
    bool ok = s.connect("www.baidu.com", 443);
    QVERIFY(ok);
    s.sendall("GET / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n");
    const QByteArray &data = s.recvall(1024 * 1024);
    QVERIFY(!data.isEmpty());
}


void TestSsl::testGetBaidu()
{
    HttpSession session;
    HttpResponse response = session.get(QString::fromUtf8("https://www.baidu.com/"));
    QVERIFY(response.isOk());
    QVERIFY(!response.html().isEmpty());
}

QTEST_MAIN(TestSsl)

#include "test_ssl.moc"
