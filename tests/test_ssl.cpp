#include <QtTest>
#include "qtnetworkng.h"

using namespace qtng;

class TestSsl: public QObject
{
    Q_OBJECT
private slots:
    void testGetBaidu();
    void testSimple();
    void testSocks5Proxy();
    void testVersion10();
};


void TestSsl::testSimple()
{
    SslSocket s;
    bool ok = s.connect("www.baidu.com", 443);
    QVERIFY(ok);
    s.sendall("GET / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n");
    const QByteArray &data = s.recvall(1024 * 1024);
    QVERIFY(!data.isEmpty());
    Certificate cert = s.peerCertificate();
    QVERIFY(!cert.isNull());
    QStringList cn;
    cn.append(QStringLiteral("baidu.com"));
    QCOMPARE(cert.subjectInfo(Certificate::CommonName), cn);
    QList<Certificate> certs = s.peerCertificateChain();
    QCOMPARE(certs.size(), 3);
    qDebug() << s.cipher().name();
}

void TestSsl::testGetBaidu()
{
    HttpSession session;
    HttpRequest request;
    request.url = QUrl("https://www.baidu.com/");
    request.addHeader("Connection", "close");
    try {
        HttpResponse response = session.send(request);
        QVERIFY(response.isOk());
        QVERIFY(!response.html().isEmpty());
    } catch (const RequestException &e) {
        qDebug() << e.what();
    }
}

void TestSsl::testSocks5Proxy()
{
    QSharedPointer<Socks5Proxy> proxy(new Socks5Proxy("127.0.0.1", 8086));
    HttpSession session;
    session.setSocks5Proxy(proxy);
    HttpResponse response = session.get("https://www.baidu.com/");
    QVERIFY(response.isOk());
}

void TestSsl::testVersion10()
{
    HttpSession session;
    session.setDefaultVersion(Http1_0);
    HttpResponse response = session.get("https://www.baidu.com/");
    QVERIFY(response.isOk());
    QVERIFY(response.version == Http1_0);
}

//QTEST_MAIN(TestSsl)

#include "test_ssl.moc"
