#include <QtTest>
#include "qtnetworkng.h"

using namespace qtng;

class TestSsl: public QObject
{
    Q_OBJECT
private slots:
    void testGetBaidu();
    void testSimple();
//    void testSocks5Proxy();
    void testVersion10();
    void testServer();
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
    QCOMPARE(certs.size(), 2);
    qDebug() << s.cipher().name();
}

void TestSsl::testGetBaidu()
{
    HttpSession session;
    HttpRequest request;
    request.setUrl("https://www.baidu.com/");
    request.addHeader("Connection", "close");
    HttpResponse response = session.send(request);
    QVERIFY(response.isOk());
    QVERIFY(!response.html().isEmpty());
}

//void TestSsl::testSocks5Proxy()
//{
//    QSharedPointer<Socks5Proxy> proxy(new Socks5Proxy("127.0.0.1", 8086));
//    HttpSession session;
//    session.setSocks5Proxy(proxy);
//    HttpResponse response = session.get("https://www.baidu.com/");
//    QVERIFY(response.isOk());
//}

void TestSsl::testVersion10()
{
    HttpSession session;
    session.setDefaultVersion(Http1_0);
    HttpResponse response = session.get("https://www.baidu.com/");
    QVERIFY(response.isOk());
    QVERIFY(response.version() == Http1_0);
}


void TestSsl::testServer()
{
    SslConfiguration config = SslConfiguration::testPurpose("Goldfish", "CN", "Example");
    SslSocket server(Socket::AnyIPProtocol, config);
    bool success = server.bind();
    QVERIFY(success);
    QVERIFY(server.state() == Socket::BoundState);
    server.listen(100);
    quint16 port = server.localPort();
    qDebug() << port;
    QVERIFY(port != 0);
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([port]{
        SslSocket client;
        bool success = client.connect(HostAddress::LocalHost, port);
        if (!success) {
            return;
        }
        client.sendall("fish is here.");
        client.close();
    }));
    {
        Timeout _(5.0);
        QSharedPointer<SslSocket> request = server.accept();
        QVERIFY(!request.isNull());
        QCOMPARE(request->localCertificate().digest(MessageDigest::Sha256),
                 config.localCertificate().digest(MessageDigest::Sha256));
        QByteArray data = request->recv(1024);
        qDebug() << data << request->sslErrors() << request->errorString();
        QVERIFY(data == "fish is here.");
    }
    clientCoroutine->join();
}
QTEST_MAIN(TestSsl)

#include "test_ssl.moc"
