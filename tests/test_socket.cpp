#include <QtCore/qdebug.h>
#include <QtCore/qcoreapplication.h>
#include "../qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    SslSocket s;
    bool ok = s.connect("www.baidu.com", 443);
    s.sendall("GET / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n");
    const QByteArray &data = s.recvall(1024 * 1024);
    qDebug() << QString::fromUtf8(data);
    Certificate cert = s.peerCertificate();
    QList<Certificate> certs = s.peerCertificateChain();
    qDebug() << cert.digest() << certs.size() << s.cipher().name();
    return 0;
}
