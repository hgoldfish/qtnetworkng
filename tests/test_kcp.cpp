#include <QtCore/qcoreapplication.h>
#include <QtCore/qfile.h>
#include <QElapsedTimer>
#include <stdio.h>
#include "qtnetworkng.h"

using namespace qtng;

void kcpWorker(QSharedPointer<KcpSocket> request)
{
    QByteArray buf(1024 * 8, Qt::Uninitialized);
    MessageDigest m(MessageDigest::Sha256);
    QElapsedTimer timer;
    timer.start();
    int count = 0;
    int rate = 0;
    uchar header[4];
    request->recvall(reinterpret_cast<char *>(header), 4);
    qint32 filesize;
    filesize = qFromBigEndian<qint32>(header);
    qDebug() << filesize;
    while (count < filesize) {
        qint32 bs = request->recv(buf.data(), buf.size());
        if (bs <= 0) {
            break;
        }
        m.addData(buf.data(), bs);
        count += bs;
        rate += bs;
        if (timer.elapsed() > 1000) {
            qDebug() << (1.0 * rate / qMax(timer.elapsed(), (qint64) 1) * 1000.0 / 1024.0) << "KB/s";
            rate = 0;
            timer.restart();
        }
    }
    const QString &message = QStringLiteral("server sha256= %1").arg(QString::fromLatin1(m.hexDigest()));
    qDebug() << message;
}

void kcpServer()
{
    KcpSocket s;
    s.bind(7943);
    s.listen(50);
    CoroutineGroup workers;
    while (true) {
        QSharedPointer<KcpSocket> r(s.accept());
        if (r.isNull()) {
            break;
        }
        qDebug() << "hello, there:" << r->peerAddressURI();
        workers.spawn([r] { kcpWorker(r); });
    }
}

void kcpClient(const QString &remoteHost, const QString &filePath)
{
    Coroutine::sleep(1.0);
    KcpSocket s;
    bool ok = s.connect(remoteHost, 7943);
    if (!ok) {
        printf("can not connect to server.");
        return;
    }
    s.setSendQueueSize(32);
    s.setMode(KcpSocket::Loopback);
    s.setUdpPacketSize(1024 * 16);

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) {
        printf("can not open file.");
        return;
    }
    QByteArray buf(1024 * 1024 * 8, Qt::Uninitialized);
    MessageDigest m(MessageDigest::Sha256);
    uchar header[4];
    qToBigEndian<qint32>(f.size(), header);
    s.sendall(reinterpret_cast<char *>(header), 4);
    while (true) {
        int bs = f.read(buf.data(), buf.size());
        qDebug() << "read bytes from file:" << bs;
        if (bs <= 0) {
            break;
        }
        m.addData(buf.data(), bs);
        s.sendall(buf.data(), bs);
    }
    const QByteArray &eof = s.recv(1024);  // 等待 qtng 在后台协程发送数据，发送数据完毕，服务器关闭连接时返回 0
    Q_ASSERT(eof.isNull());
    const QString &message = QStringLiteral("client sha256= %1").arg(QString::fromLatin1(m.hexDigest()));
    qDebug() << message;
}

int main(int argc, char **argv)
{
    //    QCoreApplication app(argc, argv); Q_UNUSED(app);
    QSharedPointer<Coroutine> t;
    if (argc == 3) {
        QString hostName = QString::fromLocal8Bit(argv[1]);
        QString filepath = QString::fromLocal8Bit(argv[2]);
        t.reset(Coroutine::spawn([hostName, filepath] { kcpClient(hostName, filepath); }));
    } else if (argc == 1) {
        t.reset(Coroutine::spawn([] { kcpServer(); }));
    } else {
        const QString &programName = QString::fromLatin1(argc > 0 ? argv[0] : "kcp_sendfile");
        const QString usage = QString::fromUtf8("Usage: \n\t Client: %1 <remotehost> <filepath>\n\tServer: %1\n");
        puts(qPrintable(usage));
    }
    t->join();
    return 0;
}
