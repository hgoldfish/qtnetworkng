#include <QCoreApplication>
#include <QTimer>
#include <QTime>
#include "qtnetworkng.h"

int many_httpget(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    CoroutineGroup operations;
    Session session;
    session.setMaxConnectionsPerServer(0);

    QList<int> l;
    for(int i = 0; i < 100; ++i) {
        l.append(i);
    }

    quint64 total = 0;
    Semaphore semp(500);
    QTime timer;
    timer.start();
    while(true) {
        semp.acquire();
        total += 1;
        operations.spawn([&session, &semp, &timer, total] {
            try {
                const Response &response = session.get(QString::fromUtf8("http://127.0.0.1:8000/"));
                float rps = total * 1.0 / timer.elapsed() * 1000;
                qDebug() << total << ":" << rps << response.statusCode;
            } catch (RequestException &e) {
                //qDebug() << total << ":" << "failed";
            }
            semp.release();
        });
    }
    return 0;
}
