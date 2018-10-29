#include <QTimer>
#include <QTime>
#include "qtnetworkng.h"

int main(int argc, char *argv[])
{
    qtng::CoroutineGroup operations;
    qtng::HttpSession session;
    session.setMaxConnectionsPerServer(0);

    QList<int> l;
    for (int i = 0; i < 100; ++i) {
        l.append(i);
    }

    quint64 total = 0;
    qtng::Semaphore semp(500);
    QTime timer;
    timer.start();
    while(true) {
        semp.acquire();
        total += 1;
        operations.spawn([&session, &semp, &timer, total] {
            try {
                const qtng::HttpResponse &response = session.get(QStringLiteral("http://127.0.0.1:8000/"));
                float rps = total * 1.0 / timer.elapsed() * 1000;
                qDebug() << total << ":" << rps << response.statusCode;
            } catch (qtng::RequestException &e) {
                qDebug() << total << ":" << "failed";
            }
            semp.release();
        });
    }
    return 0;
}
