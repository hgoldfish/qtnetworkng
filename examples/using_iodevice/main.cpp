#include <QApplication>
#include <QPlainTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include "../../qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QSharedPointer<QPlainTextEdit> text(new QPlainTextEdit);
    text->show();
    CoroutineGroup operations;
    operations.spawn([text] {
        QNetworkAccessManager manager;
        QUrl url("http://download.qt.io/online/qt5/linux/x64/online_repository/Updates.xml");
        QNetworkRequest request(url);
        QNetworkReply *reply = manager.get(request);
        qAwait(reply, &QNetworkReply::finished);
        text->setPlainText(reply->readAll());
        reply->deleteLater();
    });
    return startQtLoop();
}
