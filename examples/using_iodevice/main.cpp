#include <QApplication>
#include <QTextBrowser>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include "../../qtnetworkng.h"

using namespace qtng;

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QSharedPointer<QTextBrowser> text(new QTextBrowser);
    text->show();
    CoroutineGroup operations;
    operations.spawn([text] {
        QNetworkAccessManager manager;
        QUrl url("https://download.qt.io/");
        QNetworkRequest request(url);
        QNetworkReply *reply = manager.get(request);
        qAwait(reply, &QNetworkReply::finished);
        text->setHtml(reply->readAll());
        reply->deleteLater();
    });
    return startQtLoop();
}
