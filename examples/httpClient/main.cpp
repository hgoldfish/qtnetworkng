#include <QtCore/qdebug.h>
#include "qtnetworkng.h"
#include <QCoreApplication>
#include <QDir>
// 与httpServer配套使用，可形成一个简单的http服务器和客户端进行通信。
int main(int argc, char **argv)
{
    qtng::HttpSession session;
    qtng::HttpResponse r = session.get("https://127.0.0.1:8443/hello/");
    if (r.isOk()) {
        qDebug() << r.statusText()<<":"<<r.body();
    } else {
        qDebug() <<"error:"<< r.error()->what();
    }
    // 发送POST请求
    QJsonObject data{{"message", "Hello Server!"}};
    qtng::HttpResponse postRes = session.post("https://127.0.0.1:8443/data", data);
    if (postRes.isOk()) {
        qDebug() << "POST Response:" << postRes.json().object().value("received").toString();
    } else {
        qDebug() << "POST Error:" << postRes.error()->what();
    }
    // 文件下载示例
    QString downloadFilename = "file.txt";
    QString savePath = QDir::currentPath()+"/file.text";
    qtng::HttpResponse downloadRes = session.get(
            QString("https://127.0.0.1:8443/download?filename=%1").arg(downloadFilename));
    if (downloadRes.isOk()) {
        QSharedPointer<qtng::FileLike> saveFile = qtng::FileLike::open(savePath, "wb");
        if (saveFile) {
            saveFile->write(downloadRes.body());
            qDebug() << "File saved to:" << savePath;
        } else {
            qDebug() << "Failed to create save file";
        }
    } else {
        qDebug() << "Download failed:" << downloadRes.error()->what();
    }
    // 文件上传示例
    QString localFilePath = "filename.txt";  //改为你要上传的文件的路径
    QSharedPointer<qtng::FileLike> file = qtng::FileLike::open(localFilePath, "rb");
    if (!file) {
        qDebug() << "Failed to open local file";
        return 1;
    }
    bool ok=true;
    QByteArray fileData = file->readall(&ok);
    QFileInfo fileInfo(localFilePath);
    QString uploadUrl = QString("https://127.0.0.1:8443/upload?filename=%1").arg(fileInfo.fileName());

    qtng::HttpResponse uploadRes = session.post(uploadUrl, fileData);
    if (uploadRes.isOk()) {
        qDebug() << "Upload success:" << uploadRes.body();
    } else {
        qDebug() << "Upload failed:" << uploadRes.error()->what();
    }
    return 0;
}

