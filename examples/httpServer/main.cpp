#include "qtnetworkng.h"
#include <QtCore/qurlquery.h>
using namespace qtng;
// 与httpClient配套使用，可形成一个简单的http服务器和客户端进行通信。
class HelloRequestHandler: public SimpleHttpRequestHandler
{
public:
    virtual void doGET() override
    {
        if (path == QString::fromLatin1("/hello/")) {
            // qDebug()<<"recv get request";
            // sendResponse(HttpStatus::OK,"test");
            // sendHeader("Content-Type", "text/plain");
            // sendHeader("Content-Length", "0");
            // sendHeader("Connection", "keep-alive");
            // endHeader();
            // request->send("hello");
            sendResponse(HttpStatus::OK);
            sendHeader("Content-Type", "text/plain");
            QByteArray body = "hello";
            sendHeader("Content-Length", QByteArray::number(body.size()));
            endHeader();
            request->sendall(body);
        } else if (path.startsWith("/download")) {
            QUrlQuery query(QUrl(path).query());
            QString filename = query.queryItemValue("filename");
                                                                  // 文件下载
            if (filename.isEmpty()) {
                sendError(HttpStatus::BadRequest, "Missing filename");
                return;
            }
            QFileInfo fileInfo("C:\\Users\\Xqy\\Desktop\\qtng学习.txt");
            if (!fileInfo.exists() || fileInfo.isDir()) {
                sendError(HttpStatus::NotFound, "File not found");
                return;
            }
            QSharedPointer<FileLike> file = FileLike::open(fileInfo.absoluteFilePath(), "rb");
            if (!file) {
                sendError(HttpStatus::InternalServerError, "Cannot open file");
                return;
            }
            sendResponse(HttpStatus::OK);
            sendHeader("Content-Type", "application/octet-stream");
            sendHeader("Content-Disposition",
                       QString("attachment; filename=\"%1\"").arg(fileInfo.fileName()).toLatin1());
            sendHeader("Content-Length", QByteArray::number(file->size()));
            endHeader();
            sendfile(file, request, file->size());
            return;
            sendError(HttpStatus::NotFound);
        }else{
            sendError(HttpStatus::NotFound);
        }
    }
    virtual void doPOST() override
    {
        if (path == "/data") {
            // 读取请求体
            if (!readBody()) {
                sendError(HttpStatus::BadRequest);
                return;
            }
                    // 解析JSON
            QJsonParseError error;
            QJsonDocument doc = QJsonDocument::fromJson(body, &error);
            if (error.error != QJsonParseError::NoError) {
                sendError(HttpStatus::BadRequest, "Invalid JSON");
                return;
            }
                    // 构建响应
            QJsonObject responseObj;
            responseObj["received"] ="hello client"; //doc.object().value("message").toString();
            QByteArray responseBody = QJsonDocument(responseObj).toJson();

            sendResponse(HttpStatus::OK);
            sendHeader("Content-Type", "application/json");
            sendHeader("Content-Length", QByteArray::number(responseBody.size()));
            endHeader();
            request->sendall(responseBody);
        }else if(path.startsWith("/upload")){
            QUrlQuery query(QUrl(path).query());
            QString filename = query.queryItemValue("filename");
                if (filename.isEmpty()) {
                    sendError(HttpStatus::BadRequest, "Missing filename");
                    return;
                }

                        // 安全校验文件名
                if (filename.contains("/") || filename.contains("\\")) {
                    sendError(HttpStatus::BadRequest, "Invalid filename");
                    return;
                }
                QString filePath = QDir::currentPath() + "/upload/" + filename;
                QSharedPointer<FileLike> file = FileLike::open(filePath, "wb");
                if (!file) {
                    sendError(HttpStatus::InternalServerError, "Cannot create file");
                    return;
                }

                if (!readBody()) {
                    sendError(HttpStatus::BadRequest, "Error reading request body");
                    return;
                }

                file->write(body);
                file->close();

                sendResponse(HttpStatus::Created);
                sendHeader("Content-Type", "text/plain");
                QByteArray msg="File uploaded successfully";
                sendHeader("Content-Length",QByteArray::number(msg.size()));
                endHeader();
                request->sendall(msg);
                return;
                sendError(HttpStatus::NotFound);
        }else {
            sendError(HttpStatus::NotFound);
        }
    }
};
class HelloHttpServer: public SslServer<HelloRequestHandler>
{
public:
    HelloHttpServer(const HostAddress &serverAddress, quint16 serverPort)
        : SslServer(serverAddress, serverPort) {}
};
int main()
{
    HelloHttpServer httpd(HostAddress::Any, 8443);
    httpd.serveForever();
    return 0;
}
