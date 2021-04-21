#include "qtnetworkng.h"

using namespace qtng;


class HelloRequestHandler: public SimpleHttpRequestHandler
{
public:
    virtual void doGET() override
    {
        if (path == "/hello/") {
            sendResponse(HttpStatus::OK);
            sendHeader("Content-Type", "text/plain");
            sendHeader("Content-Length", "0");
            sendHeader("Connection", "keep-alive");
            endHeader();
        } else {
            QSharedPointer<FileLike> f = serveStaticFiles(rootDir, path);
            if (!f.isNull()) {
                sendfile(f, request);
                f->close();
            }
        }
    }
};


class HelloHttpServer: public TcpServer<HelloRequestHandler>
{
public:
    HelloHttpServer(const HostAddress &serverAddress, quint16 serverPort)
        : TcpServer(serverAddress, serverPort) {}
};


int main()
{
    HelloHttpServer httpd(HostAddress::Any, 8000);
    httpd.serveForever();
    return 0;
}
