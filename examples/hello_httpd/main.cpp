#include "qtnetworkng.h"

using namespace qtng;


class HelloRequestHandler: public BaseHttpRequestHandler
{
public:
    virtual void doGET() override
    {
        if (path == "/") {
            sendResponse(HttpStatus::OK);
            sendHeader("Content-Type", "text/plain");
            sendHeader("Content-Length", "0");
            sendHeader("Connection", "keep-alive");
            endHeader();
        } else {
            sendError(HttpStatus::NotFound);
        }
    }

    virtual void logRequest(HttpStatus, int) override
    {
    }

    virtual void logError(HttpStatus, const QString &, const QString &) override
    {
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
