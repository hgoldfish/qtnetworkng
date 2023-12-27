QtNetworkNg
===========

[中文](README.HANS.md)

Introduction
------------

QtNetworkgNg is a coroutine-based network toolkit. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API which is similar to python-gevent. As the name suggests, QtNetworkNg requires Qt5 framework. For more detail visit:

[Introduction to QtNetworkNg](https://qtng.org/intro.html)


Documents
---------

Visit https://qtng.org/


Features
--------

* General Coroutine with similar API to QThread.
* `Socket` supports UDP and TCP.
* `SSLSocket` with similar API to `Socket`.
* `KcpSocket` implements KCP over UDP.
* `SocketLike` unite these three classes, act as the base of other compoments.
* `SocketServer` provide a framework for network servers. QtNetworkNg use it to implement customizable HTTP proxy and SOCKS5 proxy server.
* `HttpSession` implements a HTTP 1.1 client, supports connection via SOCKS5/HTTP proxy.
* `HttpServer` implements a static HTTP 1.1 server, can be used for reversed http proxy.
* `NetworkInterface` equals to `QNetworkInterface`, and `HostAddress` equals to `QHostAddress`.
* `WebSocketConnection` implements WebSocket client/server.
* `MsgPackStream` is a new MessagePack implementation similar to `QDataStream`
* `Cipher`, `MessageDigest`, `PublicKey`, `PrivateKey` wrap complicate LibreSSL C API.
* Not yet support Qt 6, because this may break the compatibility with earlier version of Qt 5

Examples
--------

Here comes a simple example to get web pages.

    #include <QtCore/qdebug.h>
    #include "qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get("http://example.com/");
        qDebug() << r.html();
        return 0;
    }
    
And another exmaple to make IPv4 tcp connection.

    #include <QtCore/qdebug.h>
    #include "qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        qtng::Socket conn;
        conn.connect("example.com", 80);
        conn.sendall("GET / HTTP/1.0\r\n\r\n");
        qDebug() << conn.recv(1024 * 8);
        return 0;
    }

To create IPv4 tcp server.

    Socket s;
    CoroutineGroup workers;
    s.bind(HostAddress::Any, 8000);
    s.listen(100);
    while (true) {
        QSharedPointer<Socket> request(s.accept());
        if (request.isNull()) {
            break;
        }
        workers.spawn([request] {
            request->sendall("hello!");
            request->close();
        });
    }

To create HTTP server is even more simpler:

    TcpServer<SimpleHttpRequestHandler> httpd(HostAddress::LocalHost, 8000);
    httpd.serveForever();

A Qt GUI example to fetch web page.

    // main.cpp
    #include <QApplication>
    #include <QTextBrowser>
    #include "qtnetworkng.h"

    using namespace qtng;

    class HtmlWindow: public QTextBrowser
    {
    public:
        HtmlWindow();
        virtual ~HtmlWindow() override;
    private:
        CoroutineGroup *operations;
    };
    
    HtmlWindow::HtmlWindow()
        :operations(new CoroutineGroup)
    {
        operations->spawn([this] {
            Coroutine::sleep(1);
            HttpSession session;
            HttpResponse response = session.get("http://www.example.com/");
            if(response.isOk()) {
                setHtml(response.html());
            } else {
                setHtml("failed");
            }
        });
    }
    
    HtmlWindow::~HtmlWindow()
    {
        delete operations;
    }
    
    int main(int argc, char **argv)
    {
        QApplication app(argc, argv);
        HtmlWindow w;
        w.show();
        return startQtLoop(); // Qt GUI application start the eventloop using startQtLoop() instead of app.exec()
    }

And its project file.
    
    # fetch_web_content.pro
    TEMPLATE = app
    QT += widgets
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
As you can see, networking programming is done with very simple API.


License
-------

The QtNetworkNg is distributed under LGPL 3.0 license.

You can obtain a copy of LGPL 3.0 license at: https://www.gnu.org/licenses/lgpl-3.0.en.html


Dependencies
------------

QtNetworkNg require QtCore to build. SSL and crypto is supported using embedded LibreSSL.

Qt 5 - https://www.qt.io/download


Supported Platforms
-----------------------

Linux, Android, MacOS, Windows and OpenBSD is supported.

iOS is not tested yet, as I have no iOS machines. FreeBSD is never tested either.

GZip compression is not supported under Windows if zlib library not present.

QtNetworkNg uses more effective boost::context asm code in arm, arm64, x86, amd64 machines, and uses native ucontext or windows fiber API in other architectures.


Towards 1.0
-----------

- [ ] Complete reference documents
- [x] Implement a HTTP 1.1 server.
- [x] HTTP supports gzip compression.
- [x] HttpResponse supports stream.
- [x] Support HTTP proxy and cache.
- [x] A simple replacement for libev in Windows.
- [ ] Add more OpenSSL functions.
- [ ] Support verification/ALPS for https connection.
- [x] Support MacOS and iOS platforms.
- [x] Remove the QtNetwork dependence.
- [x] Support WebSocket Client and Server.


Towards 2.0
-----------

- [ ] Remove the QtCore dependence.
- [ ] provide the API to both Qt 5 and 6.
- [ ] Support HTTP/2
- [ ] Support HTTP/3
- [ ] Support QUIC
- [ ] Support Kademlia
- [ ] Support BitTorrent protocol
- [ ] Support MTQQ


Towards 3.0

- [ ] use IOCP under Windows to deliver an ulimate performance.
- [ ] use I/O Rings under Windows 11
- [ ] use io_uring under the nearlier Linux environment.


Building
--------

1. Clone QtNetworkNg from github as git subrepository.
2. include `qtnetworkng/qtnetworkng.pri` to your `project.pro` file. Or include `qtnetworkng/CMakeLists.txt` to the `CMakeLists.txt` of your project.
3. include `qtnetworkng.h` in you cpp files.


How to Contribute
-----------------

Create a pull request on github.com with your patch, then make a pull request to me.

