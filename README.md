QtNetworkNg
===========


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
* `HttpSession` implements a HTTP 1.0/1.1 client, supports connection via SOCKS5/HTTP proxy.
* `HttpServr` implements a static HTTP 1.0/1.1 server, can be used for reversed http proxy.
* `MsgPackStream` is a new MessagePack implementation similar to `QDataStream`
* `Cipher`, `MessageDigest`, `PublicKey`, `PrivateKey` wrap complicate LibreSSL C API.

Examples
--------

Here comes a simple example to get web pages.

    #include "qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get("http://example.com/");
        qDebug() << r.html();
        return 0;
    }
    
And another exmaple to make IPv4 tcp connection.

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

QtNetworkNg require QtCore, QtNetwork to build. SSL and crypto is supported using embedded LibreSSL.

Qt 5 - https://www.qt.io/download

Supported Platforms
-----------------------

Linux, Android and OpenBSD is supported.

Macos, iOS is not tested yet, as I have no mac machines.

Windows is supported partially. Because the Qt eventloop is not very efficient, a separate libev event loop is provided in Linux which is not available in Windows. GZip compression is not supported under Windows if zlib library not present.

QtNetworkNg uses more effective boost::context asm code in arm, arm64, x86, amd64 machines, and uses native ucontext or windows fiber API in other architectures.


Towards 1.0
-----------

- [ ] Complete reference documents
- [x] Implements an HTTP 1.0 server.
- [x] HTTP support gzip compression.
- [x] HttpResponse support stream.
- [x] Support HTTP proxy and cache.
- [ ] Built as shared library(DLL)
- [x] A simple replacement for libev in Windows.
- [ ] Add more OpenSSL functions.
- [ ] Support verification/ALPS for https connection.
- [ ] Support MacOS and iOS platforms.
- [ ] Remove QtNetwork dependence.


Towards 2.0
-----------
- [ ] Support HTTP/2
- [ ] Support HTTP/3
- [ ] Support Kademlia


Building
--------

1. Clone QtNetworkNg from github as git subrepository.
2. include `qtnetworkng/qtnetworkng.pri` in your `project.pro` file.
3. include `qtnetworkng.h` in you cpp files.

How to Contribute
-----------------

Create a pull request on github.com with your patch, then make a pull request to me.

