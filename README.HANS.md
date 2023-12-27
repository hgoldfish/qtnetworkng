QtNetworkNg
===========

[English](README.md)


简介
----

QtNetworkNg, 简称 qtng 是一个使用协程进行网络编程的工具库。

以往的 C++ 网络编程库，一般都使用回调式的编程，或者线程式的编程。前者虽然性能极强，但晦涩难懂，业务逻辑在大段代码间跳转极易出错。而后者虽然较易入门但容易触发线程的变量同步崩溃，也难以应对现代的大并发网络连接。

协程式的网络编程已经发展多年，结合两者的优点，既有较强的性能，又编程简单，获得大量的支持。在 Python, C#, nim 等语言社区里面，协程式的网络编程已经是这些社区的主流网络编程方式，而在C++ 领域长期没有得到广泛的应用。

QtNetworkNg 主要借鉴了 Python 社区的 gevent 与 requests 两个受欢迎的网络编程库。将它们的理念带到 C++ 社区，设计并实现了极具人性化的 API. 与 boost::asio, QtNetwork, POCO, libcurl 这些网络编程库相比，QtNetworkNg 的 API 非常的直接，经常能够用三五行代码即可完成传统工具库大段的代码功能。

目前 QtNetworkNg 依赖于 Qt 工具库的 QtCore 模块，因为这个模块提供了非常多 C++ 必须的小型工具库，比如`QString`, `QByteArray`, `QUrl` 这些小工具。最终的目标是重写这些工具，脱离 Qt 运行。

如对协程的详细原理与使用方式，以及 QtNetworkNg 具体是如何让网络开发更简单的，请查阅 QtNetworkNg 的入门文档:

[QtNetworkNg入门](https://qtng.org/intro.html)


文档站
------

https://qtng.org/


功能与特性
--------

* 协程的基本操作。提供了与`QThread`极其相似的接口。
* `Socket` API 支持通用的 UDP 与 TCP 编程。
* `SSLSocket` API，提供了与 `Socket` 几乎一样的 API，支持通用的 SSL 编程。包含了丰富的 SSL 功能，比如证书的处理等。
* `KcpSocket` API，同样提供了与 `Socket` 几乎一样的 API，支持 KCP 编程。KCP 是一种基于 UDP 的低延迟协议。
* `SocketLike` 统一以上三种类型的 API。
* `SocketServer` API 提供了通用的 UDP 与 TCP 服务器设计。内置实现了 SOCKS5 与 HTTP RPOXY 服务器。
* `HttpSession` 是一个 HTTP 1.1 强功能客户端，同时提供了 HTTP 编码解码与 cookie 管理等功能。
* `HttpServer` 提供 HTTP 1.1 的服务器。通过丰富的插接接口，可作为反向代理服务器或者 RESTFUL 服务器。
* `NetworkInterface` 接口，等价于 `QNetworkInterface`，可查询当前机器有哪些网卡。
* `WebSocketConnection` 提供了 WebSocket 的客户端与服务端接口。
* `MsgPackStream` 提供了与 `QDataStream` 几乎一样的 API，支持 MessagePack 序列化与反序列化。MessagePack 是一种先进的数据格式，使用较少的容量即可存储与传输各种网络数据。很适合代替 JSON 格式。
* `Cipher`, `MessageDigest`, `PublicKey`, `PrivateKey` 包装了 OpenSSL 的复杂 API。无痛使用各种加密、证书、签名、HASH 等加密学功能。
* 注意，QtNetworkNg 暂时不支持 Qt6，因为如果支持 Qt6 的话，必须放弃对 Qt 5.6 这些早期版本的支持。而这些版本目前在中国还被广泛使用。

使用示例
--------

第一个例子是一个命令行程序，运行后下载网页并打印它的内容。

    #include <QtCore/qdebug.h>
    #include "qtnetworkng.h"

    int main(int argc, char **argv)
    {
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get("http://example.com/");
        qDebug() << r.html();
        return 0;
    }

第二个例子是使用通用的 TCP 编程，连接远程的 HTTP 服务器，获取主页并且打印出来:

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

第三个例子是使用通用的 `Socket` 接口，创建一个简单的 TCP 服务器。当有客户端连接这个服务器即返回 `hello!`.

    Socket s;
    CoroutineGroup workers; // 协程管理器
    s.bind(HostAddress::Any, 8000);
    s.listen(100);
    while (true) {    // 无限循环处理客户端连接。
        QSharedPointer<Socket> request(s.accept());  // 这里一直等待，直到获取到一个客户端连接。
        if (request.isNull()) {
            break;  // 表示没有获取到客户端连接，当前程序要求退出。
        }
        workers.spawn([request] {   // 启动新协程处理这个新连接。同时继续获取下一个客户端连接。
            request->sendall("hello!");
            request->close();
        });
    }

如果是打算编写 HTTP 服务器，QtNetworkNg 已经提供了:

    TcpServer<SimpleHttpRequestHandler> httpd(HostAddress::LocalHost, 8000);
    httpd.serveForever();

QtNetworkNg 可以与 Qt GUI 程序一起使用。在 GUI 程序里面做网络请求变得非常简单:

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
        // 创建一个新的协程下载网页，这个语句立即返回。协程将在下一次空闲的时候执行。
        operations->spawn([this] {
            Coroutine::sleep(1);   // 故意暂停了一秒，免得程序运行得太快看不明白。
            HttpSession session;
            HttpResponse response = session.get("http://www.example.com/");
            if(response.isOk()) {
                // 调用 QTextBrowser::setHtml() 把下载到的 HTML 页面写到界面上。
                setHtml(response.html());
            } else {
                setHtml("failed");
            }
        });
    }

    HtmlWindow::~HtmlWindow()
    {
        // 当窗口关闭时，如果还在下载，此时会取消掉下载任务。
        delete operations;
    }

    int main(int argc, char **argv)
    {
        QApplication app(argc, argv);
        HtmlWindow w;
        w.show();
        // 注意，这里是 QtNetworkNg 与其它 Qt 程序不一样的地方，一般需要使用 startQtLoop() 这人函数来代替 app.exec()
        return startQtLoop();
    }

以上 `main.cpp` 的工程文件内容:

    # fetch_web_content.pro
    TEMPLATE = app
    QT += widgets
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)

可以看到，使用 QtNetworkNg 编程时，代码非常精简，并且非常容易理解。


授权协议
-------

QtNetworkNg 在 LGPL 3.0 协议下发布。请在这条链接下载 LGPL 3.0 协议的原文:

https://www.gnu.org/licenses/lgpl-3.0.en.html

任何人使用本程序时，本程序以及作者本人不提供任何维护保证以及责任担保。

额外豁免简单静态链接时，仍可不开源贵公司的源代码。但是不豁免即静态链接，又修改 qtng 源码的情况。


商业授权
-------

本自由软件不提供商业授权。

但是建议世界五百强，以及大股东是世界五百强的任何企业，在使用本程序的时候，能够向作者或者社区相关人员捐赠款项，履行你们的社会责任。


依赖项
------

QtNetworkNg 依赖于 Qt 5 的 QtCore 模块，但不依赖 QtGui, QtNetwork, QtSql 等其它模块。QtNetworkNg 的 SSL 和加密学功能，由 OpenSSL 提供，QtNetworkNg 只做 API 包装，没有任何加密学的实现。

使用 QtNetworkNg 时，最好安装最新的 LibreSSL 或者 OpenSSL 以减少攻击面。

为了方便 Windows 程序员使用 QtNetworkNg, 在项目代码内包含了一个最近版本的 LibreSSL，当使用 cmake 编译 QtNetworkNg 时，会自动使用内置的这个 LibreSSL.

Qt 5 下载地址:

https://www.qt.io/download


支持的平台
---------

日常测试的平台有: Linux, Android, MacOS, Windows 和 OpenBSD

iOS 和 FreeBSD 理论上都支持，但是都还没有被测试。

当使用 Gzip 压缩与解压缩功能的时候，可能需要额外安装 zlib 第三方库。一般的 Linux 与 BSD 都已经内置包含了这个库。而 Mingw 编译套件一般也包含了 zlib 库。

QtNetworkNg 使用了来自于 boost::context 开源项目编写的 ASM 代码。目前支持在 arm, arm64, x86, amd64, mips32, mips64 这个架构下使用汇编代码进行高效的协程切换。如果操作系统平台或者 CPU 指令集不支持，就会使用 POSIX 的 ucontext，以及 Windows 的纤程 API 进行切换，比如龙芯处理器下的 QtNetworkNg 即使用 ucontext 进行切换。


即将发布 1.0 版本
---------------

- [ ] 完善参考文档
- [x] 实现 HTTP 1.1 服务器。
- [x] HTTP 支持 gzip 压缩。
- [x] `HttpResponse` 接口支持 `steam()` 方法，用来获得底层的连接。
- [x] `HttpSession` 作为强功能的 HTTP 客户端，应该支持缓存以及各种代理。
- [x] Windows 底下，提供了一个类似于 libev 的事件循环，而不是依赖于 Qt 的低效事件循环。
- [ ] 支持更多的 OpenSSL 功能。
- [ ] 支持 SSL 的客户端与服务端证书认证策略。
- [x] 支持 MacOS 平台
- [x] 移除对 QtNetwork 的依赖。
- [x] 支持 WebSocket 的客户端与服务端。


发布 2.0 目标
-----------

- [ ] 移除对 Qt 的依赖
- [ ] 支持 Qt 6 的同时，也支持 Qt 5 接口。按需进行编译。
- [ ] 支持 HTTP/2
- [ ] 支持 HTTP/3
- [ ] 支持 QUIC 协议
- [ ] 支持 Kademlia DHT
- [ ] 支持 BitTorrent 协议
- [ ] 支持 MTQQ


发布 3.0 目标
------------

- [ ] 使用 IOCP 优化 QtNetworkNg 在 Windows 下的性能。
- [ ] 支持 Windows 11 的 I/O Rings 技术，提供极致的性能。
- [ ] 支持 Linux 较新的 io_uring 接口，提供极致的性能。


如何编译使用
-----------

推荐直接包含 QtNetworkNg 的源代码到工程内，而不是编译成 lib 或者 dll/so

1. 下载 QtNetworkNg 源代码
2. 二选一: 把 `qtnetworkng/qtnetworkng.pri` 包含到你的 `project.pro` 文件里面，或者把 `qtnetworkng/CMakeLists.txt` 包含到你项目里面的 `CMakeLists.txt` 里面。
3. 在 C++ 代码里面包含 `qtnetworkng.h`


如何向项目贡献自己的力量
--------------------

在项目的 github 主页发布一个 pull request, 然后推给本项目即可。如果您不想使用 github，也可以向作者的邮箱直接发送补丁包。
