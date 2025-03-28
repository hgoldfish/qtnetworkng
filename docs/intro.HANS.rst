.. qtnetworkng documentation master file, created by
   sphinx-quickstart on Fri Nov 10 11:50:39 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

QtNetworkNg简介
===========================

QtNetworkNg是基于协程的网络编程工具包，类似boost::asio但借鉴了QtNetwork和Python gevent的设计理念。相比boost::asio和Qt的QtNetwork，QtNetworkNg提供了更简洁的API。


为何选择协程
--------------

协程并非新事物，Python、Go和C#多年前就使用协程简化网络编程。

传统网络编程采用线程机制，``send()/recv()`` 会阻塞线程，操作系统将当前线程切换到就绪线程直至数据到达。这种方式直观易用，但线程资源消耗大，数千连接会占用大量内存。更严重的是，线程可能导致数据竞争、数据损坏甚至程序崩溃。

另一种选择是回调范式。在调用 ``send() / recv()`` 前使用 ``select()/poll()/epoll()`` 检测数据到达。``select()`` 会阻塞，但多个连接可在单线程中处理。回调范式被视作"新时代的goto语句"，代码难以理解和维护，但因boost::asio等框架的流行而在C++中广泛使用。

协程范式是网络编程的现在与未来。协程是轻量级线程，拥有独立栈空间，由QtNetworkNg而非操作系统管理。类似线程范式，``send() / recv()`` 会阻塞，但会在数据到达时切换到同一线程内的其他协程。可低成本创建大量协程。由于单线程运行，天然避免数据竞争问题。API保持线程范式的直观性，同时规避了线程的复杂性。


跨平台支持
---------------

QtNetworkNg已在Linux、Android、Windows、MacOS和OpenBSD平台测试通过，支持gcc、clang、mingw32、msvc编译器。

构建QtNetworkNg需要QtCore模块。

协程实现采用boost::context汇编代码，同时支持原生posix ``ucontext``和windows ``fiber`` API，已在ARM、ARM64、x86、amd64架构成功运行测试。

Qt事件循环可替换为libev事件循环，若使用cmake构建可启用SSL/加密功能，此时将使用嵌入式libev和LibreSSL。


在qmake项目中使用QtNetworkNg
----------------------------

假设您的Qt/qmake项目名为*foo*，项目文件为``foo.pro``，目录结构如下：

.. code-block:: text
    :caption: 项目原始目录结构
    
    foo.pro
    main.cpp
    
推荐使用git子模块集成QtNetworkNg，从github克隆仓库并在``foo.pro``中包含``qtnetworkng.pri``：

.. code-block:: bash
    :caption: 获取qtnetworkng
    
    git clone https://github.com/hgoldfish/qtnetworkng.git

更新后的项目目录结构：

.. code-block:: text
    :caption: 项目目录结构
    
    foo.pro
    main.cpp
    qtnetworkng/
        qtnetworkng.pri
        qtnetworkng.pro
        其他文件...
        
修改``foo.pro``包含``qtnetworkng.pri``（注意不要包含``qtnetworkng.pro``，该文件用于动态库构建）：

.. code-block:: text
    :caption: foo.pro

    QT += core network
    TARGET = foo
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
示例``main.cpp``：

.. code-block:: c++
    :caption: 获取网页
    
    #include <QtCore/qdebug.h>
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    int main(int argc, char **argv)
    {
        HttpSession session;
        HttpResponse resp = session.get("http://www.example.com/");
        if (resp.isOk()) {
            qDebug() << resp.html();
        } else {
            qDebug() << "failed.";
        }
        return 0;
    }

常规构建流程：

.. code-block:: bash
    :caption: 构建项目
    
    qmake foo.pro
    make
    ./foo


在cmake项目中使用QtNetworkNg
----------------------------

从github克隆仓库并创建``main.cpp``：

.. code-block:: bash

    git clone https://github.com/hgoldfish/qtnetworkng.git

示例``CMakeLists.txt``：

.. code-block:: cmake

    cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
    project(foo)

    set(CMAKE_AUTOMOC ON)
    set(CMAKE_INCLUDE_CURRENT_DIR ON)

    add_subdirectory(qtnetworkng)

    add_executable(foo main.cpp)
    target_link_libraries(foo qtnetworkng)

构建命令：

.. code-block:: bash
    :caption: 构建qtnetworkng
    
    mkdir build
    cd build
    cmake ..   # 使用-DCMAKE_PREFIX_PATH=/usr/local/Qt5.12.11-static-linux-amd64/lib/cmake/指定Qt路径
    make
    

协程机制
--------

QtNetworkNg基于``Coroutine``实现。确保所有网络操作运行在协程环境中，主线程已隐式转换为协程。推荐使用``CoroutineGroup``管理协程，其采用``QSharedPointer``智能指针处理协程生命周期及边界情况。

.. code-block:: c++
    :caption: 启动协程
    
    void coroutine_entry()
    {
        Coroutine::sleep(1.0); // 休眠1秒
        qDebug() << "当前协程ID: " << Coroutine::current().id();
    }
    
    // 推荐使用CoroutineGroup
    CoroutineGroup operations;
    QSharedPointer<Coroutine> coroutine = operations.spawn(coroutine_entry);
    
    // 或手动管理协程
    QSharedPointer<Coroutine> coroutine = Coroutine::spawn(coroutine_entry);
    
通过 ``Coroutine::start()`` 调度协程启动， ``Coroutine::kill()`` 发送终止异常。两个函数立即返回，实际操作异步执行。

``CoroutineGroup`` 支持命名协程管理：

.. code-block:: c++
    :caption: 管理多个协程
    
    CoroutineGroup operations;
    operations.spawnWithName("coroutine1", coroutine_entry);
    operations.kill("coroutine1");
    operations.killall();

协程终止时抛出``CoroutineExit``异常，可捕获处理。协程被删除前会自动等待结束。

.. code-block:: c++
    :caption: 终止协程示例
    
    coroutine.kill(new MyCoroutineException());

    void coroutine_entry()
    {
        try {
            与远程主机通信();
        } catch (MyCoroutineException const &e) {
            // 异常处理
        }
    }
    
``CoroutineExit`` 异常由QtNetworkNg静默处理。


Qt GUI应用特别注意事项
----------------------

Qt GUI应用通常使用Qt事件循环：

.. code-block:: c++
    :caption: 典型Qt GUI应用
    
    #include <QApplication>
    
    int main(int argc, char **argv) {
        QApplication app(argc, argv);
        QWidget w;
        w.show();
        return app.exec();
    }

问题在于``app.exec()``启动的事件循环未被QtNetworkNg管理，会永久阻塞主协程。

解决方案是使用``startQtLoop()``替代``app.exec()``，将主协程转换为事件循环协程。

示例：异步加载网页内容

.. code-block:: c++
    :caption: 典型实现

    #include <QApplication>
    #include <QTextBrowser>
    #include "qtnetworkng/qtnetworkng.h"

    using namespace qtng;

    class HtmlWindow: public QTextBrowser
    {
    public:
        HtmlWindow()
            : operations(new CoroutineGroup)
        {
            operations->spawn([this] {
                Coroutine::sleep(1);
                加载新闻();
            });
        }

        ~HtmlWindow()
        {
            delete operations;
        }
    private:
        void 加载新闻()
        {
            HttpSession session;
            HttpResponse response = session.get("http://www.example.com/");
            if (response.isOk()) {
                setHtml(response.html());
            } else {
                setHtml("加载失败");
            }
        }
    private:
        CoroutineGroup *operations;
    };

    int main(int argc, char **argv)
    {
        QApplication app(argc, argv);
        HtmlWindow w;
        w.show();
        return startQtLoop();
    }


Socket与SslSocket
-----------------

QtNetworkNg旨在简化C++网络编程。 ``Socket`` 类是对BSD socket接口的面向对象封装。

``SslSocket`` 接口与``Socket``一致，在建立连接后执行SSL握手。

``Socket`` 和 ``SslSocket`` 可转换为``SocketLike``接口，便于统一处理。

``KcpSocket`` 实现基于UDP的KCP协议，提供类似``Socket``的API，同样支持``SocketLike``转换。


创建Socket客户端
^^^^^^^^^^^^^^^^

``Socket`` 提供两种构造函数：接受原生socket描述符或协议族/类型组合。

.. code-block:: c++
    :caption: 连接远程主机
    
    // 仅IPv4
    Socket s(Socket::IPv4Protocol, Socket::TcpSocket);
    bool ok = s.connect(remoteHost, 80);
    
    // 自动检测IPv4/IPv6
    QScopedPointer<Socket> s(Socket::createConnection(remoteHost, 80));
    bool ok = !s.isNull();
    
    Socket s(socketDescriptor); // socketDescriptor需设为非阻塞
    bool ok = s.connect(remoteHost, 80);
    
``SslSocket``构造函数需额外接受``SslConfiguration``：

.. code-block:: c++
    :caption: 连接SSL服务器
    
    // 仅IPv4
    SslConfiguration config;
    SslSocket s(Socket::IPv4Protocol, config);
    bool ok = s.connect(remoteHost, 443);
    
    // 自动检测
    SslConfiguration config;
    QScopedPointer<SslSocket> s(SslSocket::createConnection(remoteHost, 443, config));
    bool ok = !s.isNull();
    
    SslSocket s(socketDescriptor, config);
    bool ok = s.connect(remoteHost, 443);
    

创建Socket服务器
^^^^^^^^^^^^^^^^

结合协程可快速搭建服务器：

.. code-block:: c++
    :caption: TCP服务器
    
    QScopedPointer<Socket> s(Socket::createServer(HostAddress::AnyIPv4, 8000, 100));
    CoroutineGroup operations;
    while (true) {
        QSharedPointer<Socket> request(s->accept());
        if (request.isNull()) {
            break;
        }
        operations.spawn([request] {
            request->sendall("你好！");
        });
    }
    

HTTP客户端
-----------

QtNetworkNg提供支持HTTP1.1/HTTPS的客户端，支持SOCKS5代理、Cookie、重定向及JSON/form-data等数据类型。

HTTP 2.0支持正在规划中。

API设计灵感源自Python的*requests*模块。


获取HTTP资源
^^^^^^^^^^^^^^^^^^^^^^^^

使用``HttpSession``类进行HTTP通信：

.. code-block:: c++
    :caption: 获取网页
    
    qtng::HttpSession session;
    HttpResponse resp = session.get(url);
    
``HttpSession`` 会自动存储响应中的Cookie，保持会话状态。


提交数据到HTTP服务器
^^^^^^^^^^^^^^^^^^^^

常用方式为POST表单提交：

.. code-block:: c++
    :caption: 提交表单
    
    FormData data;
    data.addQuery("name", "fish");
    data.addFile("file", "filename.txt", QByteArray("文件内容"));
    HttpResponse resp = session.post(url, data.toByteArray());
    
或提交JSON数据：

.. code-block:: c++
    :caption: 提交JSON
    
    QJsonObject obj;
    obj.insert("name", "fish");
    HttpResponse resp = session.post(url, obj);
    
添加请求头：

.. code-block:: c++
    :caption: 带请求头提交
    
    QJsonObject obj;
    obj.insert("username", "somebody");
    obj.insert("password", "secret");
    QMap<QString, QString> headers;
    headers.insert("X-My-Header", "test");
    HttpResponse resp = session.post(url, obj, headers);


处理HTTP响应
^^^^^^^^^^^^

``HttpResponse`` 包含服务器返回的所有信息：

.. code-block:: c++
    :caption: 获取响应信息

    HttpResponse resp = session.get(url);
    qDebug() << resp.isOk();       // 无错误返回true
    qDebug() << resp.getContentType();  // 响应内容类型
    qDebug() << resp.statusCode();      // 状态码如200
    qDebug() << resp.statusText();      // 状态文本如OK
    
支持多种数据类型解析：

.. code-block:: c++
    :caption: 获取响应内容

    qDebug() << resp.text();        // UTF8字符串
    qDebug() << resp.json();        // QJsonDocument
    qDebug() << resp.html();        // UTF8字符串
    qDebug() << resp.body();        // 原始字节数据
    qDebug() << resp.bodyAsFile()   // 可读写的文件类对象


加密技术
--------

QtNetworkNg使用LibreSSL或OpenSSL提供加密功能。


消息摘要
^^^^^^^^^^^^^^

支持主流摘要算法：

.. code-block:: c++
    :caption: SHA512哈希计算

    MessageDigest m(MessageDigest::SHA512);
    m.update("data");
    qDebug() << m.hexDigest();
    

对称加密解密
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

支持AES、Blowfish、ChaCha20等算法：

.. code-block:: c++
    :caption: AES256_CBF加密
    
    Cipher ciph(Cihper::AES256, Cipher::CBF, Cipher::Encrypt);
    ciph.setPassword("密码", MessageDigest::Sha256, "盐值");
    QByteArray encrypted = ciph.update("fish");
    encrypted.append(ciph.final());

``Cipher::setPassword()``使用PBKDF2方法生成初始向量，需保存``Cipher::saltHeader()``。


非对称加密算法
^^^^^^^^^^^^^^

支持RSA/DSA密钥生成与管理：

.. code-block:: c++
    :caption: 生成RSA密钥

    PrivateKey key = PrivateKey::generate(PrivateKey::Rsa, 2048);
    qDebug() << key.sign("fish is here.", MessageDigest::SHA256);
    qDebug() << key.save();
    PrivateKey clonedKey = PrivateKey::load(key.save());

    
证书与证书请求
^^^^^^^^^^^^^^

支持SSL证书操作：

.. code-block:: c++
    :caption: 获取SSL证书信息

    Certificate cert = sslSocket.peerCertificate();
    qDebug() << cert.subjectInfo(Certificate::CommonName);
    Certificate clonedCert = Certificate::load(cert.save());