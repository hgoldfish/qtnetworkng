.. qtnetworkng documentation master file, created by
   sphinx-quickstart on Fri Nov 10 11:50:39 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

欢迎来到QtNetworkNg的文档！
========================================

源代码
-----------

https://github.com/hgoldfish/qtnetworkng/

语言
--------

选择文档阅读语言

English:    https://qtng.org/index.html

中文:       https://qtng.org/index.HANS.html



作者
------

Qize Huang <hgoldfish#gmail.com>

欢迎发送反馈至我的邮箱。

QtNetworkNg一览
-----------------------

QtNetworkNg是基于协程的网络工具包，类似boost::asio但借鉴了QtNetwork和Python gevent的设计理念。与boost::asio和Qt的QtNetwork相比，QtNetworkNg提供了更简洁的API。正如其名，QtNetworkNg需要Qt5框架支持。以下是一个获取网页的简单示例：

.. code-block:: c++
    
    #include <QtCore/qdebug.h>
    #include "qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get("http://www.example.com/");
        if (r.isOk()) {
            qDebug() << r.html();
        } else {
            qDebug() << "failed.";
        }
        return 0;
    }

另一个建立IPv4 TCP连接的示例：

.. code-block:: c++
    
    #include <QtCore/qdebug.h>
    #include "qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        qtng::Socket conn;
        conn.connect("news.163.com", 80);
        conn.sendall("GET / HTTP/1.0\r\n\r\n");
        qDebug() << conn.recv(1024 * 8);
        return 0;
    }

创建IPv4 TCP服务器的示例：

.. code-block:: c++
    
    Socket s;
    CoroutineGroup workers;
    s.bind(HostAddress::AnyIPv4, 8000);
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

Qt GUI获取网页的示例：

.. code-block:: c++

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
        : operations(new CoroutineGroup)
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
        return startQtLoop(); // Qt GUI应用使用startQtLoop()启动事件循环而非app.exec()
    }

对应的qmake项目文件：

.. code-block:: text

    # fetch_web_content.pro
    TEMPLATE = app
    QT += widgets
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
可见，网络编程通过非常直观的API即可完成。

尝试运行（Linux环境）::

    git clone https://github.com/hgoldfish/qtnetworkng.git
    cd qtnetworkng/examples/fetch_web_content/
    qmake-qt5
    make -j4   # mingw32-make -j4
    ./fetch_web_content


用户指南
==========

.. toctree::
   :maxdepth: 3

   intro.HANS
   practices.HANS
   references.HANS
   
   
索引和表格
==================

• :ref:`genindex`
• :ref:`modindex`
• :ref:`search`