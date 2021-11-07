.. qtnetworkng documentation master file, created by
   sphinx-quickstart on Fri Nov 10 11:50:39 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to QtNetworkNg's documentation!
=======================================

Source Code
-----------

https://github.com/hgoldfish/qtnetworkng/

Author
------

Qize Huang <hgoldfish#gmail.com>

Feel free to send feedback to me.

A glance at QtNetworkNg
-----------------------

QtNetworkNg is a coroutine-based network toolkit, like boost::asio but uses concepts from QtNetwork and gevent of Python. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API. As the name suggests, QtNetworkNg requires Qt5 framework. Here comes a simple example to get web pages.

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
    
And another example to make IPv4 tcp connection.

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

To create IPv4 tcp server.

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

    
A Qt GUI example to fetch web page.

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
        return startQtLoop(); // Qt GUI application start the eventloop using startQtLoop() instead of app.exec()
    }

And its qmake project file.

.. code-block:: text

    # fetch_web_content.pro
    TEMPLATE = app
    QT += widgets
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
    
As you can see, networking programming is done with very straightforward API.

Give it a try (for linux). ::

    git clone https://github.com/hgoldfish/qtnetworkng.git
    cd qtnetworkng/examples/fetch_web_content/
    qmake-qt5
    make -j4   # mingw32-make -j4
    ./fetch_web_content


User Guide
==========

.. toctree::
   :maxdepth: 3

   intro
   practices
   references
   
   
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

