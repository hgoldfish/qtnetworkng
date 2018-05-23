.. qtnetworkng documentation master file, created by
   sphinx-quickstart on Fri Nov 10 11:50:39 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to QtNetworkNg's documentation!
=======================================

QtNetworkNg is a self-contained coroutine-based network toolkit, like boost::asio but uses concepts from QtNetwork and gevent of Python. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API. As the name suggests, QtNetworkNg requires Qt5 framework. Here comes a simple example to get web pages.

.. code-block:: c++
    
    #include <QtCore/QCoreApplication>
    #include "qtnetworkng/qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get("https://news.163.com");
        qDebug() << r.html();
        return 0;
    }
    
And another example to make tcp connection.

.. code-block:: c++
    
    #include <QtCore/QCoreApplication>
    #include "qtnetworkng/qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        qtng::Socket conn;
        conn.connect("news.163.com", 80);
        conn.sendall("GET / HTTP/1.0\r\n\r\n");
        qDebug() << conn.recv(1024 * 8);
        return 0;
    }

To create tcp server.

.. code-block:: c++
    
    Socket s;
    CoroutineGroup workers;
    s.bind(QHostAddress::Any, 8000);
    s.listen(100);
    while(true) {
        QSharedPointer<Socket> request(s.accept());
        if(request.isNull()) {
            break;
        }
        workers.spawn([request] {
            request->sendall("hello!");
            request->close();
        });
    }
    
As you can see, networking programming is done with very straightforward API.

Give it a try (for linux). ::

    git clone https://github.com/hgoldfish/qtnetworkng.git
    cd qtnetworkng/
    qmake-qt5
    make -j4   # mingw32-make -j4
    ./qtnetworkng
    
More details please refer to these documents:

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

