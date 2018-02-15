QtNetworkgNg is a self-contained coroutine-based network toolkit, like boost::asio but uses concepts of QtNetwork and gevent of Python. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API. As the name suggests, QtNetworkNg require Qt5 framework. Here comes a simple example to get web pages.

    #include <QtCore/QCoreApplication>
    #include "qtnetworkng/qtnetworkng.h"
    
    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        qtng::HttpSession session;
        qtng::HttpResponse r = session.get(QStringLiteral("https://news.163.com"));
        qDebug() << r.html();
        return 0;
    }
    
    
And another exmaple to make tcp connection.

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
    
As you can see, networking programming is done with very straightforward API.

An overview for install and using QtNetworkNg is here.

[Introduction to QtNetworkNg](docs/intro.rst)
