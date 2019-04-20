Introduction to QtNetworkNg
===========================

QtNetworkNg is a coroutine-based networking programming toolkit, like boost::asio but use concepts from QtNetwork and gevent of Python. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API.


Why Coroutines
--------------

The Coroutine is not a new thing, Python, Go, and C# was using coroutines to simplify network programming many years ago. 

The traditional network programming use threads. ``send()/recv()`` is blocked, and then the Operating System switch current thread to another ready thread until data arrived. This is very straightforward, and easy for network programming. But threads use heavy resources, thousands of connections may consume many memory. More worst, threads cause data races, data currupt, even crashes.

Another choice is use callback-based paradigm. Before calling ``send()/recv()``, use ``select()/poll()/epoll()`` to determine data arriving. Although ``select()`` is blocked, but many connections are handled in one thread. Callback-based paradigm is considered "the new-age goto", hard to understand and read/write code. But it is widely used by C++ programmer for the popularity of boost::asio and other traditional C++ networking programming frameworks.

Coroutine-based paradigm is the now and feature of network programming. Coroutine is light-weight thread which has its own stack, not managed by Operating System but QtNetworkNg. Like thread-based paradigm, ``send()/recv()`` is blocked, but switch to another coroutine in the same thread unitl data arrived. Many coroutines can be created at low cost. Because there is only one thread, no locks or other synchronization is needed. The API is straightforward like thread-based paradigm, but avoid the complexities of using threads.


Cross platforms
---------------

QtNetworkNg is tested in Linux, Android, Windows, OpenBSD. And support gcc, clang, mingw32. No dependence except Qt5 is required. Microsoft Visual C++ is not tested yet.

QtCore, QtNetwork is required to build QtNetworkNg. I am working hard to remove QtNetwork dependence.

The coroutine is implemented using boost::context asm code, and support native posix `ucontext` and windows `fiber` API. Running tests is successful in ARM, ARM64, x86, amd64.

In theory, QtNetworkNg can be ran in MacOS and iOS. But there is nothing I can do before I having a MacOS machine. And mips architecture would be supported.

The Qt eventloop can be replaced with libev eventloop, and SSL/cipher functions are enabled if you use cmake. In that case, embeded libev and LibreSSL is used.


Use QtNetworkNg in qmake projects
---------------------------------

Assume your Qt/qmake project is project *foo*, described in ``foo.pro``, and has a directory structure like this.

.. code-block:: text
    :caption: original content of project directory
    
    foo.pro
    main.cpp
    
Unlike other cpp library, QtNetworkNg encourages using git subrepository, clone QtNetworkNg from github and include the ``qtnetworkng.pri`` in your ``foo.pro`` like this.

.. code-block:: bash
    :caption: get qtnetworkng
    
    git clone https://github.com/hgoldfish/qtnetworkng.git

Now your project's directory structure.

.. code-block:: text
    :caption: contents of project directory.
    
    foo.pro
    main.cpp
    qtnetworkng/
        qtnetworkng.pri
        qtnetworkng.pro
        other files...
        
Edit your ``foo.pro`` to include ``qtnetworkng.pri``, but not ``qtnetworkng.pro``, because the ``qtnetworkng.pro`` file is exists for dynamic library build.

.. code-block:: text
    :caption: foo.pro

    QT += core network
    TARGET = foo
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
Edit ``main.cpp``.

.. code-block:: c++
    :caption: get web page.
    
    #include <QtCore/QCoreApplication>
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        HttpSession session;
        HttpResponse resp = session.get("http://www.example.com/");
        if (resp.isOk()) {
            qDebug() << resp.html();
        } else {
            qDebug() << "failed.";
        }
        return 0;\
    }

Now you can build *foo* as usual Qt/C++ project.

.. code-block:: bash
    :caption: build project
    
    qmake foo.pro
    make
    ./foo

    
Use QtNetworkNg in cmake projects
---------------------------------

Clone QtNetworkNg project from github, and create ``main.cpp``:

.. code-block:: bash

    git clone https://github.com/hgoldfish/qtnetworkng.git

An example of ``CMakeLists.txt``.

.. code-block:: cmake

    cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)
    project(foo)

    set(CMAKE_AUTOMOC ON)
    set(CMAKE_INCLUDE_CURRENT_DIR ON)

    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../ qtnetworkng)

    add_executable(foo main.cpp)
    target_link_libraries(foo qtnetworkng)


To build:

.. code-block:: bash
    :caption: build qtnetworkng
    
    mkdir build
    cd build
    cmake ..   # use full path to qmake if you want another qt version.
    make
    

The Coroutine 
-------------

QtNetworkNg is created base on the ``Coroutine``. Make sure QtNetworkNg's network operations is running in ``Coroutine``. Be convenient, the main thread is converted to Coroutine implicitly. There are two ways to create Coroutine. I strong recommend using ``CoroutineGroup``, as it use ``QSharedPointer`` to manage coroutines instead of raw pointer, and considers many corner cases.

.. code-block:: c++
    :caption: start coroutine
    
    void coroutine_entry()
    {
        Coroutine::sleep(1000); // sleep 1s
        qDebug() << "I am coroutine: " << Coroutine::current().id();
    }
    // I strong recommend using CoroutineGroup.
    CoroutineGroup operations;
    QSharedPointer<Coroutine> coroutine = operations.spawn(coroutine_entry);
    
    // Or manage coroutine yourself.
    QSharedPointer<Coroutine> coroutine = Coroutine::spawn(coroutine_entry);
    
Call ``Coroutine::start()`` schedule coroutine to start. And ``Coroutine::kill()`` to send exception to coroutine. Two function return immediately, while coroutine will start or be killed later.

The CoroutineGroup can spawn coroutines, and kill or get coroutines by name.

.. code-block:: c++
    :caption: manage many coroutines
    
    CoroutineGroup operations;
    operations.spawnWithName("coroutine1", coroutine_entry);
    operations.kill("coroutine1");
    operations.killall();

Killing coroutine safely is a big advanced feature of coroutine compare to thread and process. If coroutine is killed by other coroutine, it will throw a ``CoroutineExit`` exception. At your will, any exception based on ``CoroutineException`` can be thrown. Coroutine is killed and joined before deleted.

.. code-block:: c++
    :caption: how to kill coroutine
    
    coroutine.kill(new MyCoroutineException());

    void coroutine_entry()
    {
        try {
            communicate_with_remote_host();
        } catch (MyCoroutineException const &e) {
            // deal with exception.
        }
    }
    
The ``CoroutineExit`` exception is handled by QtNetworkNg silently.


Special Considerations for Qt GUI Application
---------------------------------------------

A Qt GUI Application typically use Qt eventloop.

.. code-block:: c++
    :caption: A typical Qt GUI Application
    
    #include <QApplication>
    
    int main(int argc, char **argv) {
        QApplication app(argc, argv);
        QWidget w;
        w.show();
        return app.exec();
    }

The problem is the ``app.exec()``. It runs an eventloop not managed by QtNetworkNg, and blocks main coroutine forever.

To solve this problem, please use ``startQtLoop()`` instead of ``app.exec()``, which turn main coroutine to eventloop coroutine.

This is an example to get content from url.

.. code-block:: c++
    :caption: A typical 

    #include <QApplication>
    #include <QTextBrowser>
    #include "qtnetworkng/qtnetworkng.h"

    using namespace qtng;

    class HtmlWindow: public QTextBrowser
    {
    public:
        HtmlWindow()
            :operations(new CoroutineGroup) {
            operations->spawn([this] {
                Coroutine::sleep(1);
                loadNews();
            });
        }

        ~HtmlWindow() {
            delete operations;
        }

    private:
        void loadNews() {
            HttpSession session;
            HttpResponse response = session.get("http://www.example.com/");
            if(response.isOk()) {
                setHtml(response.html());
            } else {
                setHtml("failed");
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


The Socket and SslSocket
------------------------

The main purpose to create QtNetworkNg is to simplify C++ network programming. There are many great networking programming toolkits already, like boost::asio, libco, libgo, poco, QtNetowrk and others. Many of them has complex callback-style API, or just simple coroutine implementations without Object Oriented socket API. 

The ``Socket`` class is a straightforward transliteration of the bsd socket interface to object-oriented interface. 

``SslSocket`` has the same interface as ``Socket``, but do ssl handshake after connection established.

``Socket`` and ``SslSocket`` objects can be converted to ``SocketLike`` objects, which are useful for functions accept both ``Socket`` and ``SslSocket`` parameter.

Note: ``Socket`` was designed to support any network families but now ipv4 and ipv6 is supported only, because QtNetworkNg is using ``QHostAddress`` now.

There is a ``KcpSocket`` implementing KCP over UDP. It has a simpliar API like ``Socket``, and support turning to ``SocketLike`` too.


Create Socket client
^^^^^^^^^^^^^^^^^^^^

``Socket`` class has two constructors. One accpets plain unix socket descriptor and another accpets protocol family and socket type.

.. code-block:: c++
    :caption: connect to remote host
    
    Socket s(Socket::AnyIPProtocol, Socket::TcpSocket);
    bool ok = s.connect(remoteHost, 80);
    
    Socket s(socketDescriptor); // socketDescriptor is set to nonblocking.
    bool ok = s.connect(remoteHost, 80);
    
The ``SslSocket`` has similar constructors which accpet an extra ``SslConfiguration``
    
.. code-block:: c++
    :caption: connect to remote ssl server.
    
    SslConfiguration config;
    SslSocket s(Socket::AnyIPProtocol, config);
    bool ok = s.connect(remoteHost, 443);
    
    SslSocket s(socketDescriptor, config);
    bool ok = s.connect(remoteHost, 443);
    
    
Create socket server
^^^^^^^^^^^^^^^^^^^^

Combine ``Socket`` and ``Coroutine``, you can create socket server in few lines of code.

.. code-block:: c++
    :caption: tcp server
    
    Socket s;
    CoroutineGroup operations;
    s.bind(QHostAddress::Any, 8000);
    s.listen(100);
    while(true) {
        QSharedPointer<Socket> request(s.accept());
        if(request.isNull()) {
            break;
        }
        operations.spawn([request] {
            request->sendall("hello!");
            request->close();
        });
    }
    
    
Http Client
-----------

QtNetworkNg provides a HTTP client support http 1.1 and https, can handle socks5 proxies, cookies, redirection and many data types such as JSON, form-data, etc..

HTTP 2.0 is planned.

The API are inspired by *requests* module of Python.


Get url from HTTP server
^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworkNg implement HTTP client in ``HttpSession`` class. To fetch data from or send data to HTTP server, you should create ``HttpSession`` object first.

.. code-block:: c++
    :caption: get web page
    
    qtng::HttpSession session;
    HttpResponse resp = session.get(url);
    
The ``HttpSession`` accept and store cookies from response, so sessions is persisted among HTTP requests. 


Send data to HTTP server
^^^^^^^^^^^^^^^^^^^^^^^^

The most common method to send data to HTTP server is making HTTP POST form data request.

.. code-block:: c++
    :caption: post query
    
    FormData data;
    data.addQuery("name", "fish");
    HttpResponse resp = session.post(url, data.toByteArray());
    
Or send json data.

.. code-block:: c++
    :caption: post file
    
    QJsonObject obj;
    obj.insert("name", "fish");
    HttpResponse resp = session.post(url, obj);
    
    
Get data from ``HttpResponse``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``HttpResponse`` contains all the data from HTTP server, such as headers, content, and status code.

.. code-block:: c++
    :caption: get response information

    HttpResponse resp = session.get(url);
    qDebug() << resp.getContentType();  // the content type of response.
    qDebug() << resp.statusCode;  // the status code of response: 200
    qDebug() << resp.statusText;  // the status text of response: OK
    
``HttpResponse`` can handle many data types.

.. code-block:: c++
    :caption: get response content

    qDebug() << resp.text();  // as QString
    qDebug() << resp.json();  // as QJsonDocument
    qDebug() << resp.html();  // as QString
    qDebug() << resp.body;  // as QByteArray


As crypto library
-----------------

QtNetworkNg can load OpenSSL dynamically, and provide many crypto routines.


Message Digest
^^^^^^^^^^^^^^

QtNetworkNg support most OpenSSL Message Digest.

.. code-block:: c++
    :caption: hash message using sha512

    MessageDigest m(MessageDigest::SHA512);
    m.update("data");
    qDebug() << m.hexDigest();
    
    
Symmetrical encryption and decryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworNg support many ciphers, such as AES, Blowfish, and ChaCha20.


.. code-block:: c++
    :caption: encrypt message using aes256_cbf
    
    Cipher ciph(Cihper::AES256, Cipher::CBF, Cipher::Encrypt);
    ciph.setPassword("thepassword", MessageDigest::Sha256, "salt");
    QByteArray encrypted = ciph.update("fish");
    encrypted.append(ciph.final());

``Cipher::setPassword()`` generate initial vector using PBKDF2 method. You should save ``Cipher::saltHeader()`` before saving the final data.


Public Key Algorithm
^^^^^^^^^^^^^^^^^^^^

QtNetworkNg can generate and manipulate RSA/DSA keys.

.. code-block:: c++
    :caption: generate rsa key

    PrivateKey key = PrivateKey::generate(PrivateKey::Rsa, 2048);
    qDebug() << key.sign("fish is here.", MessageDigest::SHA256);
    qDebug() << key.save();
    PrivateKey clonedKey = PrivateKey::load(key.save());

    
Certificate and CertificateRequest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworkNg can manipulate Certificate from ssl socket, or new-generated certificates.

.. code-block:: c++
    :caption: get ssl connection certificate.

    Certificate cert = sslSocket.peerCertificate();
    qDebug() << cert.subjectInfo(Certificate::CommonName);
    Certificate clonedCert = Certificate::load(cert.save());
    
