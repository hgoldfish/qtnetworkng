Introduction to QtNetworkNg
===========================

QtNetworkgNg is a coroutine-based network toolkit, like boost::asio but use concept of QtNetwork and gevent of Python. Compare to boost::asio and Qt's QtNetwork, QtNetworkNg has more simpler API.


Cross platforms
---------------

QtNetowrkNg is tested in linux, android, windows, openbsd. And support gcc, clang. No dependence except Qt5 is required. If `SslSocket` is used, the dynmaic library file of OpenSSL above 1.0.0 is required in runtime. However, QtNetowrkNg do not require OpenSSL for building.

QtCore, QtNetwork is required to build QtNetworkNg. I am working hard to remove QtNetwork dependence.

The coroutine is implemented using boost::context asm code, and support native posix ucontext and windows fiber API. Running tests is successful in ARM, ARM64, x86, amd64.

In theory, QtNetowrkNg can be ran in macos and ios. But there is nothing I can do before I having macos machine. And mips architecture would be supported.

Use QtNetworkNg in qmake projects
--------------------------------

Assume your Qt/qmake project is project *foo*, described in `foo.pro`, and has a directory structure like this::

    foo.pro
    main.cpp
    
Unlike other cpp library, QtNetworkNg encourages using git subrepository, clone QtNetworkNg from github and include the qtnetworkng.pri in your foo.pro like this::

    git clone https://github.com/hgoldfish/qtnetworkng.git

Now your project's directory structure::

    foo.pro
    main.cpp
    qtnetworkng/
        qtnetworkng.pri
        qtnetworkng.pro
        other files...
        
Edit your foo.pro to include `qtnetworkng.pri`, but not `qtnetworkng.pro`, because the `.pro` file is exists for dynamic library build.::

    # foo.pro
    QT += core gui widgets
    TARGET = foo
    SOURCES += main.cpp
    include(qtnetworkng/qtnetworkng.pri)
    
Now you can use QtNetworkNg as usual cpp library.

.. Use QtNetworkNg in ordinary cpp projects
.. ----------------------------------------
.. 
.. If you want a traditional cpp library usage, please download QtNetworkNg, build and install it. ::
.. 
..     git clone https://github.com/hgoldfish/qtnetworkng.git
..     cd qtnetworkng
.. 
.. QtNetworkNg support qmake and cmake, which follow the similar build flow. ::
.. 
..     mkdir build
..     cd build
..     qmake ..
..     make -j8
..     make install
..     
.. Replace `qmake` with `cmake` if you use cmake.
.. 
.. Edit your foo.pro to link to `qtnetworkng`. ::
.. 
..     # foo.pro
..     QT += core gui widgets
..     TARGET += foo
..     SOURCES += main.cpp
..     LIBS += qtnetworkng
    
The Coroutine 
-------------

QtNetworkNg is created base on the **Coroutine**. Make sure QtNetworkNg's network operations is running in `Coroutine`. Be convenient, the main thread is converted to Coroutine implicitly. There are two ways to create `Coroutine`. I strong recommend using **CoroutineGroup**, as it use `QSharedPointer` to manage coroutines instead of raw pointer, and considers many corner cases. ::

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
    
Call `Coroutine::start()` schedule coroutine to start. And `Coroutine::kill()` to send exception to coroutine.

The CoroutineGroup can spawn coroutines, and kill or get coroutines by name. ::

    CoroutineGroup operations;
    operations.spawnWithName("coroutine1", coroutine_entry);
    operations.kill("coroutine1");
    operations.killall();

Killing coroutine safely is a big advanced feature of coroutine compare to thread and process. If coroutine is killed by other coroutine, is will throw a `CoroutineExit` exception. At your will, any exception based on `CoroutineException` can be thrown. Coroutine is killed and joined before deleted. ::

    coroutine.kill(new MyCoroutineException());

    void coroutine_entry()
    {
        try {
            communicate_with_remote_host();
        } catch (MyCoroutineException const &e) {
            // deal with exception.
        }
    }
    
The `CoroutineExit` exception is handled by QtNetworkNg silently.

The Socket and SslSocket
------------------------

The main purpose to create QtNetworkNg is to simplify C++ network programming. There are many great networking programming toolkits already, like boost::asio, libco, libgo, poco, QtNetowrk and others. Many of them has complex callback-style API, or just simple coroutine implementations without Object Oriented socket API. 

The `Socket` class is a straightforward transliteration of the bsd socket interface to object-oriented interface. It was designed to support any network families but now ipv4 and ipv6 is supported only, because QtNetowrkNg is using QHostAddress now.

`SslSocket` has the same interface as `Socket`, but do ssl handshake after connection established.

`Socket` and `SslSocket` objects can be converted to `SocketLike` objects, which are useful for functions accept both `Socket` and `SslSocket` parameter.

Create Socket client
^^^^^^^^^^^^^^^^^^^^

`Socket` class has two constructors. One accpets plain unix socket descriptor and another accpets protocol family and socket type. ::

    Socket s(Socket::AnyIPProtocol, Socket::TcpSocket);
    bool ok = s.connect(remoteHost, 80);
    
    Socket s(socketDescriptor); // socketDescriptor is set to nonblocking.
    bool ok = s.connect(remoteHost, 80);
    
The `SslSocket` has similar constructors which accpet an extra `SslConfiguration`. ::
    
    SslConfiguration config;
    SslSocket s(Socket::AnyIPProtocol, config);
    bool ok = s.connect(remoteHost, 443);
    
    SslSocket s(socketDescriptor, config);
    bool ok = s.connect(remoteHost, 443);
    
Create socket server
^^^^^^^^^^^^^^^^^^^^

Combine `Socket` and `Coroutine`, you can create socket server in few lines of code::

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

QtNetworkNg provides a HTTP client support http 1.0 and https, and handle cookies, redirection and many data types such as JSON, form-data, etc..

HTTP 1.1 pipeline and HTTP 2.0 is planned.

Many concepts are inspired by *requests* module of Python.

Get url from HTTP server
^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworkNg implement HTTP client in `HttpSession` class. To fetch data from or send data to HTTP server, you should create `HttpSession` object first. ::

    qtng::HttpSession session;
    HttpResponse resp = session.get(url);
    
The `HttpSession` accept and store cookies from data, so sessions is persisted among HTTP requests. 

Send data to HTTP server
^^^^^^^^^^^^^^^^^^^^^^^^

The most common method to send data to HTTP server is making HTTP POST form data request. ::

    FormData data;
    data.addQuery("name", "fish");
    HttpResponse resp = session.post(url, data.toByteArray());
    
Or send json data. ::

    QJsonObject obj;
    obj.insert("name", "fish");
    HttpResponse resp = session.post(url, obj);
    
Retieve data from `HttpResponse`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`HttpResponse` contains all the data from HTTP server, such as headers, content, and status code. ::

    HttpResponse resp = session.get(url);
    qDebug() << resp.getContentType();  // the content type of response.
    qDebug() << resp.statusCode;  // the status code of response: 200
    qDebug() << resp.statusText;  // the status text of response: OK
    
`HttpResponse` can handle many data types. ::

    qDebug() << resp.text();  // as QString
    qDebug() << resp.json();  // as QJsonDocument
    qDebug() << resp.html();  // as QString
    qDebug() << resp.body;  // as QByteArray


As crypto library
-----------------

QtNetworkNg can load OpenSSL dynamically, and provide many crypto routines.

Message Digest
^^^^^^^^^^^^^^

QtNetworkNg support most OpenSSL Message Digest. ::

    MessageDigest m(MessageDigest::SHA512);
    m.update("data");
    qDebug() << m.hexDigest();
    
Symmetrical encryption and decryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworNg support many ciphers, such as AES, Blowfish, and ChaCha20. ::

    Cipher ciph(Cihper::AES256, Cipher::ECB);
    ciph.setPassword("thepassword");
    ciph.addData("fish");
    qDebug() << ciph.saltHeader() << ciph.finalData();

`Cipher::setPassword()` generate initial vector using PBKDF2 method. You should save `Cipher::saltHeader()` before save the final data.


Public Key Algorithm
^^^^^^^^^^^^^^^^^^^^

QtNetworkNg can generate and manipulate RSA/DSA keys. ::

    PrivateKey key = PrivateKey::generate(PrivateKey::Rsa, 2048);
    qDebug() << key.sign("fish is here.", MessageDigest::SHA512);
    qDebug() << key.save();
    PrivateKey clonedKey = PrivateKey::load(key.save());

Certificate and CertificateRequest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

QtNetworkNg can manipulate Certificate from ssl socket, or new-generated certificates. ::

    Certificate cert = sslSocket.peerCertificate();
    qDebug() << cert.subjectInfo(Certificate::CommonName);
    Certificate clonedCert = Certificate::load(cert.save());
    
