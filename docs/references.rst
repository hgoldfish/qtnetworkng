References of QtNetworkNg
=========================

1. Use Coroutines
-----------------

1.1 The Essential And Examples
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Coroutine is light-weight thread. In other programming languages, it is called *fiber*, *goroutine*, *greenlet*, etc. Coroutine has its own stack. One coroutine can yield(switch) to another coroutine manually.

.. code-block:: c++
    :caption: Example 1: switch between two BaseCoroutine

    // warning: yiled() is rarelly used, this is just an example showing the ability of coroutine.
    #include <qtnetworkng/qtnetworkng.h>
    #include <QCoreApplication>
    
    using namespace qtng;
    
    class MyCoroutine: public BaseCoroutine {
    public:
        MyCoroutine() {
            // remember the current coroutine which we will switch to.
            old = BaseCoroutine::current();
        }
        void run() {
            qDebug() << "my coroutine is here.";
            // switch to the main coroutine
            old->yield();
        }
    private:
        BaseCoroutine *old;
    };
    
    int main(int argc, char **argv) {
        QCoreApplication app(argc, argv);
        // once a new coroutine is created, the main thread is convert to main corotuine implicitly.
        MyCoroutine m;
        qDebug() << "main coroutine is here.";
        // switch to new coroutine, yield() function return until switch back.
        m.yield();
        qDebug() << "return to main coroutine.";
        return 0;
    }

In last example, we define a ``MyCoroutine`` which derived from ``BaseCoroutine`` first, and overwrite its ``run()`` member function. Be convenient, the main thread is converted to Coroutine implicitly. After create ``MyCoroutine`` object, we can yiled to it. The example output:

.. code-block:: text
    :caption: output of example 1

    main coroutine is here.
    my coroutine is here.
    return to main coroutine.
    do not delete running BaseCoroutine: QObject(0x7ffdfae77e40)

The last line is a warning which can be safely ignored for this example. Let's keep eyes on those two ``yield()`` function.

There is another ``BaseCoroutine::raise()`` function similar to ``BaseCoroutine::yield()`` function but send a ``CoroutineException`` to another coroutine. The target coroutine will throw that exception from its ``yield()``.

Now we know how to switch coroutine manually, but is useless for real-life programming. The ``yield()`` is rarelly used indeed. Instead, we use ``Coroutine::start()`` and ``Coroutine::kill()`` of ``Coroutine`` class.

QtNetworkNg's coroutine functions are splited to ``BaseCoroutine`` and ``Coroutine`` classes. The ``BaseCoroutine`` class implements the basic construction and ``yield()`` function to switch between coroutines. The ``Coroutine`` class derives from ``BaseCoroutine``. It use an extra eventloop coroutine, and introduce ``Coroutine::start()`` and ``Coroutine::kill()``.

If ``Coroutine::start()`` is called, the ``Coroutine`` schedules an event in the eventloop coroutine, and returns immediately. Once the current ``Coroutine`` is blocked in somewhere, such as ``Coroutine::join()``, ``Socket::recv()``, ``Socket::send()`` or ``Event::wait()``, the current coroutine will switch to eventloop coroutine. The eventloop coroutine process scheduled events, and start the coroutine which is schduled before.

Here comes an example showing two coroutines output message in turn. 

.. code-block:: c++
    :caption: Example 2: switch between two Coroutine.
    
    #include <QCoreApplication>
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    
    struct MyCoroutine: public Coroutine {
        MyCoroutine(const QString &name)
            : name(name) {}
        void run() override {
            for(int i = 0; i < 3; ++i) {
                qDebug() << name << i;
                // switch to eventloop coroutine, will switch back in 100 ms.
                msleep(100); 
            }
        }
        QString name;
    };
    
    int main(int argc, char **argv) {
        QCoreApplication app(argc, argv);
        MyCoroutine coroutine1("coroutine1");
        MyCoroutine coroutine2("coroutine2");
        coroutine1.start();
        coroutine2.start();
        // switch to the main coroutine
        coroutine1.join();
        // switch to the second coroutine to finish it.
        coroutine2.join();
        return 0;
    }
    
As you can see, ``join()`` and ``sleep()`` is blocking call, coroutine switching is taking place. This example outputs:

.. code-block:: text
    :caption: output of example 2
    
    "coroutine1" 0
    "coroutine2" 0
    "coroutine1" 1
    "coroutine2" 1
    "coroutine1" 2
    "coroutine2" 2

1.2 Start Coroutines
^^^^^^^^^^^^^^^^^^^^

.. note:: 

    Use ``CoroutineGroup::spawn()`` or ``CoroutineGroup::spawnWithName()`` to start and manage new coroutine.

There are many ways to start new coroutine. 

* Inherit ``Coroutine`` and override the ``Coroutine::run()`` function which will run in the new coroutine.
        
.. code-block:: c++
    :caption: Example 3: the first method to start coroutine
    
    class MyCoroutine: public Coroutine {
    public:
        virtual void run() override {
            // run in the new coroutine.
        }
    };
    
    void start() {
        MyCoroutine coroutine;
        coroutine.join();
    }
    
* Pass a function to ``Coroutine::spawn()`` function which returns the new coroutine. The passed function will be called in the new coroutine.

.. code-block:: c++
    :caption: Example 4: the second method to start coroutine
    
    void sendMessage() {
        // run in the new coroutine.
    }
    Coroutine *coroutine = Corotuine::spawn(sendMessage);
    
* The ``Coroutine::spawn()`` accepts ``std::function<void()>`` functor, so c++11 lambda is accepted either.

.. code-block:: c++
    :caption: Example 5: the third method to start coroutine
    
    QSharedPointer<Event> event(new Event);
    Coroutine *coroutine = Coroutine::spawn([event]{
        // run in the new coroutine.
    });
    
.. note::

    Captured objects must exists after the coroutine starts. More detail refer to Best Pracice.

* Pass a ``QObjet`` instance and `slot` name which is invoked in the new coroutine.
    
.. code-block:: c++
    :caption: Example 6: the forth method to start coroutine
    
    class Worker: public QObject {
        Q_OBJECT
    public slots:
        void sendMessage() {
            // run in the new coroutine.
        }
    };
    Worker worker;
    Coroutine coroutine(&worker, SLOT(sendMessage()));
    coroutine.join();
        
1.3 Operate Coroutines
^^^^^^^^^^^^^^^^^^^^^^

Most-used functions posist in ``Coroutine`` class.

.. function:: Coroutine::bool isRunning() const

    Check whether the coroutine is running now, return true or false.

.. function:: bool Coroutine::isFinished() const

    Check whether the coroutine is finished. If the coroutine is not started yet or running, this function returns false, otherwise returns `true`.

.. function:: Coroutine *Coroutine::start(int msecs = 0);

    Schedule the coroutine to start when current coroutine is blocked, and return immediately. The parameter ``msecs`` specifies how many microseconds to wait before the coroutine started, timing from ``start()`` is called. This function returns `this` coroutine object for chained call. For example:

    .. code-block:: c++
        :caption: Example 7: start coroutine
        
        QSharedPointer<Coroutine> coroutine(new MyCoroutine);
        coroutine->start()->join();

.. function:: void Coroutine::kill(CoroutineException *e = 0, int msecs = 0)

    Schedule the coroutine to raise exception ``e`` of type ``CoroutineException`` when current coroutine is blocked, and return immediately. The parameter ``msecs`` specifies how many microseconds to wait before the coroutine started, timing from ``kill()`` is called.

    If the parameter ``e`` is not specified, a ``CoroutineExitException`` will be sent to the coroutine.

    If the coroutine is not started yet, calling ``kill()`` may cause the coroutine start and throw an exception. If you don't want this behavior, use ``cancelStart()`` instead.

.. function:: void Coroutine::cancelStart()

    If the coroutine was scheduled to start, ``cancelStart()`` can cancel it. If the coroutine is started, ``cancelStart()`` kill the coroutine. After all, coroutine is set to ``Stop`` state.

.. function:: bool Coroutine::join()

    Block current coroutine and wait for the coroutine to stop. This function switch current coroutine to eventloop coroutine which runs the scheduled tasks, such as start new coroutines, check whether the socket can read/write.

.. function:: virtual void Coroutine::run()

    Override ``run()`` function to create new coroutine. Refer to *1.2 Start Coroutines*

.. function:: static Coroutine *Coroutine::current()

    This static function returns the current coroutine object. Do not save the returned pointer.

.. function:: static void Coroutine::msleep(int msecs)

    This static function block current coroutine, wake up after ``msecs`` microseconds.

.. function:: static void Coroutine::sleep(float secs)

    This static function block current coroutine, wake up after ``secs`` seconds.

.. function:: static Coroutine *Coroutine::spawn(std::function<void()> f)

    This static function start new coroutine from functor ``f``. Refer to *1.2 Start Coroutines*

The ``BaseCoroutine`` has some rarely used functions. Use them at your own risk.

.. function:: State BaseCoroutine::state() const

    Return the current state of coroutine. Can be one of ``Initialized``, ``Started``, ``Stopped`` and ``Joined``. Use this function is not encouraged, you may use `Coroutine::isRunning()` or ``Coroutine::isFinished()`` instead.
    
.. function:: bool BaseCoroutine::raise(CoroutineException *exception = 0)

    Switch to the coroutine immediately and throw an ``exception`` of type ``CoroutineException``. If the parameter ``exception`` is not specified, a ``CoroutineExitException`` is passed.
    
    Use the ``Coroutine::kill()`` is more roburst.
    
.. function:: bool BaseCoroutine::yield()

    Switch to the coroutine immediately.
    
    Use the ``Coroutine::start()`` is more roburst.
    
.. function:: quintptr BaseCoroutine::id() const

    Returns an unique imutable id for the coroutine. Basicly, the id is the pointer of coroutine.
    
.. function:: Deferred<BaseCoroutine*> BaseCoroutine::started`

    This is not a function but ``Deferred`` object. It acts like a Qt event. If you want to do something after the coroutine is started, add callback function to this ``started`` event.
    
.. function:: Deferred<BaseCoroutine*> BaseCoroutine::finished

    This is not a function but ``Deferred`` object. It acts like a Qt event. If you want to do something after the coroutine is finished, add callback function to this ``finished`` event.
    
1.4 Manage Many Coroutines Using CoroutineGroup
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Creating and deleting coroutine is complicated in C++ programming language, for the complicated memory management in C++. In general, always consider the resource used in coroutine can be deleted outside coroutine, and coroutines must exit before all the resource used are deleted.

Some rules must be followed.

* The immutable object captured by lambda must be passed by value, not pointer nor reference. 
* To capture a mutable object for lambda, should use smart pointer such as ``std::shared_ptr<>`` or ``QSharedPointer<>``.
* If ``this`` pointer is captured, coroutine must take care for the exists of ``this`` object.
* Delete coroutines before all used resource is deleted.

The use pattern of ``CoroutineGroup`` which is a utility class for managing many coroutines, follow these three rules.

* First, create a ``CoroutineGroup`` pointer filed in class, but not a value. Because C++ delete value implicitly.
* Second, delete ``CoroutineGroup`` in the destructor of class. before any other fields.
* The last, always spawn coroutine using ``CoroutineGroup``.

Here comes an example.

.. code-block:: c++
    :caption: using CoroutineGroup
    
    class MainWindow: public QMainWindow {
    public:
        MainWindow();
        virtual ~MainWindow() override;
    private:
        void loadDataFromWeb();
    private:
        QPlainText *textEdit;
        CoroutineGroup *operations; // a pointer, but not a value.
    };

    MainWindow::MainWindow()
        :textEdit(new QPlainText(this), operations(new CoroutineGroup)
    {
        setCentralWidget(textEdit);
        // always spawn coroutine using CoroutineGroup
        operations->spawn([this] {
            loadDataFromWeb();
        });
    }
    
    MainWindow::~MainWindow()
    {
        // always delete CorutineGroup before other field.
        delete operations;
        delete textEdit;
    }
    
    void MainWindow::loadDataFromWeb()
    {
        HttpSession session;
        textEdit->setPalinTex(session.get("https://news.163.com/").html();
    }
    
Functions in ``CorotuineGroup``.

.. function:: bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString())

    Add a coroutine which is specified by a smart pointer to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.
    
.. function:: bool add(Coroutine *coroutine, const QString &name = QString())

    Add a coroutine which is specified by a raw pointer to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.
    
.. function:: bool start(Coroutine *coroutine, const QString &name = QString())

    Start a coroutine, and add it to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.

.. function:: QSharedPointer<Coroutine> get(const QString &name)

    Fetch a coroutine by name. If no coroutine match the names, an empty pointer is return.
    
.. function:: bool kill(const QString &name, bool join = true)`

    Kill a coroutine by name and return true if coroutine is found. If the parameter ``join`` is true, the coroutine is joined and removed, otherwise this function is return immediately.

.. function:: bool killall(bool join = true)

    Kill all coroutines in group, and return true if any coroutine was killed. If the parameter `join` is true, the coroutine is joined and removed, otherwise this function is return immediately.

.. function:: bool joinall()

    Join all coroutines in group. and return true if any coroutine is joined.

.. function:: int size() const

    Return the number of corouitnes in group.

.. function:: bool isEmpty() const

    Return whether there is any coroutine in the group.

.. function:: QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func, bool one = true)`

    Start a new coroutine to run ``func``, and add it to group with ``name``. If the parameter ``one`` is true, and there is already a coroutine with the same name exists, no action is taken. This function return the new coroutine.
    
.. function:: QSharedPointer<Coroutine> spawn(const std::function<void()> &func)

    Start a new coroutine to run ``func``, and add it to group. This function return the new coroutine.

.. function:: QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool one = true)`

    Start a new thread to run ``func``. Create a new coroutine which waits for the new thread finishing, and add it to group with ``name``. If the parameter `one` is true, and there is alreay a coroutine with the same name exists, no action is taken. This function returns the new coroutine.

.. function:: QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func)

    Start a new thread to run ``func``. Create a new coroutine which waits for the new thread finishing, and add it to group. This function returns the new coroutine.

.. function:: static QList<T> map(std::function<T(S)> func, const QList<S> &l)

    Create many coroutines to process the content of ``l`` of type ``QList<>``. Each element in ``l`` is passed to ``func`` which run in new coroutine, and the return value of `func` is collected as return value of ``map()``.
    
    .. code-block:: c++
        :caption: map()
        
        #include <QCoreApplication>
        #include "qtnetworkng/qtnetworkng.h"

        int pow2(int i)
        {
            return i * i;
        }

        int main(int argc, char **argv)
        {
            QCoreApplication app(argc, argv);
            QList<int> range10;
            for(int i = 0; i < 10; ++i)
                range10.append(i);
            
            QList<int> result = qtng::CoroutineGroup::map<int,int>(pow2, range10);
            for(int i =0; i < 10; ++i)
                qDebug() << result[i];
            
            return 0;
        }
    
.. function:: void each(std::function<void(S)> func, const QList<S> &l)

    Create many coroutines to process the content of ``l`` of type ``QList``. Each element in ``l`` is passed to ``func`` which run in new coroutine.
    
    .. code-block:: c++
        :caption: each()
        
        #include <QCoreApplication>
        #include "qtnetworkng/qtnetworkng.h"

        void output(int i)
        {
            qDebug() << i;
        }

        int main(int argc, char **argv)
        {
            QCoreApplication app(argc, argv);
            QList<int> range10;
            for(int i = 0; i < 10; ++i)
                range10.append(i);
            CoroutineGroup::each<int>(output, range10);
            return 0;
        }

1.5 The Internal: How Coroutines Switch
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

2. Basic Network Programming
----------------------------

QtNetworkNg support IPv4 and IPV6. It is aim to provide an OOP Socket interface as the Python socket module.

In addition to basic socket interface, QtNetworkNg provide Socks5 proxy support, and a group of classes among `SocketServer` makeing server converently.

2.1 Socket
^^^^^^^^^^

Create socket is very simple, just instantiate ``Socket`` class. Or pass the platform-specific socket descriptor to constructor. 

.. code-block:: c++
    :caption: Socket constructor
    
    Socket(NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    
    Socket(qintptr socketDescriptor);
    
The parameter ``protocol`` can be used to restrict protocol to IPv4 or IPv6. If this parameter is ommited, ``Socket`` will determine the prefered protocol automatically, basically, IPv6 is chosen first. TODO: describe the mehtod.

The parameter ``type`` specify the socket type. Only TCP and UDP is supported now. If this parameter is ommited, TCP is used.

The second form of constructor is useful to convert socket which created by other network programming toolkits to QtNetworkNg socket. The passed socket must in connected state.

These are the member functions of ``Socket`` type.

.. function:: Socket *accept()

    If the socket is currently listening, ``accept()`` block current coroutine, and return new ``Socket`` object after new client connected. The returned new ``Socket`` object has connected to the new client. This function returns ``0`` to indicate the socket is closed by other coroutine.

.. function:: bool bind(QHostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to ``address`` and ``port``. If the parameter ``port`` is ommited, the Operating System choose an unused random port for you. The chosen port can obtained from ``port()`` function later. The parameter ``mode`` is not used now. 
    
    This function returns 

.. function:: bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to any address and ``port``. This function overloads ``bind(address, port)``.

.. function:: bool connect(const QHostAddress &host, quint16 port)

    Connect to remote host specified by parameters ``host`` and ``port``. Block current coroutine until the connection is established or failed.
    
    This function returns true if the connection is established.

.. function:: bool connect(const QString &hostName, quint16 port, NetworkLayerProtocol protocol = AnyIPProtocol)

    Connect to remote host specified by parameters ``hostName`` and ``port``, using ``protocol``. If ``hostName`` is not an IP address, QtNetworkNg will make a DNS query before connecting. Block current coroutine until the connection is established or failed.
    
    As the DNS query is a time consuming task, you might use ``setDnsCache()`` to cache query result if you connect few remote host frequently.
    
    If the parameter ``protocol`` is ommited or specified as ``AnyIPProtocol``, QtNetworkNg will first try to connect to IPv6 address, then try IPv4 if failed. If the DNS server returns many IPs, QtNetworkNg will try connecting to those IPs in order.
    
    This function returns true if the connection is established.

.. function:: bool close()

    Close the socket.

.. function:: bool listen(int backlog)

    The socket is set to listening mode. You can use ``accept()`` to get new client request later. The meaning of parameter ``backlog`` is platform-specific, refer to ``man listen`` please.

.. function:: bool setOption(SocketOption option, const QVariant &value)

    Set the given ``option`` to the value described by ``value``.
    
    The options can be  set on a socket.
    
    +---------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Name                               | Description                                                                                                                          |
    +====================================+======================================================================================================================================+
    | ``BroadcastSocketOption``          | UDP socket send broadcast datagram.                                                                                                  |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``AddressReusable``                | Indicates that the bind() call should allow reuse of local addresses.                                                                |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``ReceiveOutOfBandData``           | If this option is enabled, out-of-band data is directly placed into the receive data stream.                                         |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``ReceivePacketInformation``       | Reserved. Not supported yet.                                                                                                         |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``ReceiveHopLimit``                | Reserved. Not supported yet.                                                                                                         |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``LowDelayOption``                 | If set, disable the Nagle algorithm.                                                                                                 |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``KeepAliveOption``                | Enable sending of keep-alive messages on connection-oriented sockets. Expects an integer boolean flag.                               |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``MulticastTtlOption``             | Set or read the time-to-live value of outgoing multicast packets for this socket.                                                    |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``MulticastLoopbackOption``        | Set or read a boolean integer argument that determines whether sent multicast packets should be looped back to the local sockets.    |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``TypeOfServiceOption``            | Set or receive the Type-Of-Service (TOS) field that is sent with every IP packet originating from this socket.                       |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``SendBufferSizeSocketOption``     | Sets or gets the maximum socket send buffer in bytes.                                                                                |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``ReceiveBufferSizeSocketOption``  | Sets or gets the maximum socket receive buffer in bytes.                                                                             |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``MaxStreamsSocketOption``         | Reserved. STCP is not supported yet.                                                                                                 |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``NonBlockingSocketOption``        | Reserved. `Socket` internally require that socket is nonblocking.                                                                    |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    | ``BindExclusively``                | Reserved. Not supported yet.                                                                                                         |
    +------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
    
    Note: On Windows Runtime, Socket::KeepAliveOption must be set before the socket is connected.
    
.. function:: QVariant option(SocketOption option) const

    Returns the value of the option option.
    
    See also ``setOption()`` for more information.

.. function:: qint64 recv(char *data, qint64 size)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Returns the size of data received. This function returns `0` if connection is closed.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: qint64 recvall(char *data, qint64 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Returns the size of data received. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: qint64 send(const char *data, qint64 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until some data sent.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: qint64 sendall(const char *data, qint64 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Returns the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Returns the size of data received.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)

    Send ``size`` of ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: QByteArray recvall(qint64 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Returns the data received. Usually the size of returned value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``recvall(char*, qint64)``;

.. function:: QByteArray recv(qint64 size)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Returns the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recv(char*, qint64)``.

.. function:: qint64 send(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until some data sent.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``send(char*, qint64)``.

.. function:: qint64 sendall(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Returns the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``sendall(char*, qint64)``.

.. function:: QByteArray recvfrom(qint64 size, QHostAddress *addr, quint16 *port)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Returns the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recvfrom(char*, qint64, QHostAddress*, quint16*)``.

.. function:: qint64 sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)

    Send ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. function:: SocketError error() const

    Returns the type of error that last occurred.
    
    TODO: A error table.

.. function:: QString errorString() const
    
    Returns a human-readable description of the last device error that occurred.
    
.. function:: bool isValid() const

    Returns true if the socket is not closed.
    
.. function:: QHostAddress localAddress() const

    Returns the host address of the local socket if available; otherwise returns ``QHostAddress::Null``.
    
    This is normally the main IP address of the host, but can be ``QHostAddress::LocalHost`` (127.0.0.1) for connections to the local host.

.. function:: quint16 localPort() const

    Returns the host port number (in native byte order) of the local socket if available; otherwise returns `0`.
    
.. function:: QHostAddress peerAddress() const

    Returns the address of the connected peer if the socket is in ``ConnectedState``; otherwise returns ``QHostAddress::Null``.
    
.. function:: QString peerName() const

    Returns the name of the peer as specified by ``connect()``, or an empty ``QString`` if ``connect()`` has not been called.
    
.. function:: quint16 peerPort() const

    Returns the port of the connected peer if the socket is in ``ConnectedState``; otherwise returns `0`.
    
.. function:: qintptr fileno() const

    Returns the native socket descriptor of the ``Socket`` object if this is available; otherwise returns `-1`.
    
    The socket descriptor is not available when ``Socket`` is in ``UnconnectedState``.

.. function:: SocketType type() const

    Returns the socket type (TCP, UDP, or other).

.. function:: SocketState state() const

    Returns the state of the socket.
    
    TODO: a state table.

.. function:: NetworkLayerProtocol protocol() const

    Returns the protocol of the socket.

.. function:: static QList<QHostAddress> resolve(const QString &hostName)

    Make a DNS query to resolve the ``hostName``. If the ``hostName`` is an IP address, return the IP immediately.
    
.. function:: void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache)

    Set a ``SocketDnsCache`` to ``Socket`` object. Every call to ``connect(hostName, port)`` will check the cache first.
    
2.2 SslSocket
^^^^^^^^^^^^^

The ``SslSocket`` is designed to be similar to ``Socket``. It take most functions of ``Socket`` such as ``connect()``, ``recv()``, ``send()``, ``peerName()``, etc.. But exclude ``recvfrom()`` and ``sendto()`` which are only used for UDP socket.

There are three constructors to create ``SslSocket``.

.. code-block:: c++
    :caption: the constructors of SslSocket
    
    SslSocket(Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());
    

In addition, there are many function provided for obtain information from SslSocket.

.. function:: bool handshake(bool asServer, const QString &verificationPeerName = QString())

    Do handshake to other peer. If the parameter ``asServer`` is true, this ``SslSocket`` acts as SSL server.
    
    Use this function only if the ``SslSocket`` is created from plain socket.

.. function:: Certificate localCertificate() const

.. function:: QList<Certificate> localCertificateChain() const

.. function:: QByteArray nextNegotiatedProtocol() const

.. function:: NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const

.. function:: SslMode mode() const

.. function:: Certificate peerCertificate() const

.. function:: QList<Certificate> peerCertificateChain() const

.. function:: int peerVerifyDepth() const

.. function:: Ssl::PeerVerifyMode peerVerifyMode() const

.. function:: QString peerVerifyName() const

.. function:: PrivateKey privateKey() const

.. function:: SslCipher cipher() const

.. function:: Ssl::SslProtocol sslProtocol() const

.. function:: SslConfiguration sslConfiguration() const

.. function:: QList<SslError> sslErrors() const

.. function:: void setSslConfiguration(const SslConfiguration &configuration)


2.3 Socks5 Proxy
^^^^^^^^^^^^^^^^

2.4 SocketServer
^^^^^^^^^^^^^^^^


3. Http Client
--------------

3.1 HttpSession
^^^^^^^^^^^^^^^

3.2 HttpResponse
^^^^^^^^^^^^^^^^

3.3 HttpRequest
^^^^^^^^^^^^^^^

3.4 Socks5Proxy
^^^^^^^^^^^^^^^


4. Configuration And Build
--------------------------

4.1 Use libev Instead Of Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

4.2 Disable SSL Support
^^^^^^^^^^^^^^^^^^^^^^^
