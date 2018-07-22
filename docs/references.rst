References of QtNetworkNg
=========================

1. Use Coroutines
-----------------

1.1 The Essential And Examples
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Coroutine is light-weight thread. In other programming languages, it is called *fiber*, *goroutine*, *greenlet*, etc. Coroutine has its own stack. One coroutine can yield(switch) to another coroutine manually.

.. code-block:: c++
    :caption: Example 1: switch between two BaseCoroutine

    // warning: yield() is rarelly used, this is just an example showing the ability of coroutine.
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

In last example, we define a ``MyCoroutine`` which derived from ``BaseCoroutine`` first, and overwrite its ``run()`` member function. Be convenient, the main thread is converted to Coroutine implicitly. After create ``MyCoroutine`` object, we can yield to it. The example output:

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

.. method:: bool Coroutine::isRunning() const

    Check whether the coroutine is running now, return true or false.

.. method:: bool Coroutine::isFinished() const

    Check whether the coroutine is finished. If the coroutine is not started yet or running, this function returns false, otherwise returns `true`.

.. method:: Coroutine *Coroutine::start(int msecs = 0);

    Schedule the coroutine to start when current coroutine is blocked, and return immediately. The parameter ``msecs`` specifies how many microseconds to wait before the coroutine started, timing from ``start()`` is called. This function returns `this` coroutine object for chained call. For example:

    .. code-block:: c++
        :caption: Example 7: start coroutine
        
        QSharedPointer<Coroutine> coroutine(new MyCoroutine);
        coroutine->start()->join();

.. method:: void Coroutine::kill(CoroutineException *e = 0, int msecs = 0)

    Schedule the coroutine to raise exception ``e`` of type ``CoroutineException`` when current coroutine is blocked, and return immediately. The parameter ``msecs`` specifies how many microseconds to wait before the coroutine started, timing from ``kill()`` is called.

    If the parameter ``e`` is not specified, a ``CoroutineExitException`` will be sent to the coroutine.

    If the coroutine is not started yet, calling ``kill()`` may cause the coroutine start and throw an exception. If you don't want this behavior, use ``cancelStart()`` instead.

.. method:: void Coroutine::cancelStart()

    If the coroutine was scheduled to start, ``cancelStart()`` can cancel it. If the coroutine is started, ``cancelStart()`` kill the coroutine. After all, coroutine is set to ``Stop`` state.

.. method:: bool Coroutine::join()

    Block current coroutine and wait for the coroutine to stop. This function switch current coroutine to eventloop coroutine which runs the scheduled tasks, such as start new coroutines, check whether the socket can read/write.

.. method:: virtual void Coroutine::run()

    Override ``run()`` function to create new coroutine. Refer to *1.2 Start Coroutines*

.. method:: static Coroutine *Coroutine::current()

    This static function returns the current coroutine object. Do not save the returned pointer.

.. method:: static void Coroutine::msleep(int msecs)

    This static function block current coroutine, wake up after ``msecs`` microseconds.

.. method:: static void Coroutine::sleep(float secs)

    This static function block current coroutine, wake up after ``secs`` seconds.

.. method:: static Coroutine *Coroutine::spawn(std::function<void()> f)

    This static function start new coroutine from functor ``f``. Refer to *1.2 Start Coroutines*

The ``BaseCoroutine`` has some rarely used functions. Use them at your own risk.

.. method:: State BaseCoroutine::state() const

    Return the current state of coroutine. Can be one of ``Initialized``, ``Started``, ``Stopped`` and ``Joined``. Use this function is not encouraged, you may use `Coroutine::isRunning()` or ``Coroutine::isFinished()`` instead.
    
.. method:: bool BaseCoroutine::raise(CoroutineException *exception = 0)

    Switch to the coroutine immediately and throw an ``exception`` of type ``CoroutineException``. If the parameter ``exception`` is not specified, a ``CoroutineExitException`` is passed.
    
    Use the ``Coroutine::kill()`` is more roburst.
    
.. method:: bool BaseCoroutine::yield()

    Switch to the coroutine immediately.
    
    Use the ``Coroutine::start()`` is more roburst.
    
.. method:: quintptr BaseCoroutine::id() const

    Returns an unique imutable id for the coroutine. Basicly, the id is the pointer of coroutine.
    
.. method:: BaseCoroutine *BaseCoroutine::previous() const

    Returns an pointer of ``BaseCoroutine`` which will switch to after this coroutine finished.
    
.. method:: void BaseCoroutine::setPrevious(BaseCoroutine *previous)

    Set the pointer of ``BaseCoroutine`` which will switch to after this coroutine finished.
    
.. method:: Deferred<BaseCoroutine*> BaseCoroutine::started`

    This is not a function but ``Deferred`` object. It acts like a Qt event. If you want to do something after the coroutine is started, add callback function to this ``started`` event.
    
.. method:: Deferred<BaseCoroutine*> BaseCoroutine::finished

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

.. method:: bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString())

    Add a coroutine which is specified by a smart pointer to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.
    
.. method:: bool add(Coroutine *coroutine, const QString &name = QString())

    Add a coroutine which is specified by a raw pointer to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.
    
.. method:: bool start(Coroutine *coroutine, const QString &name = QString())

    Start a coroutine, and add it to group. If the parameter ``name`` is specified, we can use ``CoroutineGroup::get(name)`` to fetch the coroutine later.

.. method:: QSharedPointer<Coroutine> get(const QString &name)

    Fetch a coroutine by name. If no coroutine match the names, an empty pointer is return.
    
.. method:: bool kill(const QString &name, bool join = true)`

    Kill a coroutine by name and return true if coroutine is found. If the parameter ``join`` is true, the coroutine is joined and removed, otherwise this function is return immediately.

.. method:: bool killall(bool join = true)

    Kill all coroutines in group, and return true if any coroutine was killed. If the parameter `join` is true, the coroutine is joined and removed, otherwise this function is return immediately.

.. method:: bool joinall()

    Join all coroutines in group. and return true if any coroutine is joined.

.. method:: int size() const

    Return the number of corouitnes in group.

.. method:: bool isEmpty() const

    Return whether there is any coroutine in the group.

.. method:: QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func, bool replace = false)`

    Start a new coroutine to run ``func``, and add it to group with ``name``. If the parameter ``replace`` is false, and there is already a coroutine with the same name exists, no action is taken. Otherwise, if there is already a coroutine with the same name exists, the old one is returned. This function returns the new coroutine.
    
.. method:: QSharedPointer<Coroutine> spawn(const std::function<void()> &func)

    Start a new coroutine to run ``func``, and add it to group. This function return the new coroutine.

.. method:: QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool replace = false)`

    Start a new thread to run ``func``. Create a new coroutine which waits for the new thread finishing, and add it to group with ``name``. If the parameter ``replace`` is false, and there is already a coroutine with the same name exists, no action is taken. Otherwise, if there is already a coroutine with the same name exists, the old one is returned. This function returns the new coroutine.

.. method:: QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func)

    Start a new thread to run ``func``. Create a new coroutine which waits for the new thread finishing, and add it to group. This function returns the new coroutine.

.. method:: static QList<T> map(std::function<T(S)> func, const QList<S> &l)

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
    
.. method:: void each(std::function<void(S)> func, const QList<S> &l)

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

        
1.5 Communicate Between Two Coroutine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The most significant advantage of QtNetworkNg with respect to `boost::coroutine` is that QtNetworkNg has a well-established coroutine communication mechanism.

1.5.1 RLock
+++++++++++

`Reentrant Lock` is a mutual exclusion (mutex) device that may be locked multiple times by the same coroutine, without causing a deadlock.

.. _Reentrant Lock: https://en.wikipedia.org/wiki/Reentrant_mutex

``Lock``, ``RLock``, ``Semaphore`` are usually acquired and released using ``ScopedLock<T>`` which releases locks before function returns.

.. code-block:: c++
    :caption: using RLock
    
    #include <QtCore/qcoreapplication.h>
    #include "qtnetworkng/qtnetworkng.h"
    
    void output(QSharedPointer<RLock> lock, const QString &name)
    {
        ScopedLock l(*lock);    // acquire lock now, release before function returns. comment out this line and try again later.
        qDebug() << name << 1;
        Coroutine::sleep(1.0);
        qDebug() << name << 2;
        lock.release();
    }
    
    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        QSharedPointer<RLock> lock(new RLock);
        QCoroutineGroup operations;
        operations.spawn([lock]{
            output(lock, "first");
        });
        operations.spawn([lock]{
            output(lock, "second");
        });
        return 0;
    }
    
The output is

.. code-block:: text
    :caption: output of using RLock
    
    "first" 1
    "first" 2
    "second" 1
    "second" 2

If you comment out the line ``ScopedLock l(*lock);``, the output is:

.. code-block:: text
    :caption: output without RLock
    
    "first" 1
    "second" 1
    "first" 2
    "second" 2

.. method:: bool acquire(bool blocking = true)

    Acquire the lock. If the lock is acquired by other coroutine, and the paremter ``blocking`` is true, block current coroutine until the lock is released by other coroutine. Otherwise this function returns immediately.
    
    Returns whether the lock is acquired.
    
.. method:: void release()

    Release the lock. The coroutine waiting at this lock will resume after current coroutine switching to eventloop coroutine later.
    
.. method:: bool isLocked() const

    Check whether any coroutine hold this lock.
    
.. method:: bool isOwned() const

    Check whether current coroutine hold this lock.

1.5.2 Event
+++++++++++

An `Event` (also called event semaphore) is a type of synchronization mechanism that is used to indicate to waiting coroutines when a particular condition has become true.

.. _Event: https://en.wikipedia.org/wiki/Event_(synchronization_primitive)

.. method:: bool wait(bool blocking = true)

    Waiting event. If this ``Event`` is not set, and the parameter ``blocking`` is true, block current coroutine until this event is set. Otherwise returns immediately.
    
    Returns whether the event is set.
    
.. method:: void set()

    Set event. The coroutine waiting at this event will resume after current coroutine switching to eventloop coroutine later.
    
.. method:: void clear()

    Clear event.
    
.. method:: bool isSet() const

    Check whether this event is set.
    
.. method:: int getting() const

    Get the number of coroutines waiting at this event.
    
1.5.3 ValueEvent<>
++++++++++++++++++

``ValueEvent<>`` extends ``Event``. Two coroutines can use ``ValueEvent<>`` to send value.

.. code-block:: c++
    :caption: use ValueEvent<> to send value.
    
    #include <QtCore/qcoreapplication.h>
    #include "qtnetworkng/qtnetworkng.h"

    using namespace qtng;

    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        QSharedPointer<ValueEvent<int>> event(new ValueEvent<int>());
        
        CoroutineGroup operations;
        operations.spawn([event]{
            qDebug() << event->wait();
        });
        operations.spawn([event]{
            event->send(3);
        });
        return 0;
    }

The output is:

.. code-block:: text

    3

.. method:: void send(const Value &value)
    
    Send a value to other coroutine, and set this event.
    
    The coroutines waiting at this event will resume after current coroutine switching to eventloop coroutine.
    
.. method:: Value wait(bool blocking = true)
    
    Waiting event. If this ``Event`` is not set, and the parameter ``blocking`` is true, block current coroutine until this event is set. Otherwise returns immediately.
    
    Returns the value sent by other coroutine. If failed, construct a value usning default constructor.
    
.. method:: void set()

    Set event. The coroutines waiting at this event will resume after current coroutine switching to eventloop coroutine.
    
.. method:: void clear()

    Clear event.
    
.. method:: bool isSet() const

    Check whether this event is set.
    
.. method:: int getting() const

    Get the number of coroutines waiting at this event.
    
1.5.4 Gate
++++++++++

``Gate`` is a special interface to ``Event``. This type can be used to control data transmit rate.

.. method:: bool goThrough(bool blocking = true)

    It is the same as ``Event::wait()``.
    
.. method:: bool wait(bool blocking = true)

    It is the same as ``Event::wait()``.
    
.. method:: void open();

    It is the same as ``Event::set()``.
    
.. method:: void close();

    It is the same as ``Event::clear()``.
    
.. method:: bool isOpen() const;

    It is the same as ``Event::isSet()``.
    
1.5.5 Semaphore
+++++++++++++++

A `semaphore` is a variable or abstract data type used to control access to a common resource by multiple coroutines.

.. _semaphore: https://en.wikipedia.org/wiki/Semaphore_(programming)

.. code-block:: c++
    :caption: using Semaphore to control the concurrent number of request.
    
    #include <QtCore/qcoreapplication.h>
    #include "qtnetworkng/qtnetworkng.h"

    using namespace qtng;

    void send_request(QSharedPointer<Semaphore> semaphore)
    {
        ScopedLock<Semaphore> l(*semaphore);
        HttpSession session;
        qDebug() << session.get("https://news.163.com").statusCode;
    }

    int main(int argc, char **argv)
    {
        QCoreApplication app(argc, argv);
        QSharedPointer<Semaphore> semaphore(new Semaphore(5));
        
        CoroutineGroup operations;
        for(int i = 0; i < 100; ++i) {
            operations.spawn([semaphore]{
                send_request(semaphore);
            });
        }
        return 0;
    }

The last example spawns 100 corotuines, but only 5 coroutines is making request to http server.

.. method:: Semaphore(int value = 1)

    This constructor requires a ``value`` indicating the maximum number of resources.
    
.. method:: bool acquire(bool blocking = true)

    Acquire the semaphore. If all resouces are used, and the parameter ``blocking`` is true, blocks current coroutine until any other coroutine release a resource. Otherwise this function returns immediately.
    
    Returns whether the semaphore is acquired.
    
.. method:: void release()

    Release the semaphore. The coroutine waiting at this semaphore will resume after current coroutine switching to eventloop coroutine later.

.. method:: bool isLocked() const
    
    Check whether this semaphore is hold by any coroutine.
    
1.5.6 Queue
+++++++++++
    
A queue between two coroutines.

.. method:: Queue(int capacity)

This constructor requires a ``capacity`` indicating the maximum number of elements can hold.

.. method:: void setCapacity(int capacity)

Set the the maximum number of elements this queue can hold.

.. method:: bool put(const T &e)

Put a element ``e`` to this queue. If the size of queue reaches the capacity, blocks current coroutine until any other coroutine take elements from this queue.

.. method:: T get()

Get (take) a element from this queue. If this queue is empty, blocks current coroutine until any other coroutine put elements to this queue.

.. method:: bool isEmpty() const

Check whether this queue is empty.

.. method:: bool isFull() const

Check whether this queue reaches the maximum size.

.. method:: int getCapacity() const

Get the capacity of this queue.

.. method:: int size() const

Returns how many elements in this queue.

.. method:: int getting() const

Returns the number of coroutines waiting for elements.

1.5.7 Lock
++++++++++

The ``Lock`` is similar to ``RLock``, but cause dead lock if same corotine locks twice.

1.5.8 Condition
+++++++++++++++

Monitor variable value between coroutines.

.. method:: bool wait()

Block current coroutine until being waked up by ``notify()`` or ``notifyAll()`` by other corotuines.

.. method:: void notify(int value = 1)

Wake up coroutines. The number of coroutines is indicated by ``value``.

.. method:: void notifyAll()

Wake up all coroutines waiting at this condition.

.. method:: int getting() const

Returns the number of coroutines waiting at this condition.

1.6 The Internal: How Coroutines Switch
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

to be written.

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

.. method:: Socket *accept()

    If the socket is currently listening, ``accept()`` block current coroutine, and return new ``Socket`` object after new client connected. The returned new ``Socket`` object has connected to the new client. This function returns ``0`` to indicate the socket is closed by other coroutine.

.. method:: bool bind(QHostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to ``address`` and ``port``. If the parameter ``port`` is ommited, the Operating System choose an unused random port for you. The chosen port can obtained from ``port()`` function later. The parameter ``mode`` is not used now. 
    
    This function returns 

.. method:: bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to any address and ``port``. This function overloads ``bind(address, port)``.

.. method:: bool connect(const QHostAddress &host, quint16 port)

    Connect to remote host specified by parameters ``host`` and ``port``. Block current coroutine until the connection is established or failed.
    
    This function returns true if the connection is established.

.. method:: bool connect(const QString &hostName, quint16 port, NetworkLayerProtocol protocol = AnyIPProtocol)

    Connect to remote host specified by parameters ``hostName`` and ``port``, using ``protocol``. If ``hostName`` is not an IP address, QtNetworkNg will make a DNS query before connecting. Block current coroutine until the connection is established or failed.
    
    As the DNS query is a time consuming task, you might use ``setDnsCache()`` to cache query result if you connect few remote host frequently.
    
    If the parameter ``protocol`` is ommited or specified as ``AnyIPProtocol``, QtNetworkNg will first try to connect to IPv6 address, then try IPv4 if failed. If the DNS server returns many IPs, QtNetworkNg will try connecting to those IPs in order.
    
    This function returns true if the connection is established.

.. method:: bool close()

    Close the socket.

.. method:: bool listen(int backlog)

    The socket is set to listening mode. You can use ``accept()`` to get new client request later. The meaning of parameter ``backlog`` is platform-specific, refer to ``man listen`` please.

.. method:: bool setOption(SocketOption option, const QVariant &value)

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
    
.. method:: QVariant option(SocketOption option) const

    Returns the value of the option option.
    
    See also ``setOption()`` for more information.

.. method:: qint64 recv(char *data, qint64 size)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Returns the size of data received. This function returns `0` if connection is closed.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint64 recvall(char *data, qint64 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Returns the size of data received. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint64 send(const char *data, qint64 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until some data sent.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint64 sendall(const char *data, qint64 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Returns the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint64 recvfrom(char *data, qint64 size, QHostAddress *addr, quint16 *port)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Returns the size of data received.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint64 sendto(const char *data, qint64 size, const QHostAddress &addr, quint16 port)

    Send ``size`` of ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: QByteArray recvall(qint64 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Returns the data received. Usually the size of returned value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``recvall(char*, qint64)``;

.. method:: QByteArray recv(qint64 size)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Returns the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recv(char*, qint64)``.

.. method:: qint64 send(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until some data sent.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``send(char*, qint64)``.

.. method:: qint64 sendall(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Returns the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``sendall(char*, qint64)``.

.. method:: QByteArray recvfrom(qint64 size, QHostAddress *addr, quint16 *port)

    Receives not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Returns the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recvfrom(char*, qint64, QHostAddress*, quint16*)``.

.. method:: qint64 sendto(const QByteArray &data, const QHostAddress &addr, quint16 port)

    Send ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Returns the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: SocketError error() const

    Returns the type of error that last occurred.
    
    TODO: A error table.

.. method:: QString errorString() const
    
    Returns a human-readable description of the last device error that occurred.
    
.. method:: bool isValid() const

    Returns true if the socket is not closed.
    
.. method:: QHostAddress localAddress() const

    Returns the host address of the local socket if available; otherwise returns ``QHostAddress::Null``.
    
    This is normally the main IP address of the host, but can be ``QHostAddress::LocalHost`` (127.0.0.1) for connections to the local host.

.. method:: quint16 localPort() const

    Returns the host port number (in native byte order) of the local socket if available; otherwise returns `0`.
    
.. method:: QHostAddress peerAddress() const

    Returns the address of the connected peer if the socket is in ``ConnectedState``; otherwise returns ``QHostAddress::Null``.
    
.. method:: QString peerName() const

    Returns the name of the peer as specified by ``connect()``, or an empty ``QString`` if ``connect()`` has not been called.
    
.. method:: quint16 peerPort() const

    Returns the port of the connected peer if the socket is in ``ConnectedState``; otherwise returns `0`.
    
.. method:: qintptr fileno() const

    Returns the native socket descriptor of the ``Socket`` object if this is available; otherwise returns `-1`.
    
    The socket descriptor is not available when ``Socket`` is in ``UnconnectedState``.

.. method:: SocketType type() const

    Returns the socket type (TCP, UDP, or other).

.. method:: SocketState state() const

    Returns the state of the socket.
    
    TODO: a state table.

.. method:: NetworkLayerProtocol protocol() const

    Returns the protocol of the socket.

.. method:: static QList<QHostAddress> resolve(const QString &hostName)

    Make a DNS query to resolve the ``hostName``. If the ``hostName`` is an IP address, return the IP immediately.
    
.. method:: void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache)

    Set a ``SocketDnsCache`` to ``Socket`` object. Every call to ``connect(hostName, port)`` will check the cache first.
    
2.2 SslSocket
^^^^^^^^^^^^^

The ``SslSocket`` is designed to be similar to ``Socket``. It take most functions of ``Socket`` such as ``connect()``, ``recv()``, ``send()``, ``peerName()``, etc.. But exclude ``recvfrom()`` and ``sendto()`` which are only used for UDP socket.

There are three constructors to create ``SslSocket``.

.. code-block:: c++
    :caption: the constructors of SslSocket
    
    SslSocket(Socket::NetworkLayerProtocol protocol = Socket::AnyIPProtocol, 
            const SslConfiguration &config = SslConfiguration());
    
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());
    
In addition, there are many function provided for obtain information from SslSocket.

.. method:: bool handshake(bool asServer, const QString &verificationPeerName = QString())

    Do handshake to other peer. If the parameter ``asServer`` is true, this ``SslSocket`` acts as SSL server.
    
    Use this function only if the ``SslSocket`` is created from plain socket.

.. method:: Certificate localCertificate() const

    Returns the the topest certificate of local peer.
    
    Usually this function returns the same certificate as ``SslConfiguration::localCertificate()``.

.. method:: QList<Certificate> localCertificateChain() const

    Returns the certificate chain of local peer.
    
    Usually this function returns the same certificate as ``SslConfiguration::localCertificate()`` and ``localCertificateChain``, plus some CA certificates from ``SslConfiguration::caCertificates``.

.. method:: QByteArray nextNegotiatedProtocol() const

    Returns the next negotiated protocol used by the ssl connection.
    
    `The Application-Layer Protocol Negotiation` is needed by HTTP/2.
    
    .. _The Application-Layer Protocol Negotiation: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation

.. method:: NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const

    Returns the status of the next protocol negotiation.

.. method:: SslMode mode() const

    Returns the mode the ssl connection. (Server or client)

.. method:: Certificate peerCertificate() const

    Returns the topest certificate of remote peer.

.. method:: QList<Certificate> peerCertificateChain() const

    Returns the certificate chain of remote peer.
    
.. method:: int peerVerifyDepth() const

    Returns the depth of verification. If the certificate chain of remote peer is longer than depth, the verification is failed.

.. method:: Ssl::PeerVerifyMode peerVerifyMode() const

    Returns the mode of verification.
    
    +----------------------+--------------------------------------------------------------------------------------+
    | PeerVerifyMode       | Description                                                                          |
    +======================+======================================================================================+
    | ``VerifyNone``       | ``SslSocket`` will not request a certificate from the peer. You can set this mode    |
    |                      | if you are not interested in the identity of the other side of the connection.       |
    |                      | The connection will still be encrypted, and your socket will still send its          |
    |                      | local certificate to the peer if it's requested.                                     |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``QueryPeer``        | ``SslSocket`` will request a certificate from the peer, but does not require this    |
    |                      | certificate to be valid. This is useful when you want to display peer certificate    |
    |                      | details to the user without affecting the actual SSL handshake. This mode is         |
    |                      | the default for servers.                                                             |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``VerifyPeer``       | ``SslSocket`` will request a certificate from the peer during the SSL handshake      |
    |                      | phase, and requires that this certificate is valid.                                  |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``AutoVerifyPeer``   | ``SslSocket`` will automatically use QueryPeer for server sockets and                |
    |                      | VerifyPeer for client sockets.                                                       |
    +----------------------+--------------------------------------------------------------------------------------+

.. method:: QString peerVerifyName() const

    Returns the name of remote peer.

.. method:: PrivateKey privateKey() const

    Returns the private key used by this connection.
    
    This function returns the same private key to ``SslConfiguration::privateKey()``.

.. method:: SslCipher cipher() const

    Get the cipher used by this connection. If there is no cipher used, this function returns empty cipher. ``Cipher::isNull()`` returns true in that case.
    
    The cipher is available only after handshaking.

.. method:: Ssl::SslProtocol sslProtocol() const

    Returns the ssl protocol used by this connection.

.. method:: SslConfiguration sslConfiguration() const

    Returns the configuration used by this connection.

.. method:: QList<SslError> sslErrors() const

    Returns the errors occured while handshaking and communication.

.. method:: void setSslConfiguration(const SslConfiguration &configuration)

    Set the configuration to use. This function must called before ``handshake()`` is called.
    
2.3 Socks5 Proxy
^^^^^^^^^^^^^^^^

``Socks5Proxy`` provides SOCKS5 client support. You can use it to make connection to remote host via SOCKS5 proxy.

There are two constructors.

.. code-block:: c++
    :caption: the constructors of Socks5Proxy
    
    Socks5Proxy();
    
    Socks5Proxy(const QString &hostName, quint16 port,
                 const QString &user = QString(), const QString &password = QString());

The first construct an empty ``Socks5Proxy``. The address of proxy server is needed to connect to remote host.

The second constructor use the ``hostName`` and ``port`` to create a valid Socks5 Proxy.

.. method:: QSharedPointer<Socket> connect(const QString &remoteHost, quint16 port);

    Use this function to connect to ``remoteHost`` at ``port`` via this proxy.
    
    Returns new ``Socket`` connect to ``remoteHost`` if success, otherwise returns an zero pointer.
    
    This function block current coroutine until the connection is made, or failed.
    
    The DNS query of ``remoteHost`` is made at the proxy server.
    
.. method:: QSharedPointer<Socket> connect(const QHostAddress &remoteHost, quint16 port)

    Connect to ``remoteHost`` at ``port`` via this proxy.
    
    Returns new ``Socket`` connect to ``remoteHost`` if success, otherwise returns an zero pointer.
    
    This function block current coroutine until the connection is made, or failed.
    
    This function is similar to ``connect(QString, quint16)`` except that there is no DNS query made.
    
.. method:: QSharedPointer<SocketLike> listen(quint16 port)

    Tell the Socks5 proxy to Listen at ``port``.
    
    Returns a ``SocketLike`` object if success, otherwise returns zero pointer.
    
    You can call ``SocketLike::accept()`` to obtain new requests to that ``port``.
    
    This function block current coroutine until the server returns whether success or failed.
    
    The ``SocketLike::accept()`` is blocked until new request arrived.
    
.. method:: bool isNull() const
    
    Returns true if there is no ``hostName`` or ``port`` of proxy server is provided.
    
.. method:: Capabilities capabilities() const

    Returns the capabilities of proxy server.
    
.. method:: QString hostName() const

    Returns the ``hostName`` of proxy server.
    
.. method:: quint16 port() const;

    Returns the ``port`` of proxy server.
    
.. method:: QString user() const

    Returns the ``user`` used for autherication of proxy server.
    
.. method:: QString password() const

    Returns the ``password`` used for autherication of proxy server.
    
.. method:: void setCapabilities(QFlags<Capability> capabilities)

    Set the capabilities of proxy server.
    
.. method:: void setHostName(const QString &hostName)
    
    Set the ``hostName`` of proxy server.
    
.. method:: void setPort(quint16 port)

    Set the ``port`` of proxy server.
    
.. method:: void setUser(const QString &user)

    Set the ``user`` used for autherication of proxy server.
    
.. method:: void setPassword(const QString &password)

    Set the ``password`` used for autherication of proxy server.

2.4 SocketServer
^^^^^^^^^^^^^^^^

Not implmented yet.

3. Http Client
--------------

3.1 HttpSession
^^^^^^^^^^^^^^^

3.2 HttpResponse
^^^^^^^^^^^^^^^^

3.3 HttpRequest
^^^^^^^^^^^^^^^

4. Http Server
--------------

4.1 Basic Http Server
^^^^^^^^^^^^^^^^^^^^^

4.2 Application Server
^^^^^^^^^^^^^^^^^^^^^^

5. Configuration And Build
--------------------------

5.1 Use libev Instead Of Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.2 Disable SSL Support
^^^^^^^^^^^^^^^^^^^^^^^
