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
        MyCoroutine()
        :BaseCoroutine(nullptr) {
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
    
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    
    struct MyCoroutine: public Coroutine {
        MyCoroutine(const QString &name)
            : name(name) {}
        void run() override {
            for (int i = 0; i < 3; ++i) {
                qDebug() << name << i;
                // switch to eventloop coroutine, will switch back in 100 ms.
                msleep(100); 
            }
        }
        QString name;
    };
    
    int main(int argc, char **argv) {
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
    
* The ``Coroutine::spawn()`` accepts ``std::function<void()>`` functor, so c++11 lambda is also acceptable.

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

    Return an unique imutable id for the coroutine. Basicly, the id is the pointer of coroutine.
    
.. method:: BaseCoroutine *BaseCoroutine::previous() const

    Return an pointer of ``BaseCoroutine`` which will switch to after this coroutine finished.
    
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
            for (int i = 0; i < 10; ++i)
                range10.append(i);
            
            QList<int> result = qtng::CoroutineGroup::map<int,int>(pow2, range10);
            for (int i =0; i < 10; ++i)
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
            for (int i = 0; i < 10; ++i)
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
    
    #include "qtnetworkng.h"

    using namespace qtng;

    void output(QSharedPointer<RLock> lock, const QString &name)
    {
        ScopedLock<RLock> l(*lock);    // acquire lock now, release before function returns. comment out this line and try again later.
        qDebug() << name << 1;
        Coroutine::sleep(1.0);
        qDebug() << name << 2;
    }


    int main(int argc, char **argv)
    {
        QSharedPointer<RLock> lock(new RLock);
        CoroutineGroup operations;
        operations.spawn([lock]{
            output(lock, "first");
        });
        operations.spawn([lock]{
            output(lock, "second");
        });
        operations.joinall();
        return 0;
    }
    
The output is

.. code-block:: text
    :caption: output of using RLock
    
    "first" 1
    "first" 2
    "second" 1
    "second" 2

If you comment out the line ``ScopedLock l(lock);``, the output is:

.. code-block:: text
    :caption: output without RLock
    
    "first" 1
    "second" 1
    "first" 2
    "second" 2

.. method:: bool acquire(bool blocking = true)

    Acquire the lock. If the lock is acquired by other coroutine, and the paremter ``blocking`` is true, block current coroutine until the lock is released by other coroutine. Otherwise this function returns immediately.
    
    Return whether the lock is acquired.
    
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
    
    Return whether the event is set.
    
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
    
    Return the value sent by other coroutine. If failed, construct a value usning default constructor.
    
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
    
    #include "qtnetworkng/qtnetworkng.h"

    using namespace qtng;

    void send_request(QSharedPointer<Semaphore> semaphore)
    {
        ScopedLock<Semaphore> l(semaphore);
        HttpSession session;
        qDebug() << session.get("https://news.163.com").statusCode;
    }

    int main(int argc, char **argv)
    {
        QSharedPointer<Semaphore> semaphore(new Semaphore(5));
        
        CoroutineGroup operations;
        for (int i = 0; i < 100; ++i) {
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
    
    Return whether the semaphore is acquired.
    
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

Return how many elements in this queue.

.. method:: int getting() const

Return the number of coroutines waiting for elements.

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

Return the number of coroutines waiting at this condition.

1.6 Utitilies
^^^^^^^^^^^^^

Several utitilies are provided to resolve conflicts between coroutine event loop and Qt event loop.

*The Biggest Error* in QtNetworkNg programming is that if blocking functions such as ``Socket`` functions, ``RLock`` functions and ``Event`` functions are called in the eventloop coroutine, the behavior of program will become undefined. So, remember, always emit Qt signals in eventloop, and handle signals in spawned coroutine. If this error is found, QtNetworkNg prints a warning message. Fortunately, this error is easy to find.

Another error is that you run a local eventloop using ``QDialog::exec()``.

Here come two functions that can resolve these errors, and another that can spawn threads in coroutines.

.. method:: T callInEventLoop(std::function<T ()> func)

    Call a function in eventloop and return its value.

    To run a local eventloop,

    .. code-block:: c++
    
        int code = callInEventLoop<int>([this] -> int {
            QDialog d(this);  
            return d.exec();
        });
        if (code == QDialog::Accepted) {
            receiveFile();
        } else {
            rejectFile();
        }
        
    To emit signal in eventloop:
    
    .. code-block:: c++
    
        QString filePath = receiveFile();
        callInEventLoop([this, filePath]{
            emit fileReceived(filePath);
        });

.. method:: void callInEventLoopAsync(std::function<void ()> func, quint32 msecs = 0)

    This is a asynchronous version of ``callInEventLoop()``. This function returns immediately, and schedules a call to function after ``msecs`` milliseconds.
    
    .. code-block:: c++
    
        if (error) {
            callInEventLoopAsync([this] {
                QMessageBox::information(this, windowTitle(), tr("Operation failed."));
            });
            return;
        }
    
    Note: Calling to ``callInEventLoopAsync()`` is lighter than ``callInEventLoop()``. And in most cases, if you don't care about the result of function, ``callInEventLoopAsync()`` is the best choice.
    
    
.. method:: T callInThread(std::function<T()> func)

    Call function in new thread and return its value.
    
.. method:: void qAwait(const typename QtPrivate::FunctionPointer<Func>::Object *obj, Func signal)

    Await a Qt signal.
    
    .. code-block:: c++
    
        QNetworkRequest request(url);
        QNetworkReply *reply = manager.get(request);
        qAwait(reply, &QNetworkReply::finished);
        text->setPlainText(reply->readAll());


1.7 The Internal: How Coroutines Switch
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
    
    Socket(HostAddress::NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    
    Socket(qintptr socketDescriptor);
    
The parameter ``protocol`` can be used to restrict protocol to IPv4 or IPv6. If this parameter is ommited, ``Socket`` will determine the prefered protocol automatically, basically, IPv6 is chosen first. TODO: describe the mehtod.

The parameter ``type`` specify the socket type. Only TCP and UDP is supported now. If this parameter is ommited, TCP is used.

The second form of constructor is useful to convert socket which created by other network programming toolkits to QtNetworkNg socket. The passed socket must in connected state.

These are the member functions of ``Socket`` type.

.. method:: Socket *accept()

    If the socket is currently listening, ``accept()`` block current coroutine, and return new ``Socket`` object after new client connected. The returned new ``Socket`` object has connected to the new client. This function returns ``0`` to indicate the socket is closed by other coroutine.

.. method:: bool bind(HostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to ``address`` and ``port``. If the parameter ``port`` is ommited, the Operating System choose an unused random port for you. The chosen port can obtained from ``port()`` function later. The parameter ``mode`` is not used now. 
    
    This function returns true if the port is bound successfully.

.. method:: bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform)

    Bind the socket to any address and ``port``. This function overloads ``bind(address, port)``.

.. method:: bool connect(const HostAddress &host, quint16 port)

    Connect to remote host specified by parameters ``host`` and ``port``. Block current coroutine until the connection is established or failed.
    
    This function returns true if the connection is established.

.. method:: bool connect(const QString &hostName, quint16 port, HostAddress::NetworkLayerProtocol protocol = AnyIPProtocol)

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

    Return the value of the option option.
    
    See also ``setOption()`` for more information.

.. method:: qint32 recv(char *data, qint32 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Return the size of data received. This function returns `0` if connection is closed.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint32 recvall(char *data, qint32 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Return the size of data received. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint32 send(const char *data, qint32 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until some data sent.
    
    Return the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint32 sendall(const char *data, qint32 size)

    Send ``size`` of ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Return the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint32 recvfrom(char *data, qint32 size, HostAddress *addr, quint16 *port)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Return the size of data received.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: qint32 sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port)

    Send ``size`` of ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Return the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: QByteArray recvall(qint32 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until the size of data equals ``size`` or connection is closed.
    
    This function is similar to ``recv()``, but block current coroutine until all data is received. If you can not be sure the size of data, use ``recv()`` instead. Otherwise that current coroutine might be blocked forever.
    
    Return the data received. Usually the size of returned value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``recvall(char*, qint32)``;

.. method:: QByteArray recv(qint32 size)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    Return the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recv(char*, qint32)``.

.. method:: qint32 send(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until some data sent.
    
    Return the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``send(char*, qint32)``.

.. method:: qint32 sendall(const QByteArray &data)

    Send ``data`` to remote host. Block current coroutine until all data sent or the connection closed.
    
    Return the size of data sent. Usually the return value is equals to the parameter ``size``, but might be smaller than ``size`` if the connection is closed. You might consider that is an exception.
    
    If some error occured, this function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.
    
    This function overloads ``sendall(char*, qint32)``.

.. method:: QByteArray recvfrom(qint32 size, HostAddress *addr, quint16 *port)

    Receive not more than ``size`` of data from connection. Blocks current coroutine until some data arrived.
    
    This is used for datagram socket only.
    
    Return the data received. This function returns empty ``QByteArray`` if connection is closed.
    
    This function can not indicate whether there is any error occured. If this function returns empty data, use ``error()`` to check error, and ``errorString()`` to get the error message.
    
    This function overloads ``recvfrom(char*, qint32, HostAddress*, quint16*)``.

.. method:: qint32 sendto(const QByteArray &data, const HostAddress &addr, quint16 port)

    Send ``data`` to remote host specified by ``addr`` and ``port``. Block current coroutine until some data sent.
    
    This is used for datagram socket only.
    
    Return the size of data sent. Usually, the returned value is smaller than the parameter ``size``.
    
    If some error occured, function returns `-1`. You can use ``error()`` and ``errorString()`` to get the error message.

.. method:: SocketError error() const

    Return the type of error that last occurred.
    
    TODO: A error table.

.. method:: QString errorString() const
    
    Return a human-readable description of the last device error that occurred.
    
.. method:: bool isValid() const

    Return true if the socket is not closed.
    
.. method:: HostAddress localAddress() const

    Return the host address of the local socket if available; otherwise returns ``HostAddress::Null``.
    
    This is normally the main IP address of the host, but can be ``HostAddress::LocalHost`` (127.0.0.1) for connections to the local host.

.. method:: quint16 localPort() const

    Return the host port number (in native byte order) of the local socket if available; otherwise returns `0`.
    
.. method:: HostAddress peerAddress() const

    Return the address of the connected peer if the socket is in ``ConnectedState``; otherwise returns ``HostAddress::Null``.
    
.. method:: QString peerName() const

    Return the name of the peer as specified by ``connect()``, or an empty ``QString`` if ``connect()`` has not been called.
    
.. method:: quint16 peerPort() const

    Return the port of the connected peer if the socket is in ``ConnectedState``; otherwise returns `0`.
    
.. method:: qintptr fileno() const

    Return the native socket descriptor of the ``Socket`` object if this is available; otherwise returns `-1`.
    
    The socket descriptor is not available when ``Socket`` is in ``UnconnectedState``.

.. method:: SocketType type() const

    Return the socket type (TCP, UDP, or other).

.. method:: SocketState state() const

    Return the state of the socket.
    
    TODO: a state table.

.. method:: NetworkLayerProtocol protocol() const

    Return the protocol of the socket.

.. method:: static QList<HostAddress> resolve(const QString &hostName)

    Make a DNS query to resolve the ``hostName``. If the ``hostName`` is an IP address, return the IP immediately.
    
.. method:: void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache)

    Set a ``SocketDnsCache`` to ``Socket`` object. Every call to ``connect(hostName, port)`` will check the cache first.
    
2.2 SslSocket
^^^^^^^^^^^^^

The ``SslSocket`` is designed to be similar to ``Socket``. It take most functions of ``Socket`` such as ``connect()``, ``recv()``, ``send()``, ``peerName()``, etc.. But exclude ``recvfrom()`` and ``sendto()`` which are only used for UDP socket.

There are three constructors to create ``SslSocket``.

.. code-block:: c++
    :caption: the constructors of SslSocket
    
    SslSocket(HostAddress::NetworkLayerProtocol protocol = Socket::AnyIPProtocol,
            const SslConfiguration &config = SslConfiguration());
    
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());
    
In addition, there are many function provided for obtain information from SslSocket.

.. method:: bool handshake(bool asServer, const QString &verificationPeerName = QString())

    Do handshake to other peer. If the parameter ``asServer`` is true, this ``SslSocket`` acts as SSL server.
    
    Use this function only if the ``SslSocket`` is created from plain socket.

.. method:: Certificate localCertificate() const

    Return the the topest certificate of local peer.
    
    Usually this function returns the same certificate as ``SslConfiguration::localCertificate()``.

.. method:: QList<Certificate> localCertificateChain() const

    Return the certificate chain of local peer.
    
    Usually this function returns the same certificate as ``SslConfiguration::localCertificate()`` and ``localCertificateChain``, plus some CA certificates from ``SslConfiguration::caCertificates``.

.. method:: QByteArray nextNegotiatedProtocol() const

    Return the next negotiated protocol used by the ssl connection.
    
    `The Application-Layer Protocol Negotiation` is needed by HTTP/2.
    
    .. _The Application-Layer Protocol Negotiation: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation

.. method:: NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const

    Return the status of the next protocol negotiation.

.. method:: SslMode mode() const

    Return the mode the ssl connection. (Server or client)

.. method:: Certificate peerCertificate() const

    Return the topest certificate of remote peer.

.. method:: QList<Certificate> peerCertificateChain() const

    Return the certificate chain of remote peer.
    
.. method:: int peerVerifyDepth() const

    Return the depth of verification. If the certificate chain of remote peer is longer than depth, the verification is failed.

.. method:: Ssl::PeerVerifyMode peerVerifyMode() const

    Return the mode of verification.
    
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

    Return the name of remote peer.

.. method:: PrivateKey privateKey() const

    Return the private key used by this connection.
    
    This function returns the same private key to ``SslConfiguration::privateKey()``.

.. method:: SslCipher cipher() const

    Get the cipher used by this connection. If there is no cipher used, this function returns empty cipher. ``Cipher::isNull()`` returns true in that case.
    
    The cipher is available only after handshaking.

.. method:: Ssl::SslProtocol sslProtocol() const

    Return the ssl protocol used by this connection.

.. method:: SslConfiguration sslConfiguration() const

    Return the configuration used by this connection.

.. method:: QList<SslError> sslErrors() const

    Return the errors occured while handshaking and communication.

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
    
    Return new ``Socket`` connect to ``remoteHost`` if success, otherwise returns an zero pointer.
    
    This function block current coroutine until the connection is made, or failed.
    
    The DNS query of ``remoteHost`` is made at the proxy server.
    
.. method:: QSharedPointer<Socket> connect(const HostAddress &remoteHost, quint16 port)

    Connect to ``remoteHost`` at ``port`` via this proxy.
    
    Return new ``Socket`` connect to ``remoteHost`` if success, otherwise returns an zero pointer.
    
    This function block current coroutine until the connection is made, or failed.
    
    This function is similar to ``connect(QString, quint16)`` except that there is no DNS query made.
    
.. method:: QSharedPointer<SocketLike> listen(quint16 port)

    Tell the Socks5 proxy to Listen at ``port``.
    
    Return a ``SocketLike`` object if success, otherwise returns zero pointer.
    
    You can call ``SocketLike::accept()`` to obtain new requests to that ``port``.
    
    This function block current coroutine until the server returns whether success or failed.
    
    The ``SocketLike::accept()`` is blocked until new request arrived.
    
.. method:: bool isNull() const
    
    Return true if there is no ``hostName`` or ``port`` of proxy server is provided.
    
.. method:: Capabilities capabilities() const

    Return the capabilities of proxy server.
    
.. method:: QString hostName() const

    Return the ``hostName`` of proxy server.
    
.. method:: quint16 port() const;

    Return the ``port`` of proxy server.
    
.. method:: QString user() const

    Return the ``user`` used for autherication of proxy server.
    
.. method:: QString password() const

    Return the ``password`` used for autherication of proxy server.
    
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

``HttpSession`` is a HTTP 1.0/1.1 client with automatical cookie management and automatical redirection. ``HttpSession::send()`` is the core function, which sends request to web server, then parses the response. Other than these, ``HttpSession`` provides many shortcut function, such as ``get()``, ``post()``, ``head()``, etc. Those functions help you to make http request in one line code.

``HttpSession`` can use Socks5 proxy which is default to none. However the support for HTTP proxy has not been implemented yet.

Cookies are parsed and stored using ``HttpSession::cookieJar()``. All response can be stored using ``HttpSession::cacheManager()`` which default to none. QtNetworkNg provides a ``HttpMemoryCacheManager`` which stores all cacheable responses in memory.

.. code-block:: c++
    :caption: examples to send http request
    
    HttpSession session;
    
    // use send()
    HttpRequest request;
    request.setUrl("https://qtng.org/");
    request.setMethod("GET");
    request.setTimeout(10.0f);
    HttpResponse response = session.send(request);
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();

    // use shortcuts
    HttpResponse response = session.get("https://qtng.org/");
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();
    
    QMap<QString, QString> query;
    query.insert("username", "panda");
    query.insert("password", "xoxoxoxox");
    HttpResponse response = session.post("https://qtng.org/login/", query);
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();
    
    // use cache cache manager
    session.setCacheManager(QSharedPointer<HttpCacheManager>::create());

The ``HttpRequest`` provides a number of functions for fine-grained control of requests to the web server. The most used functions are ``setMethod()``, ``setUrl()``, ``setBody()``, ``setTimeout()``. 

The ``HttpResponse`` provides functions to parse HTTP response. If some error occured, such as connection timout, HTTP 500 error, and others, ``HttpResonse::isOk()`` returns false. So, always check it before use ``HttpResonse``. The detail of errors is ``HttpResonse::error()``.

There is a special function ``HttpRequest::setStreamResponse()`` which indicate that ``HttpResponse`` do not parse the response body. Then, you can take the HTTP connection as plain Socket using ``HttpResponse::takeStream()``.


3.1 HttpSession
^^^^^^^^^^^^^^^

.. method:: HttpResponse send(HttpRequest &request)

    Send http request to web server, and parses the response.
    
.. method:: QNetworkCookieJar &cookieJar()

    Return the cookie manager.
    
    Note: the setter ``setCookieJar(...)`` has not been implemented yet.
    
.. method:: QNetworkCookie cookie(const QUrl &url, const QString &name)

    Return the specified cookie of ``url``.
    
    Cookies are always associated with a URL. So you should provide two parameters ``url`` and ``name`` together.
    
.. method:: void setMaxConnectionsPerServer(int maxConnectionsPerServer)

    Set the max connections per server to connect. The default value is 10, means that if you make more than 10 requests to a web server, some requests would be blocked untils the first 10 requests finished.
    
    If ``maxConnectionsPerServer`` less than 0, ``HttpSession`` omit the limit.
    
.. method:: int maxConnectionsPerServer()

    Return the current max connections per server to connect.
    
.. method:: void setDebugLevel(int level)

    If debug level is more than 0, ``HttpSession`` will print the digest sent to or received from web server.
    
    If debug level is more than 1, ``HttpSession`` will print the full content sent to or received from web server, especially the full response body. This can lead to a lot of screen scrolling.
    
.. method:: void disableDebug()

    Disable printing debug information.
    
.. method:: void setDefaultUserAgent(const QString &userAgent)

    Set the default user agent string.
    
    The default value is "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0", which is my favourite browser.
    
.. method:: QString defaultUserAgent() const

    Return the default user agent string.
    
    Each individual ``HttpRequest`` can set its own user agent string using ``HttpRequest::setUserAgent()``
    
.. method:: HttpVersion defaultVersion() const

    Return the default HTTP version to use.
    
    The default value is Http 1.1
    
    Each individual ``HttpRequest`` can set its own http version using ``HttpRequest::setVersion()``
    
.. method:: HttpVersion defaultVersion() const

    Return the default http version.
    
.. method:: void setDefaultConnectionTimeout(float timeout)

    Set the default connection timeout, which default to 10 seconds.
    
    This limit only apply before connection established. If the ``HttpSession`` can not connect to web server, a ``ConnectTimeout`` error is set to ``HttpResponse``.
    
    Each individual ``HttpRequest`` can set its own timeout.
    
.. method:: float defaultConnnectionTimeout() const

    Return the default connection timeout. 
    
.. method:: void setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy)

    Set the SOCKS5 proxy.
    
.. method:: QSharedPointer<Socks5Proxy> socks5Proxy() const

    Return the SOCKS5 proxy.
    
.. method:: void setCacheManager(QSharedPointer<HttpCacheManager> cacheManager)

    Set the cache manager.
    
.. method:: QSharedPointer<HttpCacheManager> cacheManager() const

    Return the cache manager.
    
.. method:: HttpResponse get(const QString &url)

    Send HTTP request to web server using GET method.
    
    There are many similar functions:

    .. code-block:: c++
    
        HttpResponse get(const QUrl &url);
        HttpResponse get(const QUrl &url, const QMap<QString, QString> &query);
        HttpResponse get(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse get(const QUrl &url, const QUrlQuery &query);
        HttpResponse get(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        HttpResponse get(const QString &url);
        HttpResponse get(const QString &url, const QMap<QString, QString> &query);
        HttpResponse get(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse get(const QString &url, const QUrlQuery &query);
        HttpResponse get(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        
        HttpResponse head(const QUrl &url);
        HttpResponse head(const QUrl &url, const QMap<QString, QString> &query);
        HttpResponse head(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse head(const QUrl &url, const QUrlQuery &query);
        HttpResponse head(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        HttpResponse head(const QString &url);
        HttpResponse head(const QString &url, const QMap<QString, QString> &query);
        HttpResponse head(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse head(const QString &url, const QUrlQuery &query);
        HttpResponse head(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);

        HttpResponse options(const QUrl &url);
        HttpResponse options(const QUrl &url, const QMap<QString, QString> &query);
        HttpResponse options(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse options(const QUrl &url, const QUrlQuery &query);
        HttpResponse options(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        HttpResponse options(const QString &url);
        HttpResponse options(const QString &url, const QMap<QString, QString> &query);
        HttpResponse options(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse options(const QString &url, const QUrlQuery &query);
        HttpResponse options(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);

        HttpResponse delete_(const QUrl &url);
        HttpResponse delete_(const QUrl &url, const QMap<QString, QString> &query);
        HttpResponse delete_(const QUrl &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse delete_(const QUrl &url, const QUrlQuery &query);
        HttpResponse delete_(const QUrl &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        HttpResponse delete_(const QString &url);
        HttpResponse delete_(const QString &url, const QMap<QString, QString> &query);
        HttpResponse delete_(const QString &url, const QMap<QString, QString> &query, const QMap<QString, QByteArray> &headers);
        HttpResponse delete_(const QString &url, const QUrlQuery &query);
        HttpResponse delete_(const QString &url, const QUrlQuery &query, const QMap<QString, QByteArray> &headers);
        
.. method:: HttpResponse post(const QString &url, const QByteArray &body)

    Send HTTP request to web server using POST method.
    
    There are many similar functions:
    
    .. code-block:: c++
    
        HttpResponse post(const QUrl &url, const QByteArray &body);
        HttpResponse post(const QUrl &url, const QJsonDocument &body);
        HttpResponse post(const QUrl &url, const QJsonObject &body);
        HttpResponse post(const QUrl &url, const QJsonArray &body);
        HttpResponse post(const QUrl &url, const QMap<QString, QString> &body);
        HttpResponse post(const QUrl &url, const QUrlQuery &body);
        HttpResponse post(const QUrl &url, const FormData &body);
        HttpResponse post(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QByteArray &body);
        HttpResponse post(const QString &url, const QJsonDocument &body);
        HttpResponse post(const QString &url, const QJsonObject &body);
        HttpResponse post(const QString &url, const QJsonArray &body);
        HttpResponse post(const QString &url, const QMap<QString, QString> &body);
        HttpResponse post(const QString &url, const QUrlQuery &body);
        HttpResponse post(const QString &url, const FormData &body);
        HttpResponse post(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse post(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);

        HttpResponse patch(const QUrl &url, const QByteArray &body);
        HttpResponse patch(const QUrl &url, const QJsonDocument &body);
        HttpResponse patch(const QUrl &url, const QJsonObject &body);
        HttpResponse patch(const QUrl &url, const QJsonArray &body);
        HttpResponse patch(const QUrl &url, const QMap<QString, QString> &body);
        HttpResponse patch(const QUrl &url, const QUrlQuery &body);
        HttpResponse patch(const QUrl &url, const FormData &body);
        HttpResponse patch(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QByteArray &body);
        HttpResponse patch(const QString &url, const QJsonDocument &body);
        HttpResponse patch(const QString &url, const QJsonObject &body);
        HttpResponse patch(const QString &url, const QJsonArray &body);
        HttpResponse patch(const QString &url, const QMap<QString, QString> &body);
        HttpResponse patch(const QString &url, const QUrlQuery &body);
        HttpResponse patch(const QString &url, const FormData &body);
        HttpResponse patch(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse patch(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);

        HttpResponse put(const QUrl &url, const QByteArray &body);
        HttpResponse put(const QUrl &url, const QJsonDocument &body);
        HttpResponse put(const QUrl &url, const QJsonObject &body);
        HttpResponse put(const QUrl &url, const QJsonArray &body);
        HttpResponse put(const QUrl &url, const QMap<QString, QString> &body);
        HttpResponse put(const QUrl &url, const QUrlQuery &body);
        HttpResponse put(const QUrl &url, const FormData &body);
        HttpResponse put(const QUrl &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QUrl &url, const FormData &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QByteArray &body);
        HttpResponse put(const QString &url, const QJsonDocument &body);
        HttpResponse put(const QString &url, const QJsonObject &body);
        HttpResponse put(const QString &url, const QJsonArray &body);
        HttpResponse put(const QString &url, const QMap<QString, QString> &body);
        HttpResponse put(const QString &url, const QUrlQuery &body);
        HttpResponse put(const QString &url, const FormData &body);
        HttpResponse put(const QString &url, const QByteArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QJsonDocument &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QJsonObject &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QJsonArray &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QMap<QString, QString> &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const QUrlQuery &body, const QMap<QString, QByteArray> &headers);
        HttpResponse put(const QString &url, const FormData &body, const QMap<QString, QByteArray> &headers);


3.2 HttpResponse
^^^^^^^^^^^^^^^^

.. method:: QUrl url() const

    Return the url of response. In most cases, it is the url of request. If there are redirections, it is the url of last response.

.. method:: void setUrl(const QUrl &url)

    Set the url of response. This function is called by ``HttpSession``.
    
.. method:: int statusCode() const

    Return the status code of response, such as 200 for success, 404 for not found, and 500 for internal error of server.
    
.. method:: void setStatusCode(int statusCode)

    Set the status code of response. This function is called by ``HttpSession``.
    
.. method:: QString statusText() const

    Return the status text of response, such as ``OK`` for success, ``Not Found`` or ``Bad Gateway`` for failed.

.. method:: void setStatusText(const QString &statusText)

    Set the status text of response. This function is called by ``HttpSession``.
    
.. method:: QList<QNetworkCookie> cookies() const

    Return the cookies of repsonse.
    
.. method:: void setCookies(const QList<QNetworkCookie> &cookies)

    Set the cookies of response. This function is called by ``HttpSession``.
    
.. method:: HttpRequest request() const

    Return the request sent to server. In most cases, it is the request you sent. If there are redirections, it is the new request made by ``HttpSession``.
    
.. method:: qint64 elapsed() const

    The elapsed time in milliseconds, which started from ``HttpSession`` getting request, end at error occured or finished parsing.
    
.. method:: void setElapsed(qint64 elapsed)

    Set the elapsed time. This function is called by ``HttpSession``.
    
.. method:: QList<HttpResponse> history() const

    The previous responses. In most cases, it is an empty list. If there are redirections, it is not empty.
    
.. method:: void setHistory(const QList<HttpResponse> &history)

    Set the previous response. This function is called by ``HttpSession``.
    
.. method:: HttpVersion version() const

    Return the HTTP version of response. The value can be HTTP 1.0 or HTTP 1.1.
    
    Note: HTTP 2.0 is not supported yet.
    
.. method:: void setVersion(HttpVersion version)

    Set the HTTP version of response. This function is called by ``HttpSession``.
    
.. method:: QByteArray body() const

    Return the content of response as ``QByteArray``.
    
.. method:: QJsonDocument json();

    Return the content of response as ``QJsonDocument``.
    
.. method:: QString text()

    Return the content of response as UTF-8 string.
    
.. method:: QString html()

    Return the content of response as string. The encoding is detected from HTTP header and HTML document.

    Note: This function has not been implemented and is currently equivalent to text.
    
.. method:: bool isOk() const

    Return false if some error occured.
    
    Note: This function should always be called first before using other functions.

.. method:: bool hasNetworkError() const

    Return true if some network error occured.
    
.. method:: bool hasHttpError() const

    Return true if an HTTP error occured.

.. method:: QSharedPointer<RequestError> error() const

    Return the error.
    
.. method:: void setError(QSharedPointer<RequestError> error)

    Set the error. This function is called by ``HttpSession``.

.. method:: QSharedPointer<SocketLike> takeStream(QByteArray *readBytes)

    In most cases, ``HttpSession`` returns ``HttpResponse`` only if it read all headers and content from server. But you can set ``HttpRequest::streamResponse()`` to ``true``, ``HttpSession`` will return ``HttpResonse`` immediately after reading the HTTP headers.
    
    ``takeStream()`` returns the http connection.

3.3 HttpRequest
^^^^^^^^^^^^^^^

.. method:: QString method() const

    Return the method of request.
    
.. method:: void setMethod(const QString &method)

    Set the method of request. Can be ``GET``, ``POST``, ``PUT``, etc. 
    
.. method:: QUrl url() const

    Return the url of request.
    
.. method:: void setUrl(const QUrl &url)

    Set the url of request.
    
.. method:: void setUrl(const QString &url)

    Set the url of request.
    
.. method:: QUrlQuery query() const

    Return the query string of request.
    
.. method:: void setQuery(const QMap<QString, QString> &query)

    Set the query string of request.
    
.. method:: void setQuery(const QUrlQuery &query)

    Set the query string of request.
    
.. method:: QList<QNetworkCookie> cookies() const

    Set the cookies of request.
    
.. method:: void setCookies(const QList<QNetworkCookie> &cookies)

    Set the cookies of request.
    
.. method:: QByteArray body() const

    Return the body of request.
    
.. method:: void setBody(const QByteArray &body)

    Set the body of request.
    
    There are serveral variant functions:
    
    .. code-block:: c++
        
        void setBody(const FormData &formData);
        void setBody(const QJsonDocument &json);
        void setBody(const QJsonObject &json);
        void setBody(const QJsonArray &json);
        void setBody(const QMap<QString, QString> form);
        void setBody(const QUrlQuery &form);

.. method:: QString userAgent() const

    Return the user agent string of request.
    
.. method:: void setUserAgent(const QString &userAgent)

    Set the user agent string of request.
    
.. method:: int maxBodySize() const

    Return the max body size of response.
    
    Note: this limit apply to response, not request. If server returns a response larger that this size, ``HttpSession`` will report an ``UnrewindableBodyError`` error.
    
.. method:: void setMaxBodySize(int maxBodySize)

    Set the max body size of response.
    
    Note: see ``maxBodySize()``.
    
.. method:: int maxRedirects() const

    Return the max redirections allow. Set to 0 will disable HTTP redirection.
    
    Note: When this limit is exceeded, ``HttpSession`` will report an ``TooManyRedirects`` error.
    
.. method:: void setMaxRedirects(int maxRedirects)

    Set the max redirections allow.
    
    Note: see ``maxRedirects()``.
    
.. method:: HttpVersion version() const

    Return the HTTP version of request. Default to ``Unkown``, means that ``HttpSession::defaultVersion()`` is used instead.
    
    Note:: ``HttpSession::defaultVersion()`` is default to HTTP 1.1
    
.. method:: void setVersion(HttpVersion version)

    Set the HTTP version of request. 
    
    Note:: see ``version()``.
    
.. method:: bool streamResponse() const

    If true, indicate that ``HttpResponse`` is returned without reading HTTP content.
    
    Note: see ``HttpResponse::takeStream()``.
    
.. method:: void setStreamResponse(bool streamResponse)

    Set true to let ``HttpSession`` return ``HttpResponse`` without reading HTTP content.
    
    Note: see ``HttpResponse::takeStream()``.
    
.. method:: float tiemout() const

    Return the connection timeout.
    
    Note: this restriction only apply in connecting phase. You could use ``qtng::Timeout`` to manage the timeout over the entire request.
    
.. method:: void setTimeout(float timeout);

    Set the connection timeut.
    
    Note: see ``timeout()``.
    

3.4 FormData
^^^^^^^^^^^^

``FormData`` is the HTTP form for POST. It is needed for uploading files.

Note: see ``void HttpRequest::setBody(const FormData &formData)``.

.. method:: void addFile(const QString &name, const QString &filename, const QByteArray &data, const QString &contentType = QString())
    
    Add a file to the field in ``name`` of form.
    
.. method:: void addQuery(const QString &key, const QString &value)

    Set the field in ``name`` of form to ``value``.


3.4 HTTP errors
^^^^^^^^^^^^^^^

Before using the ``HttpResponse``, you should check ``HttpResonse::isOk()``. If the function returns false,  the response is bad. At this point, ``HttpResponse::error()`` returns an instance of following types:

* RequestError

    All error is request error.

* HTTPError

    Web server returns an HTTP error. The error code is ``HTTPError::statusCode``.

* ConnectionError

    Connection is broken while reading or sending data.

* ProxyError

    Can not connect to web server through proxy.

* SSLError

    Can not make SSL connection, handshake failed.

* RequestTimeout

    Timeout while reading or sending data.

    ``RequestTimeout`` is also a ``ConnectionError``.

* ConnectTimeout

    Timeout while conneting to server.

    ``ConnectTimeout`` is also a ``ConnectionError`` and a ``RequestTimeout``.

* ReadTimeout

    Timeout while reading.

    ``ReadTimeout`` is also a ``RequestTimeout``.

* URLRequired

    There is not url in request.

* TooManyRedirects

    Web server return too many redirection responses.

* MissingSchema

    The url of request misses schema.

    Note: ``HttpSession`` only supports ``http`` and ``https``.

* InvalidScheme

    The url of request has an unsupported schema other than ``http`` and ``https``.

* UnsupportedVersion

    The HTTP version is not supported.

    Note: ``HttpSession`` only supports HTTP 1.0 and 1.1.

* InvalidURL

    The url of request is invalid.

* InvalidHeader

    The server returns invalid header.

* ChunkedEncodingError

    The server returns bad chuncked encoding body.

* ContentDecodingError

    Can not decode the body of response.

* StreamConsumedError

    The stream is consumed while reading body.

* UnrewindableBodyError

    The body is too large.


4. Http Server
--------------

4.1 Basic Http Server
^^^^^^^^^^^^^^^^^^^^^

4.2 Application Server
^^^^^^^^^^^^^^^^^^^^^^

5. Cryptography
---------------

5.1 Cryptographic Hash
^^^^^^^^^^^^^^^^^^^^^^

5.2 Symmetrical encryption and decryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.3 Public Key Algorithm
^^^^^^^^^^^^^^^^^^^^^^^^

5.4 Certificate and CertificateRequest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.5 Key Derivation Function
^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.6 TLS Cipher Suite
^^^^^^^^^^^^^^^^^^^^

6. Configuration And Build
--------------------------

6.1 Use libev Instead Of Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

6.2 Disable SSL Support
^^^^^^^^^^^^^^^^^^^^^^^
