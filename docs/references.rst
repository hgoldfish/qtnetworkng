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
                // switch to eventloop coroutine, will switch back in 100 ms.See 1.7 for details.
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
        operations.joinall();
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

1.7.1 Functor
-------------
Abstract callback interface that defines a unified ``operator()`` method. All concrete callbacks should inherit from this class (e.g., timer callbacks, I/O event callbacks).

.. method:: virtual bool operator()() = 0

    Pure virtual base class; subclasses must implement concrete logic.


1.7.2 DoNothingFunctor
----------------------
No-operation callback that can be used as a placeholder or default callback.

.. method:: bool operator()()

    No-operation callback that directly returns ``false``.


1.7.3 YieldCurrentFunctor
-------------------------
Yields execution rights of the current operation.

.. method:: explicit YieldCurrentFunctor()

    Preserves the pointer to the current coroutine.

.. method:: virtual bool operator()()

    Reawakens the preserved coroutine pointer.


1.7.4 DeleteLaterFunctor<T>
---------------------------
Delays object deletion to avoid direct destruction within callbacks.

.. method:: virtual bool operator()()

    Releases dynamically allocated objects of type ``T``.


1.7.5 LambdaFunctor
-------------------
Wraps a lambda expression to allow it to act as a callback.

.. method:: virtual bool operator()()

    Invokes the stored ``callback()`` to execute user-defined logic.


1.7.6 callInEventLoopCoroutine
------------------------------
Core class of the coroutine event loop, serving as the carrier of the event loop.Responsible for managing I/O event monitoring, timer scheduling, coroutine suspension/resumption, and coordinating interactions between coroutines and the underlying event-driven mechanisms.

Types of I/O operations

    .. code-block:: c++

        enum EventType {
            Read = 1,
            Write = 2,
            ReadWrite = 3,
        };

.. method:: int createWatcher(EventType event, qintptr fd, Functor *callback)

    Creates a read/write event watcher for file descriptor ``fd``, binding the callback function ``callback``.


.. method:: void startWatcher(int watcherId)

    Starts the watcher with specified ID. Used for dynamic event monitoring control.


.. method:: void stopWatcher(int watcherId)

    Stops the watcher with specified ID. Used for dynamic event monitoring control.


.. method:: void removeWatcher(int watcherId)

    Removes the watcher and releases associated resources.


.. method:: void triggerIoWatchers(qintptr fd)

    Manually triggers all registered event callbacks associated with ``fd``. Used for external event notifications.


.. method:: void callLaterThreadSafe(quint32 msecs, Functor *callback)

    Schedules an asynchronous callback to be executed after a delay of ``msecs`` milliseconds in a thread-safe manner.


.. method:: int callLater(quint32 msecs, Functor *callback)

    Executes ``callback`` once after delaying ``msecs`` milliseconds. Returns timer ID.


.. method:: int callRepeat(quint32 msecs, Functor *callback)

    Repeatedly executes ``callback`` every ``msecs`` milliseconds. Returns timer ID.


.. method:: void cancelCall(int callbackId)

    Cancels the timer with specified ID to prevent callback execution.


.. method:: bool runUntil(BaseCoroutine *coroutine)

    Runs event loop until ``coroutine`` completes. Used to block waiting for coroutine finish.


.. method:: bool yield()

    Suspends current coroutine and yields CPU to other coroutines. Typically called while waiting for events.


.. method:: int exitCode()

    Returns event loop's termination status code for judging operation result.


.. method:: bool isQt()

    Determines if the event loop backend implementation is Qt.


.. method:: bool isEv()

    Determines if the event loop backend implementation is libev.


.. method:: bool isWin()

    Determines if the event loop backend implementation is winev.


.. method:: static EventLoopCoroutine *get()

    Unified entry point for event loop, manages instance lifecycle via thread-local storage and adapts to multi-platform backends.
    Serves as the core hub for asynchronous programming. Its design philosophy aligns with Python's ``asyncio.get_event_loop()``, but implements lower-level control leveraging C++ features.


1.7.7 ScopedIoWatcher
---------------------
RAII wrapper for IO event watcher that automatically manages resources.

.. method:: ScopedIoWatcher(EventType event, qintptr fd)

    Creates a watcher for specified event type (read/write) on file descriptor ``fd``.

.. method:: bool start()

    Starts the watcher.


1.7.8 CurrentLoopStorage
------------------------
Abstract base class for event loops that defines platform-dependent interfaces.

.. method:: QSharedPointer<EventLoopCoroutine> getOrCreate()

    Gets the event loop instance for current thread; creates a new instance if none exists.

.. method:: QSharedPointer<EventLoopCoroutine> get()

    Only retrieves current thread's event loop instance; returns null pointer if uninitialized.

.. method:: void set(QSharedPointer<EventLoopCoroutine> eventLoop)

    Explicitly sets current thread's event loop instance (overrides auto-creation logic).

.. method:: void clean()

    Clears current thread's event loop instance, triggering ``QSharedPointer``'s reference-counted destruction.

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

2.4.1 BaseStreamServer
+++++++++++++++++++++++

BaseStreamServer is the foundational core class for building other SocketServers, providing basic socket server methods and reserving interfaces for further implementation of server types like TcpServer and KcpServer.

.. method:: BaseStreamServer(const HostAddress &serverAddress, quint16 serverPort);

    Initializes the server's listening address and port, defaults to binding all network interfaces using HostAddress::Any. Also initializes event objects started and stopped to track server status.

.. method:: bool serveForever()

    Blocks to run the server, cyclically accepting client connections and processing requests.

.. method:: bool start()

    Starts the server non-blockingly, running the service in background coroutine.

.. method:: void stop()

    Immediately closes server socket and terminates all connections.

.. method:: bool wait()

    Blocks current thread until server completely stops.

.. method:: void setAllowReuseAddress(bool b)

    Sets whether to allow port reuse (SO_REUSEADDR).

.. method:: bool isSecure()

    Identifies if the server uses encrypted protocols (e.g. SSL). Default returns: false, subclasses (e.g. WithSsl) override to return true.

.. method:: QSharedPointer<SocketLike> serverSocket()

    Gets underlying server socket object. First call will trigger serverCreate() to create socket.

.. method:: quint16 serverPort()

    Gets port number bound by the server.

.. method:: HostAddress serverAddress()

    Gets IP address bound by the server.

.. method:: virtual bool serverBind()

    Binds the server to specified address and port. Default implementation: sets SO_REUSEADDR option (if allowing address reuse), calls Socket::bind() for system call.

.. method:: virtual bool serverActivate()

    Sets socket to listening state. Default implementation: calls Socket::listen(), sets maximum connection queue length.

.. method:: virtual QSharedPointer<SocketLike> prepareRequest(QSharedPointer<SocketLike> request);

    Preprocesses requests (e.g. SSL handshake).

.. method:: virtual bool verifyRequest(QSharedPointer<SocketLike> request);

    Verifies request validity (e.g. IP blacklist). Default implementation: directly returns true, accepting all connections.

2.4.2 WithSsl
++++++++++++++
Adds SSL/TLS encryption to any streaming server seamlessly through template composition.

.. method:: WithSsl(const HostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);

    Initializes SSL server, inherits from ServerType, with several other similar constructors:

.. code-block:: c++

    WithSsl(const HostAddress &serverAddress, quint16 serverPort);
    WithSsl(quint16 serverPort);
    WithSsl(quint16 serverPort, const SslConfiguration &configuration);
.. method:: void setSslConfiguration(const SslConfiguration &configuration);

    Dynamically sets SSL configuration.

.. method:: SslConfiguration sslConfiguration() const;

    Gets SSL configuration.

.. method:: void setSslHandshakeTimeout(float sslHandshakeTimeout)

    Controls SSL handshake phase duration to prevent client-side malicious occupation.

.. method:: float sslHandshakeTimeout()

    Gets current SSL handshake timeout setting.

.. method:: virtual bool isSecure()

    Indicates server uses encrypted protocol for external code inspection.

.. method:: prepareRequest()

    Upgrades raw TCP connection to SSL connection.

2.4.3 BaseRequestHandler
+++++++++++++++++++++++++
Base class for request handling logic, users should inherit and implement concrete logic.

.. method:: void run()

    Main flow controller ensuring execution order: setup → handle → finish.

.. method:: void setup()

    Initializes request handling environment (e.g. verifying permissions, loading configurations).

.. method:: void handle()

    Implements core business logic (e.g. reading requests, processing data, returning responses).

.. method:: void finish()

    Cleans up resources (e.g. closing connections, logging, memory release). finish() should ensure resource cleanup even if business logic fails.

.. method:: void userData()

    Safely retrieves server-associated custom data (e.g. database connection pools, configuration objects).

2.4.4 Socks5RequestHandler
+++++++++++++++++++++++++++
Socks5RequestHandler implements SOCKS5 proxy protocol, inheriting from BaseRequestHandler to handle client connection requests through SOCKS5 proxy. Core features include protocol handshake, target address resolution, connection establishment, and data forwarding.

.. method:: virtual void handle()

    Main entry point for handling client SOCKS5 requests.

.. method:: bool handshake()

    Handles SOCKS5 handshake and authentication negotiation. Return value: true indicates successful handshake, false indicates failure.

.. method:: bool parseAddress(QString *hostName, HostAddress *addr, quint16 *port)

    Parses target address and port from client request.

.. method:: virtual QSharedPointer<SocketLike> makeConnection(const QString &hostName, const HostAddress &hostAddress,quint16 port, HostAddress *forwardAddress)

    Establishes connection to target server. hostName: Target domain name (e.g. ATYP=0x03), hostAddress: Target IP address (e.g. ATYP=0x01 or 0x04), port: Target port, forwardAddress: Output parameter recording actual connected server address.

.. method:: bool sendConnectReply(const HostAddress &hostAddress, quint16 port)

    Sends connection success response to client.

.. method:: bool sendFailedReply()

    Sends connection failure response.

.. method:: virtual void exchange(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward)

    Bidirectionally forwards data between client and target server.

.. method:: doConnect()

    Allows subclass extension for connection success behavior.

.. method:: doFailed()

    Allows subclass extension for connection failure behavior.

.. method:: virtual void logProxy(const QString &hostName, const HostAddress &hostAddress, quint16 port,const HostAddress &forwardAddress, bool success)

    Logs detailed proxy request information.

2.4.5 TcpServer
++++++++++++++++

Encapsulates the creation, binding, and listening of TCP servers. Implements business logic decoupling through the template parameter RequestHandler. Supports high-concurrency connections based on coroutine concurrency model.

.. method:: TcpServer(const HostAddress &serverAddress, quint16 serverPort);

    Initialize the TCP server, bind to the specified address and port. Directly calls the constructor of ``BaseStreamServer``. If no address is specified, it defaults to binding all network interfaces (HostAddress::Any).

.. method:: virtual QSharedPointer<SocketLike> serverCreate();

    Create the underlying TCP server socket.

.. method:: virtual void processRequest(QSharedPointer<SocketLike> request)

    Handle a single client connection request.

.. code-block:: c++
    :caption: Example: Simple TCP Server

    #include <QCoreApplication>
    #include "qtnetworkng.h"
    using namespace  qtng;
    class EchoHandler : public BaseRequestHandler // Inherit BaseRequestHandler and override handle()
    {
    protected:
        void handle()  {
            qDebug()<<"Received message";
            qint32 size=1024;
            QByteArray data=request->recvall(size);
            qDebug()<<QString(data);
        }
    };
    int main()
    {
        // Create the server, listen on port 8080
        TcpServer<EchoHandler> server(8080);
        // Configure server parameters
        server.setRequestQueueSize(100); // Set connection queue length
        server.setAllowReuseAddress(true); // Allow port reuse
        // Start the server (blocking operation)
        if (!server.serveForever()) {
            qDebug() << "Server startup failed!";
            return 1;
        }
        return 0;
    }

2.4.6 KcpServer
++++++++++++++++
Detailed explanation of the KcpServer and KcpServerV2 classes, their methods, and implementation differences.

.. method:: KcpServer(const HostAddress &serverAddress, quint16 serverPort)

    Initialize the KCP server, bind to the specified address and port. Directly calls the constructor of ``BaseStreamServer``. If no address is specified, it defaults to binding all network interfaces (HostAddress::Any).

.. method:: virtual QSharedPointer<SocketLike> serverCreate()

    Call ``KcpSocket::createServer()`` to create the KCP server, implemented via the KcpSocket class. This method initializes KCP sessions, binds to the specified address/port, and sets default parameters (e.g., MTU size, window size).

.. method:: virtual void processRequest(QSharedPointer<SocketLike> request)

    After accepting a client connection, instantiate the user-defined RequestHandler and pass the KCP session (encapsulated as a SocketLike object) to the business logic processing module.


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

4.1.1 BaseHttpRequestHandler
++++++++++++++++++++++++++++

Base class for handling HTTP requests, providing core functionality for HTTP protocol parsing, response generation, and error handling.

.. method:: BaseHttpRequestHandler()

    Initializes default parameters: HTTP version defaults to Http1_1, request timeout (requestTimeout) defaults to 1 hour, maximum request body size (maxBodySize) defaults to 32MB, connection state (closeConnection) initially set to Maybe.

.. method:: virtual void handle()

    Processes requests in a loop until closeConnection is marked as Yes, calls handleOneRequest() to process individual requests.

.. method:: virtual void handleOneRequest()

    Sets timeout limit (Timeout timeout(requestTimeout)), calls parseRequest() to parse request headers, dispatches to specific HTTP method handlers via doMethod().

.. method:: virtual bool parseRequest()

    Parses request line (e.g. GET /path HTTP/1.1), extracts method/path/version, parses and stores headers, handles Connection header to determine keep-alive, returns true on success or false on failure (automatically sends 400 error).

.. method:: void doMethod

    HTTP method dispatcher. All methods return 501 Not implemented by default. The following methods require subclass implementation:

    .. code-block:: c++

        virtual void doGET();
        virtual void doPOST();
        virtual void doPUT();
        virtual void doDELETE();
        virtual void doPATCH();
        virtual void doHEAD();
        virtual void doOPTIONS();
        virtual void doTRACE();
        virtual void doCONNECT();

.. method:: bool sendError(HttpStatus status, const QString &message = QString())

    Generates standard error page (HTML format), sends error response headers (status code, Content-Type, etc.), logs error via logError().

.. method:: void sendCommandLine(HttpStatus status, const QString &shortMessage)

    Sends status line (e.g. HTTP/1.1 200 OK).

.. method:: void sendHeader(const QByteArray &name, const QByteArray &value)

    Adds response header (automatically handles Connection logic).

.. method:: void sendHeader(KnownHeader name, const QByteArray &value)

    Same functionality as sendHeader.

.. method:: bool endHeader()

    Finalizes headers with \r\n, returns true on success.

.. method:: QSharedPointer<FileLike> bodyAsFile(bool processEncoding = true)

    Reads request body via Content-Length or Transfer-Encoding, handles GZIP/DEFLATE decompression (requires QTNG_HAVE_ZLIB), supports chunked encoding. Returns readable FileLike object containing request body.

.. method:: bool switchToWebSocket()

    Validates Upgrade: websocket and Sec-WebSocket-Key headers, calculates and returns Sec-WebSocket-Accept, marks connection upgrade to WebSocket.

.. method:: virtual void logRequest(HttpStatus status, int bodySize);

    Logs client address, request method, status code, and response body size.

.. method:: virtual void logError(HttpStatus status, const QString &shortMessage, const QString &longMessage);

    Logs error status and messages.

4.1.2 StaticHttpRequestHandler
++++++++++++++++++++++++++++++
Inherits ``BaseHttpRequestHandler``. Handles static resource requests with file transfer, directory listing, auto-index file detection. Includes path traversal protection, automatic MIME type detection, and XSS protection.

.. method:: QSharedPointer<FileLike> serveStaticFiles(const QDir &dir, const QString &subPath)

    Returns file content or directory listing based on given directory and subpath.

.. method:: QSharedPointer<FileLike> listDirectory(const QDir &dir, const QString &displayDir)

    Generates HTML directory listing page with clickable links for files/subdirectories.

.. method:: QFileInfo getIndexFile(const QDir &dir)

    Checks for index.html/index.htm in directory. Returns file info if exists, otherwise empty. Determines whether to display default index file when accessing directories.

.. method:: virtual bool loadMissingFile(const QFileInfo &fileInfo);

    Returns false by default. Subclasses can override to generate/retrieve missing files.

4.1.3 SimpleHttpRequestHandler
+++++++++++++++++++++++++++++++
Inherits ``SimpleHttpRequestHandler``. Preconfigured static file server with out-of-the-box basic HTTP file serving.

.. method:: void setRootDir(const QDir &rootDir)

    Sets accessible root directory. Ensure process has read permissions. Recommended to set before server startup to avoid race conditions.

.. method:: virtual void doGET() override;

    Handles GET requests using parent class's serveStaticFiles method.

.. method:: virtual void doHEAD() override;

    Handles HEAD requests using parent class's serveStaticFiles method.

4.1.4 BaseHttpProxyRequestHandler
++++++++++++++++++++++++++++++++++
Implements core logic for HTTP proxy, supporting forward proxy and tunnel proxy (e.g. HTTPS CONNECT method).

.. method:: virtual void logRequest(qtng::HttpStatus status, int bodySize)

    Empty implementation for request logging. Requires subclass implementation.

.. method:: virtual void logError(qtng::HttpStatus status, const QString &shortMessage, const QString &longMessage)

    Empty implementation for error logging. Requires subclass implementation.

.. method:: virtual void logProxy(const QString &remoteHostName, quint16 remotePort, const HostAddress &forwardAddress,bool success)

    Provides proxy-specific logging via logProxy(). Disables regular request logging by default to avoid duplication.

.. method:: virtual void doMethod()

    HTTP request dispatcher. Checks if method is CONNECT for tunnel handling, routes other methods (GET/POST/etc.) through standard proxy flow.

.. method:: virtual void doCONNECT()

    Handles CONNECT tunnel requests by establishing bidirectional client-target server channels.

.. method:: virtual void doProxy()

    Handles standard HTTP proxy requests by forwarding client requests to target servers and returning responses.

.. method:: virtual QSharedPointer<SocketLike> makeConnection(const QString &remoteHostName, quint16 remotePort,HostAddress *forwardAddress)

    It is responsible for creating and initializing a Socket connection to the target server, given the passed remoteHostName and remotePort. This connection will be used for subsequent HTTP request forwarding or HTTPS tunnel proxy (such as CONNECT method).

4.2 Application Server
^^^^^^^^^^^^^^^^^^^^^^
SimpleHttpServer : public TcpServer<SimpleHttpRequestHandler>
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
There is no specific implementation yet

SimpleHttpsServer : public SslServer<SimpleHttpRequestHandler>
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
There is no specific implementation yet

5.1 Password Hash Table
^^^^^^^^^^^^^^^^^^^^^^^
MessageDigest
++++++++++++++
Provides message digest (hash) functionality, supporting multiple hash algorithms, allows processing data in chunks and generating digests. Supports MD4 and MD5 algorithms, Sha1, Sha224, Sha256, Sha384, Sha512 series of SHA algorithms, as well as Ripemd160 and Whirlpool hash algorithms.

.. method:: MessageDigest(Algoritim algo)

    Initializes the context with the specified hash algorithm.

.. method:: addData(const char *data, int len)

    Adds raw byte data to the hash calculation. Calls EVP_DigestUpdate to update the context. Marks error on failure.

.. method:: addData(const char *data)

    Overload of addData. Internally calculates data length and calls the previous addData.

.. method:: QByteArray result()

    Finalizes the hash calculation and returns the final digest. If called for the first time, calls EVP_DigestFinal_ex to finalize the calculation and caches the result. Subsequent calls return the cached result directly. Returns empty QByteArray on failure.

.. method:: void update(const QByteArray &data)

    Same as addData, provides compatibility with common hash interfaces.

.. method:: void update(const char *data, int len)

    Same as addData, provides compatibility with common hash interfaces.

.. method:: QByteArray hexDigest()

    Same as result(), returns the raw digest.

.. method:: QByteArray digest()

    Returns the digest in hexadecimal string form.

.. method:: static QByteArray hash(const QByteArray &data, Algorithm algo)

    One-time calculation of the hash value (hexadecimal) of the data.

.. method:: static QByteArray digest(const QByteArray &data, Algorithm algo)

    One-time calculation of the hash value (raw bytes) of the data.

.. method:: QByteArray PBKDF2_HMAC(int keylen, const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo = MessageDigest::Sha256, int i = 10000)

    Calls OpenSSL's PKCS5_PBKDF2_HMAC function to generate the key.

.. method:: QByteArray scrypt(int keylen, const QByteArray &password, const QByteArray &salt, int n = 1048576, int r = 8, int p = 1)

    Not yet implemented.

5.2 Symmetric Encryption and Decryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Cipher
+++++++
Provides symmetric encryption/decryption functionality. Supports multiple algorithms (e.g. AES, DES, ChaCha20) and modes (e.g. CBC, CTR, ECB). Supports password derivation and padding control.

.. method:: Cipher(Algorithm alog, Mode mode, Operation operation)

    Initializes the encryption context. Obtains the corresponding OpenSSL EVP_CIPHER via getOpenSSL_CIPHER(). Creates EVP_CIPHER_CTX context. Enables padding by default. Marks hasError on failure.

.. method:: Cipher *copy(Operation operation)

    Copies the current configuration and creates a new Cipher instance.

.. method:: bool isValid()

    Checks if the context is valid. Conditions: OpenSSL context exists, no errors occurred, and it has been initialized.

.. method:: bool isStream()

    Determines if the current encryption context uses stream cipher mode (e.g. CFB, OFB, CTR).

.. method:: bool isBlock()

    Determines if block cipher mode is used (e.g. ECB, CBC). Directly returns !isStream().

.. method:: void setKey(const QByteArray &key)

    Sets the raw key.

.. method:: QByteArray key()

    Returns the current key.

.. method:: setInitialVector(const QByteArray &iv)

    Sets the initialization vector (IV). Stores the IV and initializes the context.

.. method:: QByteArray initialVector()

    Returns the current IV.

.. method:: QByteArray iv()

    Same as initialVector method.

.. method:: bool setPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo = MessageDigest::Sha256, int i = 100000)

    Derives key via password using PBKDF2-HMAC. Parameters: password, salt, hash algorithm, iteration count. Generates random salt (optional), calls PBKDF2_HMAC to derive key and IV.

.. method:: bool setOpensslPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo = MessageDigest::Md5, int i = 1)

    Compatible with OpenSSL's key derivation (EVP_BytesToKey). Parameters: password, salt (must be 8 bytes), hash algorithm, iteration count. Uses legacy method to generate keys, suitable for decrypting data encrypted by OpenSSL.

.. method:: QByteArray addData(const QByteArray &data)

    Processes data in chunks and returns encrypted/decrypted result.

.. method:: QByteArray addData(const char *data, int len)

    Processes data in chunks and returns encrypted/decrypted result.

.. method:: QByteArray update(const QByteArray &data)

    Processes data in chunks and returns encrypted/decrypted result.

.. method:: QByteArray update(const char *data, int len)

    Processes data in chunks and returns encrypted/decrypted result.

.. method:: QByteArray finalData()

    Finalizes encryption/decryption and returns remaining data.

.. method:: QByteArray final()

    Finalizes encryption/decryption and returns remaining data.

.. method:: QByteArray saltHeader()

    Generates OpenSSL-style salt header ("Salted__" + 8-byte salt). Saves salt during encryption for decryption use.

.. method:: QByteArray parseSalt()

    Parses salt value from OpenSSL header. Return value: QPair<QByteArray, QByteArray> (salt + remaining data).

.. method:: bool setPadding(bool padding)

    Enables or disables PKCS#7 padding: Controls the automatic addition of padding bytes at the end of data for block cipher algorithms (e.g. AES-CBC, DES-ECB). Only effective for block ciphers: automatically ignores padding settings in stream cipher modes (e.g. CTR, CFB).

.. method:: bool padding()

    Gets enable/disable status of PKCS#7 padding.

.. method:: int keySize()

    Gets key length.

.. method:: int ivSize()

    Gets IV length.

.. method:: int blockSize()

    Gets block length.

5.3 Public Key Algorithms
^^^^^^^^^^^^^^^^^^^^^^^^^
5.3.1 PublicKey
++++++++++++++++
Core class in the encryption system, used for managing public key operations.

.. method:: PublicKey()

    Creates an empty public key object. Initializes OpenSSL's EVP_PKEY structure internally.

.. method:: PublicKey(const PublicKey &other)

    Deep copies the underlying OpenSSL key object (via EVP_PKEY_dup). Prevents multiple objects sharing the same key memory, ensuring thread safety.

.. method:: static PublicKey load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem)

    Creates BIO memory object to read key data. Calls PEM_read_bio_PUBKEY to parse PEM format. Generates EVP_PKEY structure and stores it in PublicKeyPrivate.

.. method:: QByteArray save(Ssl::EncodingFormat format = Ssl::Pem)

    Writes the key to BIO object via PEM_write_bio_PUBKEY.

.. method:: QByteArray encrypt(const QByteArray &data)

    Initializes encryption context (algorithm auto-detected). Dynamically calculates output buffer size (avoids fixed length limitation). Executes encryption and returns result.

.. method:: QByteArray rsaPublicEncrypt(const QByteArray &data, RsaPadding padding = PKCS1_PADDING)

    RSA-specific encryption. PKCS1_PADDING: Best compatibility (default). NO_PADDING: Requires manual padding handling, only for specific protocols.

.. method:: QByteArray rsaPublicDecrypt(const QByteArray &data, RsaPadding padding = PKCS1_PADDING)

    RSA-specific decryption. PKCS1_PADDING: Best compatibility (default). NO_PADDING: Requires manual padding handling, only for specific protocols.

.. method:: bool verify(const QByteArray &data, const QByteArray &hash, MessageDigest::Algorithm hashAlgo)

    Processes data with specified hash algorithm (e.g. SHA256). Compares signature hash value with computed value. Returns true if verification passes.

.. method:: Algorithm algorithm()

    Enum type identifying key type (RSA/DSA/EC).

.. method:: int bits()

    Returns key length. 2048-bit RSA key returns 2048.

.. method:: PublicKey &operator=(const PublicKey &other)

    Overloaded = operator. Functionally equivalent to copy constructor.

.. method:: bool operator==(const PublicKey &other)

    Overloaded == operator.

.. method:: bool operator==(const PrivateKey &)

    Overloaded == operator.

.. method:: bool operator!=(const PublicKey &other)

    Overloaded != operator.

.. method:: bool operator!=(const PrivateKey &)

    Overloaded != operator.

.. method:: QByteArray digest(MessageDigest::Algorithm algorithm = MessageDigest::Sha256)

    Generates unique fingerprint (e.g. SHA256 hash) for key verification.

.. method:: bool isNull()

    Checks if key is empty.

.. method:: bool isValid()

    Checks key validity.

5.3.2 PrivateKey
+++++++++++++++++
Encapsulates private key operations including key generation, signing, decryption, and private key-specific encryption operations.

.. method:: PrivateKey()

    Default constructor.

.. method:: PrivateKey(const PrivateKey &other)

    Copy constructor.

.. method:: PrivateKey(PrivateKey &&other)

    Move constructor.

.. method:: PrivateKey &operator=(const PublicKey &other)

    Copy assignment operator.

.. method:: PrivateKey &operator=(const PrivateKey &other)

    Copy assignment operator.

.. method:: bool operator==(const PrivateKey &other)

    Overloaded == operator.

.. method:: bool operator==(const PublicKey &)

    Overloaded == operator.

.. method:: bool operator!=(const PrivateKey &other)

    Overloaded != operator.

.. method:: bool operator!=(const PublicKey &)

    Overloaded != operator.

.. method:: PublicKey publicKey()

    Extracts the public key corresponding to current private key.

.. method:: QByteArray sign(const QByteArray &data, MessageDigest::Algorithm hashAlgo)

    Signs data using private key.

.. method:: QByteArray decrypt(const QByteArray &data)

    Decrypts data using private key. Initializes decryption context: EVP_PKEY_decrypt_init. Calculates decrypted length: Calls EVP_PKEY_decrypt twice (first to get length, second to decrypt data). Returns decrypted result: Resizes QByteArray and fills data.

.. method:: rsaPrivateEncrypt

    Directly uses RSA private key for raw encryption.

.. method:: rsaPrivateDecrypt

    Directly uses RSA private key for raw decryption.

.. method:: static PrivateKey generate(Algorithm algo, int bits)

    Generates private key of specified algorithm and length.

.. method:: static PrivateKey load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &password = QByteArray())

    Loads private key from PEM/DER format with password decryption support.

.. method:: QByteArray save(Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &password = QByteArray())

    Core functionality serializes private key. Supports password encryption (requires valid encryption algorithm). Relies on PrivateKeyWriter to handle OpenSSL low-level details. Needs DER format and default encryption logic improvement.

.. method:: QByteArray savePublic(Ssl::EncodingFormat format = Ssl::Pem)

    Directly reuses public key saving logic. Ensures output contains only public key information. No password handling required, always saves in plaintext.

5.3.3 PasswordCallback
+++++++++++++++++++++++
Encryption/decryption progress tracking.

.. method:: virtual QByteArray get(bool writing) = 0;

    Gets encryption/decryption progress. Must be implemented by subclass.

5.3.4 PrivateKeyWriter
+++++++++++++++++++++++
Serializes asymmetric encryption keys (e.g. RSA, DSA keys) to specific formats (PEM/DER). Supports encrypting private keys and saving to files or memory. Core responsibility: Provides flexible configuration options (encryption algorithm, password, public-only saving) and calls OpenSSL functions for serialization.

.. method:: PrivateKeyWriter(const PrivateKey &key)

    Copy constructor via private key.

.. method:: PrivateKeyWriter(const PublicKey &key)

    Copy constructor via public key.

.. method:: PrivateKeyWriter &setCipher(Cipher::Algorithm algo, Cipher::Mode mode)

    Specifies encryption algorithm for private key (e.g. AES-256-CBC). If not called, defaults to no encryption (Cipher::Null).

.. method:: PrivateKeyWriter &setPassword(const QByteArray &password)

    Provides password for private key encryption via direct input.

.. method:: PrivateKeyWriter &setPassword(QSharedPointer<PasswordCallback> callback)

    Provides password for private key encryption via dynamic callback.

.. method:: PrivateKeyWriter &setPublicOnly(bool publicOnly)

    Forces saving public key only, even when private key is passed. Extracts public key from private key and saves.

.. method:: QByteArray asPem()

    Serializes key to PEM format. Supports encrypted private keys.

.. method:: QByteArray asDer()

    Not fully implemented, returns empty data. Serializes key to DER format. Supports PKCS#8 encryption.

.. method:: bool save(const QString &filePath)

    Saves key to file. Uses PEM format by default.

5.3.5 PrivateKeyReader
+++++++++++++++++++++++
Responsible for loading private/public keys from files or memory data. Supports handling encrypted private key files (via password or callback).

.. method:: PrivateKeyReader()

    Initialization. Generates PrivateKey object.

.. method:: PrivateKeyReader &setPassword(const QByteArray &password)

    Sets direct password for decrypting encrypted private keys.

.. method:: PrivateKeyReader &setPassword(QSharedPointer<PasswordCallback> callback)

    Sets password callback object for dynamic password retrieval (e.g. GUI input).

.. method:: PrivateKeyReader &setFormat(Ssl::EncodingFormat format)

    Specifies input data encoding format (currently only PEM supported).

.. method:: PrivateKey read(const QByteArray &data)

    Reads private key from in-memory byte array.

.. method:: PublicKey readPublic(const QByteArray &data)

    Reads public key from in-memory byte array.

.. method:: PrivateKey read(const QString &filePath)

    Reads private key from file.

.. method:: PublicKey readPublic(const QString &filePath)

    Reads public key from file.

5.4 Certificates and Certificate Requests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
5.4.1 Certificate
++++++++++++++++++
Encapsulates certificate operations. Provides interfaces like load/save certificate, retrieve certificate information, generate certificates.

.. method:: Certificate()

    Constructor. Performs initialization.

.. method:: Certificate(const Certificate &other)

    Copy constructor. Performs initialization.

.. method:: Certificate(Certificate &&other)

    Move constructor. Performs initialization.

.. method:: static Certificate load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem)

    Loads certificate from PEM or DER formatted byte stream.

.. method:: static Certificate generate(const PublicKey &publickey, const PrivateKey &caKey, MessageDigest::Algorithm signAlgo, long serialNumber, const QDateTime &effectiveDate, const QDateTime &expiryDate, const QMultiMap<SubjectInfo, QString> &subjectInfoes)

    Generates new X.509 certificate. Signs with CA private key.

.. method:: static Certificate selfSign(const PrivateKey &key, MessageDigest::Algorithm signAlgo, long serialNumber, const QDateTime &effectiveDate, const QDateTime &expiryDate, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)

    Self-sign shortcut method. Calls generate method internally.

.. method:: QByteArray save(Ssl::EncodingFormat format = Ssl::Pem)

    Saves certificate in PEM or DER format.

.. method:: QByteArray digest(MessageDigest::Algorithm algorithm = MessageDigest::Sha256)

    Computes hash value (e.g. SHA-256) of certificate DER data.

.. method:: QDateTime effectiveDate()

    Parses X509_getm_notBefore and X509_getm_notAfter in CertificatePrivate::init.

.. method:: QDateTime expiryDate()

    Parses X509_getm_notBefore and X509_getm_notAfter in CertificatePrivate::init.

.. method:: QStringList subjectInfo(SubjectInfo subject)

    Retrieves X509_NAME via X509_get_subject_name and X509_get_issuer_name. Parses into key-value pairs.

.. method:: QStringList subjectInfo(const QByteArray &attribute)

    Retrieves X509_NAME via X509_get_subject_name and X509_get_issuer_name. Parses into key-value pairs.

.. method:: PublicKey publicKey()

    Gets public key.

.. method:: QByteArray serialNumber()

    Gets serial number.

.. method:: bool isBlacklisted()

    Checks if certificate is in predefined blacklist (e.g. malicious certificates from Comodo incident).

.. method:: bool isNull()

    Checks if certificate is empty.

.. method:: bool isValid()

    Checks certificate validity (non-empty and not blacklisted).

.. method:: QString toString()

    Returns certificate as string representation.

.. method:: QByteArray version()

    Returns current certificate version.

.. method:: bool isSelfSigned()

    Calls X509_check_issued to check if certificate is self-signed.

5.4.2 CertificateRequest
+++++++++++++++++++++++++
Certificate request operations.

.. method:: certificate()

    Returns Certificate object associated with the certificate request.

5.5 TLS Cipher Suites
^^^^^^^^^^^^^^^^^^^^^^
5.5.1 SslCipher
++++++++++++++++
Encryption cipher suite used in SSL/TLS connections. Contains detailed information like encryption algorithm, protocol version, key exchange method.

.. method:: SslCipher()

    Default constructor.

.. method:: SslCipher(const QString &name)

    Constructor via name.

.. method:: SslCipher(const QString &name, Ssl::SslProtocol protocol)

    Constructor via name and protocol.

.. method:: SslCipher(const SslCipher &other)

    Copy constructor.

.. method:: QString authenticationMethod()

    Returns key authentication method (e.g. RSA).

.. method:: QString encryptionMethod()

    Returns specific encryption algorithm.

.. method:: bool isNull()

    Determines if object is valid (returns true if constructor found no match).

.. method:: QString keyExchangeMethod()

    Returns key exchange method (e.g. ECDHE).

.. method:: QString name()

    Directly returns name stored in private class.

.. method:: Ssl::SslProtocol protocol()

    Directly returns protocol enum value stored in private class.

.. method:: QString protocolString()

    Directly returns protocol string stored in private class.

.. method:: int supportedBits()

    Returns supported encryption bits.

.. method:: int usedBits()

    Returns used encryption bits.

.. method:: inline bool operator!=(const SslCipher &other)

    Determines cipher equality via name and protocol comparison, not all attributes.

.. method:: SslCipher &operator=(SslCipher &&other)

    Move assignment operator.

.. method:: SslCipher &operator=(const SslCipher &other)

    Copy assignment operator.

.. method:: void swap(SslCipher &other)

    Swaps two cipher suites.

.. method:: bool operator==(const SslCipher &other)

    Determines cipher equality via name and protocol comparison, not all attributes.

6. Configuration and Building
------------------------------
6.1 Use libev instead of Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
In CMake files, use conditional judgment to replace Qt event loop (qtev) with libev in Unix environments. The specific logic is as follows:

1. **OS Judgment**:

    If the current system is Unix (including Linux, macOS and other non-Windows systems), enter the libev configuration branch.

2. **Event Loop Backend Selection**:

    * Use ``check_function_exists`` to detect whether the system supports ``epoll_ctl`` or ``kqueue``.
        *  If ``epoll`` exists (Linux systems), define ``EV_USE_EPOLL=1`` and ``EV_USE_EVENTFD=1`` to use epoll as the event-driven mechanism.
        * If ``kqueue`` exists (BSD systems), define ``EV_USE_KQUEUE=1`` to use kqueue.
        * If neither is supported, fall back to ``poll()``.
    * Define the macro ``QTNETWOKRNG_USE_EV`` to indicate enabling the libev event loop.

3. **Source Code Integration**:

    * Add libev's source file ``src/ev/ev.c`` and header file ``src/ev/ev.h``.
    * Use ``src/eventloop_ev.cpp`` as the implementation of the event loop, replacing Qt's native event loop.

4. **Trigger Condition**:

    When CMake detects the target system is UNIX, libev is automatically enabled without additional configuration.


6.2 Disable SSL Support
^^^^^^^^^^^^^^^^^^^^^^^

6.2.1 Disable SSL Support During Build
+++++++++++++++++++++++++++++++++++++++++

    * **For qmake builds**: SSL support is disabled by default. To enable it, manually add the OpenSSL module.
    * **For CMake builds**:
    * The built-in OpenSSL is controlled by ``QTNG_USE_OPENSSL``.
        1. When ``OFF`` (default), use qtnetworkng's built-in OpenSSL.
        2. When ``ON``, use the system's OpenSSL.
    * To completely disable SSL, comment out related configurations in CMake (not recommended).


6.2.2 Using Base Socket Classes Directly
+++++++++++++++++++++++++++++++++++++++++
If encryption is not required, use base Socket classes instead of SslSocket. Using Socket directly bypasses all SSL/TLS layers, transmitting data in plaintext.
A simple example:

.. code-block:: c++
    :caption: Example: Implementing a simple HTTP server using base TcpServer instead of SslServer

        #include "qtnetworkng.h"
        using namespace qtng;
        class HelloRequestHandler: public SimpleHttpRequestHandler
        {
        public:
            virtual void doGET() override
            {
                if (path == QString::fromLatin1("/hello/")) {
                    sendResponse(HttpStatus::OK);
                    sendHeader("Content-Type", "text/plain");
                    QByteArray body = "hello";
                    sendHeader("Content-Length", QByteArray::number(body.size()));
                    endHeader();
                    request->sendall(body);
                }
            }
        };
        class HelloHttpServer: public TcpServer<HelloRequestHandler>
        {
        public:
            HelloHttpServer(const HostAddress &serverAddress, quint16 serverPort)
                : TcpServer(serverAddress, serverPort) {}
        };
        int main()
        {
            HelloHttpServer httpd(HostAddress::Any, 8443);
            httpd.serveForever();
            return 0;
        }

7. Other Auxiliary Classes
---------------------------

7.1 IO Operations
^^^^^^^^^^^^^^^^^^

This module provides cross-platform file and memory I/O abstractions with coroutine-friendly non-blocking operations and secure POSIX path management utilities, suitable for network applications requiring efficient and safe file handling.

Core Functions:

.. method:: bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy = -1, int suitableBlockSize = 1024 * 8)

    Copies content between files with large file support. Parameters:

    * inputFile/outputFile: File objects for I/O
    * bytesToCopy: Bytes to copy (-1 for full content)
    * suitableBlockSize: Buffer size (default 8KB).

7.1.1 FileLike
+++++++++++++++

Abstract base class defining common file operation interfaces with read/write/close/size capabilities.

.. method:: virtual qint32 read(char *data, qint32 size)

    Read data to buffer (pure virtual).

.. method:: virtual qint32 write(const char *data, qint32 size)

    Write buffer data (pure virtual).

.. method:: virtual void close()

    Close file (pure virtual).

.. method:: virtual qint64 size()

    Get file size (pure virtual).

.. method:: virtual QByteArray readall(bool *ok);

    Read entire file, returns success via 'ok'.

.. method:: QByteArray read(qint32 size)

    Read specified data size.

.. method:: qint32 write(const QByteArray &data)

    Write QByteArray data.

.. method:: static QSharedPointer<FileLike> rawFile(QSharedPointer<QFile> f)

    Create FileLike from QFile.

.. method:: static QSharedPointer<FileLike> rawFile(QFile *f)

    Create FileLike from QFile pointer.

.. method:: static QSharedPointer<FileLike> open(const QString &filepath, const QString &mode = QString())

    Open file as FileLike instance.

.. method:: static QSharedPointer<FileLike> bytes(const QByteArray &data)

    Create memory-based BytesIO.

.. method:: static QSharedPointer<FileLike> bytes(QByteArray *data)

    Create BytesIO with existing data.

7.1.2 RawFile
++++++++++++++

QFile wrapper implementing actual file I/O with non-blocking support (Unix).

.. method:: virtual qint32 read(char *data, qint32 size) override

    System call/QFile read (coroutine-friendly).

.. method:: virtual qint32 write(const char *data, qint32 size) override

    System call/QFile write (coroutine-friendly).

.. method:: virtual void close() override

    Close underlying QFile.

.. method:: virtual qint64 size() override

    Get file size.

.. method:: bool seek(qint64 pos)

    Reposition file pointer.

.. method:: QString fileName() const

    Retrieve filename.

.. method:: static QSharedPointer<RawFile> open(const QString &filepath, const QString &mode = QString())

    Open file with mode, set non-block flag (Unix).

.. method:: static QSharedPointer<RawFile> open(const QString &filepath, QIODevice::OpenMode mode)

    Open via QIODevice mode with non-block flag.


7.1.3 BytesIO
+++++++++++++++

In-memory byte stream simulating file operations.

.. method:: virtual qint32 read(char *data, qint32 size)

    Read from memory buffer.

.. method:: virtual qint32 write(const char *data, qint32 size)

    Write to memory buffer.

.. method:: virtual void close()

    No-op (no close needed for memory).

.. method:: virtual qint64 size()

    Get buffer size.

.. method:: virtual QByteArray readall(bool *ok)

    Return entire buffer content.

.. method:: QByteArray data()

    Access underlying QByteArray.

7.1.4 PosixPath
+++++++++++++++++

POSIX-compliant path handling class for cross-platform development.

.. method:: PosixPath operator/(const QString &path)

    Path concatenation (may contain ../.).

.. method:: PosixPath operator|(const QString &path)

    Auto-normalize path (filter ../.).

.. method:: bool isNull()

    Check empty path.

.. method:: bool isFile()

    Check regular file.

.. method:: bool isDir()

    Check directory.

.. method:: bool isSymLink()

    Check symbolic link.

.. method:: bool isAbsolute()

    Check absolute path.

.. method:: bool isExecutable()

    Check executable flag.

.. method:: bool isReadable()

    Check read permission.

.. method:: bool isRelative()

    Check relative path.

.. method:: bool isRoot()

    Check root directory.

.. method:: bool isWritable()

    Check write permission.

.. method:: bool exists()

    Check path existence.

.. method:: qint64 size()

    Get file size.

.. method:: QString path()

    Get full path string.

.. method:: QFileInfo fileInfo()

    Get QFileInfo object.

.. method:: QString parentDir()

    Get parent directory path.

.. method:: PosixPath parentPath()

    Get parent as PosixPath.

.. method:: QString name()

    Get filename (without extension).

.. method:: QString baseName()

    Alias of name().

.. method:: QString suffix()

    Get last extension.

.. method:: QString completeBaseName()

    Get multi-segment filename.

.. method:: QString completeSuffix()

    Get multi-segment extension.

.. method:: QString toAbsolute()

    Convert to absolute path.

.. method:: QString relativePath(const QString &other)

    Get relative path (string version).

.. method:: QString relativePath(const PosixPath &other)

    Get relative path (object version).

.. method:: bool isChildOf(const PosixPath &other)

    Check descendant relationship.

.. method:: bool hasChildOf(const PosixPath &other)

    Check ancestor relationship.

.. method:: QDateTime created()

    Get creation time.

.. method:: QDateTime lastModified()

    Get modification time.

.. method:: QDateTime lastRead()

    Get access time.

.. method:: QStringList listdir()

    List directory contents.

.. method:: QList<PosixPath> children()

    Get child paths as objects.

.. method:: bool mkdir(bool createParents = false)

    Create directory (with parent creation if enabled).

.. method:: bool touch()

    Not implemented.

.. method:: QSharedPointer<RawFile> open(const QString &mode = QString())

    Open via RawFile with mode string (e.g. "rw+").

.. method:: QByteArray readall(bool *ok)

    Read entire file content.

.. method:: static PosixPath cwd()

    Get current working directory.

7.1.5 Additional Functions
+++++++++++++++++++++++++++

.. method:: QDebug &operator<<(QDebug &, const PosixPath &)

    Debug output for PosixPath.

.. method:: uint qHash(const PosixPath &path, uint seed = 0)

    Generate hash for QHash key usage.

.. method:: QPair<QString, QString> safeJoinPath(const QString &parentDir, const QString &subPath)

    Normalize path joining with security checks.

.. method:: QPair<QFileInfo, QString> safeJoinPath(const QDir &parentDir, const QString &subPath)

    QDir version of path joining.
