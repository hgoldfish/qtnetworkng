QtNetworkNg 参考文档
====================

1. 使用协程
-----------

1.1 基础与示例
^^^^^^^^^^^^^^

协程是轻量级线程。在其他编程语言中，也被称为 *fiber* 、 *goroutine* 、 *greenlet* 等。协程拥有独立的栈空间，可以手动切换（yield）到其他协程。

.. code-block:: c++
    :caption: 示例 1: 在两个协程间进行切换

    // 警告: yield() 通常不直接使用, 这里只是为了展示协程的切换
    #include <qtnetworkng/qtnetworkng.h>
    #include <QCoreApplication>
    
    using namespace qtng;
    
    class MyCoroutine: public BaseCoroutine {
    public:
        MyCoroutine()
        :BaseCoroutine(nullptr) {
            // 保存协程上下文
            old = BaseCoroutine::current();
        }
        void run() {
            qDebug() << "我的协程在这里";
            // 切换回主协程
            old->yield();
        }
    private:
        BaseCoroutine *old;
    };
    
    int main(int argc, char **argv) {
        QCoreApplication app(argc, argv);
        // 一旦创建了一个新的协程，主线程就会隐式地转换为主协程。
        MyCoroutine m;
        qDebug() << "主协程在这里";
        // 切换到新的协程，yield（）函数返回直到切换回来。
        m.yield();
        qDebug() << "返回主协程";
        return 0;
    }

上述示例中，我们首先定义继承自``BaseCoroutine``的``MyCoroutine``，并重写其``run()``成员函数。程序输出：

.. code-block:: text
    :caption: 示例1的输出

    主协程在这里
    我的协程在这里
    返回主协程
    不要删除运行中的BaseCoroutine: QObject(0x7ffdfae77e40)  # 可安全忽略的警告
 
``BaseCoroutine::raise()`` 与 ``BaseCoroutine::yield()`` 类似，但会向目标协程发送``CoroutineException``异常。

实际开发中更常用的是``Coroutine::start()``和``Coroutine::kill()``。QtNetworkNg 将协程功能分为``BaseCoroutine``和``Coroutine``两个类：

- ``BaseCoroutine``：提供基础切换功能
- ``Coroutine``：通过事件循环协程实现调度

示例2:展示两个协程交替执行

.. code-block:: c++
    :caption: 示例 2: 两个协程交替运行.
    
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    
    struct MyCoroutine: public Coroutine {
        MyCoroutine(const QString &name)
            : name(name) {}
        void run() override {
            for (int i = 0; i < 3; ++i) {
                qDebug() << name << i;
                // 进入事件循环，将在100 ms后切换回来。详情参见1.7.
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
        // 切换回主协程
        coroutine1.join();
        // 切换到第二个协程来完成它
        coroutine2.join();
        return 0;
    }

输出结果：

.. code-block:: text
    :caption: 示例2的输出
    
    "coroutine1" 0
    "coroutine2" 0
    "coroutine1" 1
    "coroutine2" 1
    "coroutine1" 2
    "coroutine2" 2

1.2 启动协程
^^^^^^^^^^^^

.. note:: 

    使用 ``CoroutineGroup::spawn()`` 或 ``CoroutineGroup::spawnWithName()`` 来启动和管理新协程。

有多种方式可以启动新协程：

* 继承 ``Coroutine`` 并重写 ``Coroutine::run()`` 函数，该函数将在新协程中运行。
        
.. code-block:: c++
    :caption: 示例3: 启动协程的第一种方法
    
    class MyCoroutine: public Coroutine {
    public:
        virtual void run() override {
            // 在新协程中运行
        }
    };
    
    void start() {
        MyCoroutine coroutine;
        coroutine.join();
    }
    
* 将函数传递给 ``Coroutine::spawn()`` 函数，该函数会返回新协程。传递的函数将在新协程中被调用。

.. code-block:: c++
    :caption: 示例4: 启动协程的第二种方法
    
    void sendMessage() {
        // 在新协程中运行
    }
    Coroutine *coroutine = Corotuine::spawn(sendMessage);
    
* ``Coroutine::spawn()`` 接受 ``std::function<void()>`` 函数对象，因此也支持 C++11 lambda 表达式。

.. code-block:: c++
    :caption: 示例5: 启动协程的第三种方法
    
    QSharedPointer<Event> event(new Event);
    Coroutine *coroutine = Coroutine::spawn([event]{
        // 在新协程中运行
    });
    
.. note::

    捕获的对象必须在协程启动后继续存在。更多细节参考《最佳实践》。

* 传递 ``QObjet`` 实例和槽函数名，该槽函数将在新协程中被调用。
    
.. code-block:: c++
    :caption: 示例6: 启动协程的第四种方法
    
    class Worker: public QObject {
        Q_OBJECT
    public slots:
        void sendMessage() {
            // 在新协程中运行
        }
    };
    Worker worker;
    Coroutine coroutine(&worker, SLOT(sendMessage()));
    coroutine.join();

.. method:: Deferred<BaseCoroutine*> BaseCoroutine::started`

和

.. method:: Deferred<BaseCoroutine*> BaseCoroutine::finished


1.3 操作协程
^^^^^^^^^^^^^^^^^^^^^^

最常用的函数位于 ``Coroutine`` 类中。

.. method:: bool Coroutine::isRunning() const

    检查协程是否正在运行，返回 true 或 false。

.. method:: bool Coroutine::isFinished() const

    检查协程是否已完成。若协程未启动或仍在运行则返回 false，否则返回 `true`。

.. method:: Coroutine *Coroutine::start(int msecs = 0);

    调度协程在当前协程阻塞时启动，并立即返回。参数 ``msecs`` 指定协程启动前的等待微秒数（从 ``start()`` 调用时开始计时）。返回 `this` 协程对象以支持链式调用。例如：

    .. code-block:: c++
        :caption: 示例7: 启动协程
        
        QSharedPointer<Coroutine> coroutine(new MyCoroutine);
        coroutine->start()->join();

.. method:: void Coroutine::kill(CoroutineException *e = 0, int msecs = 0)

    调度协程在当前协程阻塞时抛出 ``CoroutineException`` 类型异常 ``e``，并立即返回。参数 ``msecs`` 指定操作执行前的等待微秒数（从 ``kill()`` 调用时开始计时）。

    若未指定参数 ``e``，将发送 ``CoroutineExitException``。

    若协程尚未启动，调用 ``kill()`` 可能导致协程启动后立即抛出异常。若需避免此行为，请改用 ``cancelStart()``。

.. method:: void Coroutine::cancelStart()

    若协程已被调度启动，本函数可取消该调度。若协程已启动，本函数将终止协程。最终协程状态会被设为 ``Stop``。

.. method:: bool Coroutine::join()

    阻塞当前协程直至目标协程停止。本函数将切换当前协程至事件循环协程，后者负责执行调度任务（如启动新协程、检查套接字可读/写状态）。

.. method:: virtual void Coroutine::run()

    重写本函数以定义协程逻辑。参考 *1.2 启动协程*。

.. method:: static Coroutine *Coroutine::current()

    静态函数返回当前协程对象指针。请勿保存该指针。

.. method:: static void Coroutine::msleep(int msecs)

    静态函数阻塞当前协程 ``msecs`` 微秒后唤醒。

.. method:: static void Coroutine::sleep(float secs)

    静态函数阻塞当前协程 ``secs`` 秒后唤醒。

.. method:: static Coroutine *Coroutine::spawn(std::function<void()> f)

    静态函数通过函数对象 ``f`` 启动新协程。参考 *1.2 启动协程*。

``BaseCoroutine`` 包含一些较少使用的函数，使用时需谨慎。

.. method:: State BaseCoroutine::state() const

    返回协程当前状态（``Initialized``, ``Started``, ``Stopped``, ``Joined``）。建议优先使用 `Coroutine::isRunning()` 或 ``Coroutine::isFinished()``。

.. method:: bool BaseCoroutine::raise(CoroutineException *exception = 0)

    立即切换至目标协程并抛出 ``CoroutineException`` 类型异常。若未指定 ``exception``，默认抛出 ``CoroutineExitException``。
    
    建议优先使用 ``Coroutine::kill()``。

.. method:: bool BaseCoroutine::yield()

    立即切换至目标协程。
    
    建议优先使用 ``Coroutine::start()``。

.. method:: quintptr BaseCoroutine::id() const

    返回协程唯一不可变 ID（通常为协程指针值）。

.. method:: BaseCoroutine *BaseCoroutine::previous() const

    返回本协程结束后将切换到的 ``BaseCoroutine`` 指针。

.. method:: void BaseCoroutine::setPrevious(BaseCoroutine *previous)

    设置本协程结束后将切换到的 ``BaseCoroutine`` 指针。

.. attribute:: Deferred<BaseCoroutine*> BaseCoroutine::started

    本属性为 ``Deferred`` 对象，作用类似 Qt 事件。可通过添加回调函数在协程启动后执行操作。

.. attribute:: Deferred<BaseCoroutine*> BaseCoroutine::finished

    本属性为 ``Deferred`` 对象，作用类似 Qt 事件。可通过添加回调函数在协程结束后执行操作。

1.4 使用 CoroutineGroup 管理多个协程
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

在 C++ 中创建和删除协程较为复杂，主要由于内存管理问题。通常需确保协程使用的资源在外部删除前协程已退出，并遵循以下规则：

• Lambda 捕获的不可变对象必须通过值传递（非指针或引用）
• 捕获可变对象时应使用智能指针（如 ``std::shared_ptr<>`` 或 ``QSharedPointer<>``）
• 若捕获 ``this`` 指针，需确保对象生命周期
• 在所有资源删除前删除协程

``CoroutineGroup`` 的使用模式遵循三条原则：

• 在类中声明 ``CoroutineGroup`` 指针（非值类型），避免隐式析构
• 在类析构函数中优先删除 ``CoroutineGroup``
• 始终通过 ``CoroutineGroup`` 启动协程

示例：

.. code-block:: c++
    :caption: 使用 CoroutineGroup
    
    class MainWindow: public QMainWindow {
    public:
        MainWindow();
        virtual ~MainWindow() override;
    private:
        void loadDataFromWeb();
    private:
        QPlainText *textEdit;
        CoroutineGroup *operations;  // 声明为指针
    };

    MainWindow::MainWindow()
        :textEdit(new QPlainText(this)), operations(new CoroutineGroup)
    {
        setCentralWidget(textEdit);
        // 通过 CoroutineGroup 启动协程
        operations->spawn([this] {
            loadDataFromWeb();
        });
    }
    
    MainWindow::~MainWindow()
    {
        // 优先删除 CoroutineGroup
        delete operations;
        delete textEdit;
    }
    
    void MainWindow::loadDataFromWeb()
    {
        HttpSession session;
        textEdit->setPlainText(session.get("https://news.163.com/").html());
    }

``CoroutineGroup`` 方法列表：

.. method:: bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString())

    通过智能指针添加协程到组。指定 ``name`` 后可后续通过 ``get()`` 获取
    
.. method:: bool add(Coroutine *coroutine, const QString &name = QString())

    通过裸指针添加协程到组。指定 ``name`` 后可后续通过 ``get()`` 获取
    
.. method:: bool start(Coroutine *coroutine, const QString &name = QString())

    启动协程并添加到组。指定 ``name`` 后可后续通过 ``get()`` 获取

.. method:: QSharedPointer<Coroutine> get(const QString &name)

    按名称获取协程。未找到返回空指针
    
.. method:: bool kill(const QString &name, bool join = true)

    按名称终止协程。``join=true`` 时等待协程结束，``join=false`` 立即返回

.. method:: bool killall(bool join = true)

    终止组内所有协程。``join=true`` 时等待所有协程结束

.. method:: bool joinall()

    等待组内所有协程结束

.. method:: int size() const

    返回组内协程数量

.. method:: bool isEmpty() const

    判断组是否为空

.. method:: QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func, bool replace = false)

    启动名为 ``name`` 的协程执行 ``func``。``replace=false`` 时同名协程存在则不操作，返回旧协程；``replace=true`` 返回新协程

.. method:: QSharedPointer<Coroutine> spawn(const std::function<void()> &func)

    启动新协程执行 ``func`` 并添加到组

.. method:: QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool replace = false)

    在新线程执行 ``func``，创建等待线程完成的协程并命名。同名处理逻辑同 ``spawnWithName``

.. method:: QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func)

    在新线程执行 ``func``，创建等待线程完成的协程并添加到组

.. method:: static QList<T> map(std::function<T(S)> func, const QList<S> &l)

    并行处理列表元素，返回结果列表：

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

    并行处理列表元素无返回值：

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

1.5 协程间通信
^^^^^^^^^^^^^^

相较于 `boost::coroutine`，QtNetworkNg 最显著的优势在于其完善的协程通信机制。

1.5.1 RLock
+++++++++++

`可重入锁` 是一种互斥（mutex）机制，允许同一协程多次加锁而不会引发死锁。

.. _可重入锁: https://en.wikipedia.org/wiki/Reentrant_mutex

``Lock``、``RLock``、``Semaphore`` 通常通过 ``ScopedLock<T>`` 在函数返回前自动释放锁：

.. code-block:: c++
    :caption: 使用 RLock
    
    #include "qtnetworkng.h"

    using namespace qtng;

    void output(QSharedPointer<RLock> lock, const QString &name)
    {
        ScopedLock<RLock> l(*lock);    // 立即获取锁，函数返回前自动释放。注释此行可观察不同效果
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
    
输出结果：

.. code-block:: text
    :caption: 带 RLock 的输出
    
    "first" 1
    "first" 2
    "second" 1
    "second" 2

若注释 ``ScopedLock l(lock);`` 行，输出变为：

.. code-block:: text
    :caption: 无 RLock 的输出
    
    "first" 1
    "second" 1
    "first" 2
    "second" 2

.. method:: bool acquire(bool blocking = true)

    获取锁。若锁被其他协程持有且 ``blocking=true``，则阻塞当前协程直至锁释放；否则立即返回。
    
    返回是否成功获取锁。
    
.. method:: void release()

    释放锁。等待此锁的协程将在当前协程切换至事件循环协程后恢复执行。
    
.. method:: bool isLocked() const

    检测是否有协程持有此锁。
    
.. method:: bool isOwned() const

1.5.2 Event
+++++++++++

`Event` (事件信号量)是用于通知等待协程特定条件已触发的同步机制。

.. _Event: https://en.wikipedia.org/wiki/Event_(synchronization_primitive)

.. method:: bool wait(bool blocking = true)

    等待事件。若事件未触发且 ``blocking=true``，阻塞当前协程直至事件触发；否则立即返回。
    
    返回事件是否已触发。
    
.. method:: void set()

    触发事件。等待此事件的协程将在当前协程切换至事件循环协程后恢复。
    
.. method:: void clear()

    重置事件状态。
    
.. method:: bool isSet() const

    检测事件是否已触发。
    
.. method:: int getting() const

    获取当前等待此事件的协程数量。
    
1.5.3 ValueEvent<>
++++++++++++++++++

``ValueEvent<>`` 继承自 ``Event``，支持协程间传递数据。

.. code-block:: c++
    :caption: 使用 ValueEvent<> 传递值
    
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

输出结果：

.. code-block:: text

    3

.. method:: void send(const Value &value)
    
    发送数据并触发事件。等待协程将在当前协程切换至事件循环协程后恢复。
    
.. method:: Value wait(bool blocking = true)
    
    等待事件。若事件未触发且 ``blocking=true``，阻塞当前协程直至触发。返回发送的数据，失败时返回默认构造值。
    
.. method:: void set()

    触发事件（与 ``send()`` 等效）。
    
.. method:: void clear()

    重置事件状态。
    
.. method:: bool isSet() const

    检测事件是否已触发。
    
.. method:: int getting() const

1.5.4 Gate
++++++++++

``Gate`` 是 ``Event`` 的特殊接口，用于控制数据传输速率。

.. method:: bool goThrough(bool blocking = true)

    等效于 ``Event::wait()``。
    
.. method:: bool wait(bool blocking = true)

    等效于 ``Event::wait()``。
    
.. method:: void open();

    等效于 ``Event::set()``。
    
.. method:: void close();

    等效于 ``Event::clear()``。
    
.. method:: bool isOpen() const;

    等效于 ``Event::isSet()``。
    
1.5.5 Semaphore
+++++++++++++++

`信号量` 是用于控制多协程共享资源访问的变量或抽象数据类型。

.. _信号量: https://en.wikipedia.org/wiki/Semaphore_(programming)

.. code-block:: c++
    :caption: 使用 Semaphore 控制请求并发数
    
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

该示例启动 100 个协程，但仅有 5 个协程同时向 HTTP 服务器发起请求。

.. method:: Semaphore(int value = 1)
    :no-index:

    构造函数指定最大资源数 ``value``。
    
.. method:: bool acquire(bool blocking = true)

    获取信号量。若资源耗尽且 ``blocking=true``，阻塞当前协程直至其他协程释放资源；否则立即返回。
    
    返回是否成功获取信号量。
    
.. method:: void release()

    释放信号量。等待此信号量的协程将在当前协程切换至事件循环协程后恢复。

.. method:: bool isLocked() const
    
    检测信号量是否被任一协程占用。

1.5.6 Queue
+++++++++++

协程间队列。

.. method:: Queue(int capacity)
    :no-index:

构造函数指定队列容量 ``capacity``。

.. method:: void setCapacity(int capacity)

设置队列最大容量。

.. method:: bool put(const T &e)

插入元素 ``e``。若队列已满，阻塞当前协程直至其他协程取出元素。

.. method:: T get()

取出元素。若队列为空，阻塞当前协程直至其他协程插入元素。

.. method:: bool isEmpty() const

检测队列是否为空。

.. method:: bool isFull() const

检测队列是否已满。

.. method:: int getCapacity() const

获取队列容量。

.. method:: int size() const

返回队列当前元素数量。

.. method:: int getting() const

返回当前等待元素的协程数量。

1.5.7 Lock
++++++++++

``Lock`` 类似 ``RLock``，但同一协程重复加锁会导致死锁。

1.5.8 Condition
+++++++++++++++

协程间变量值监控。

.. method:: bool wait()

阻塞当前协程直至被其他协程的 ``notify()`` 或 ``notifyAll()`` 唤醒。

.. method:: void notify(int value = 1)

唤醒指定数量（``value``）的等待协程。

.. method:: void notifyAll()

唤醒所有等待协程。

.. method:: int getting() const

返回当前等待此条件的协程数量。

1.6 实用工具
^^^^^^^^^^^^^

提供多个实用函数解决协程事件循环与 Qt 事件循环的冲突问题。

QtNetworkNg 编程中**最严重的错误**是在事件循环协程中调用阻塞函数（如 ``Socket`` 函数、``RLock`` 函数、``Event`` 函数），这将导致未定义行为。请始终在事件循环中发射 Qt 信号，并在派生协程中处理信号。若检测到此错误，QtNetworkNg 会输出警告信息。此错误易于排查。

另一常见错误是在协程中使用 ``QDialog::exec()`` 运行局部事件循环。以下函数可解决此类问题，并支持在协程中创建线程：

.. method:: T callInEventLoop(std::function<T ()> func)

    在事件循环中执行函数并返回结果。

    运行局部事件循环：

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
        
    在事件循环发射信号：
    
    .. code-block:: c++
    
        QString filePath = receiveFile();
        callInEventLoop([this, filePath]{
            emit fileReceived(filePath);
        });

.. method:: void callInEventLoopAsync(std::function<void ()> func, quint32 msecs = 0)

    本函数为 ``callInEventLoop()`` 的异步版本，立即返回并在 ``msecs`` 毫秒后调度函数执行。
    
    .. code-block:: c++
    
        if (error) {
            callInEventLoopAsync([this] {
                QMessageBox::information(this, windowTitle(), tr("操作失败"));
            });
            return;
        }
    
    注意：``callInEventLoopAsync()`` 比 ``callInEventLoop()`` 更轻量。多数情况下若不关心函数结果，建议使用本函数。
    
    
.. method:: T callInThread(std::function<T()> func)

    在新线程执行函数并返回结果。
    
.. method:: void qAwait(const typename QtPrivate::FunctionPointer<Func>::Object *obj, Func signal)

    等待 Qt 信号触发。
    
    .. code-block:: c++
    
        QNetworkRequest request(url);
        QNetworkReply *reply = manager.get(request);
        qAwait(reply, &QNetworkReply::finished);
        text->setPlainText(reply->readAll());


1.7 内部机制：协程如何切换
^^^^^^^^^^^^^^^^^^^^^^^^^^

1.7.1 Functor
++++++++++++++
抽象回调接口，定义统一的 operator()方法，所有具体回调需继承此类，例如定时器回调，IO事件回调

.. method:: virtual bool operator()()=0
    
    纯虚基类，子类需实现具体逻辑

1.7.2 DoNothingFunctor
++++++++++++++++++++++++
空操作回调，可用于占位或默认回调

.. method::operator()()=0

  空操作回调，直接返回 false

1.7.3 YieldCurrentFunctor
++++++++++++++++++++++++++++++
让出当前操作的执行权

.. method::explicit YieldCurrentFunctor()

  保存当前协程的指针

.. method::virtual bool operator()()
 
 重新唤醒保存的指针

1.7.4 DeleteLaterFunctor<T>
++++++++++++++++++++++++++++++
延迟删除对象，避免在回调中直接析构

.. method::virtual bool operator()()

 释放动态分配的对象

1.7.5 LambdaFunctor
++++++++++++++++++++
包装函数，允许lambda表达式作为回调

.. method::virtual operator()()

  调用callback() 执行用户定义逻辑

1.7.6 callInEventLoopCoroutine
+++++++++++++++++++++++++++++++
协程事件循环的核心类，作为事件循环的载体,负责管理 ​I/O 事件监听、定时器调度、协程挂起与恢复，并协调协程与底层事件驱动的交互。

I/O操作类型

    .. code-block:: c++

        enum EventType {
            Read = 1,
            Write = 2,
            ReadWrite = 3,
        };

.. method:: int createWatcher(EventType event, qintptr fd, Functor *callback)

 创建针对文件描述符 fd 的读写事件监视器，绑定回调函数 callback

.. method:: void startWatcher(int watcherId);

 启动指定 ID 的监视器。适用于动态控制事件监听。

.. method:: void stopWatcher(int watcherId);

 停止指定 ID 的监视器。适用于动态控制事件监听。

.. method:: void removeWatcher(int watcherId);

 移除监视器，释放相关资源。

.. method:: void triggerIoWatchers(qintptr fd);

 手动触发与 fd 关联的所有已注册事件回调。用于外部事件通知。

.. method:: void callLaterThreadSafe(quint32 msecs, Functor *callback)

 线程安全地调度一个延迟 msecs 毫秒后执行的异步回调。

.. method:: int callLater(quint32 msecs, Functor *callback)

 延迟 msecs 毫秒后执行一次 callback，返回定时器 ID。

.. method:: int callRepeat(quint32 msecs, Functor *callback) 

 每隔 msecs 毫秒重复执行 callback，返回定时器 ID。

.. method:: void cancelCall(int callbackId)

 取消指定 ID 的定时器，防止回调执行。

.. method:: bool runUntil(BaseCoroutine *coroutine)
 
 运行事件循环，直到 coroutine 协程结束。用于阻塞等待协程完成。

.. method:: bool yield();

 挂起当前协程，让出 CPU 给其他协程。通常在等待事件时调用。

 .. method:: int exitCode()

 返回事件循环的终止状态码，用于判断事件循环的运行结果。

.. method:: bool isQt()

 判断事件循环的后端实现(Qt) 

.. method:: bool isEv() 

 判断事件循环的后端实现(libev)

.. method:: bool isWin()
 
 判断事件循环的后端实现(winev)

.. method:: static EventLoopCoroutine *get();

 事件循环的统一入口，通过线程本地存储管理实例生命周期，并适配多平台后端，是异步编程的核心枢纽。其设计理念与 Python 的 asyncio.get_event_loop() 一脉相承，但结合 C++ 特性实现了更底层的控制。

1.7.7 ScopedIoWatcher
+++++++++++++++++++++++
RAII 封装 IO 事件监视器，自动管理资源。

.. method:: ScopedIoWatcher(EventType, qintptr fd)
    :no-index:

 创建指定类型（读/写）的文件描述符监视器。

.. method:: ​bool start()

 启动监视器。

1.7.8 CurrentLoopStorage
+++++++++++++++++++++++++
 事件循环的抽象基类，定义平台相关的接口。

.. method:: QSharedPointer<EventLoopCoroutine> getOrCreate();

 获取当前线程的事件循环实例；若不存在则创建新实例。

.. method:: QSharedPointer<EventLoopCoroutine> get();

 仅获取当前线程的事件循环实例，若未初始化则返回空指针。

.. method:: void set(QSharedPointer<EventLoopCoroutine> eventLoop);

 显式设置当前线程的事件循环实例（覆盖自动创建逻辑）。

.. method:: void clean();

 清空当前线程的事件循环实例，触发 QSharedPointer 的引用计数析构。
    
2. 基础网络编程
----------------------------

QtNetworkNg 支持 IPv4 和 IPv6，旨在提供类似 Python socket 模块的面向对象套接字接口。

除基础套接字接口外，QtNetworkNg 还支持 Socks5 代理，并提供 ``SocketServer`` 相关类简化服务器开发。

2.1 Socket
^^^^^^^^^^

创建套接字非常简单，只需实例化 ``Socket`` 类或将平台特定的套接字描述符传递给构造函数。

.. code-block:: c++
    :caption: Socket 构造函数
    
    Socket(HostAddress::NetworkLayerProtocol protocol = AnyIPProtocol, SocketType type = TcpSocket);
    
    Socket(qintptr socketDescriptor);

参数 ``protocol`` 可用于限制协议为 IPv4 或 IPv6。若省略此参数，``Socket`` 将自动选择首选协议（通常优先选择 IPv6）。TODO: 描述具体方法。

参数 ``type`` 指定套接字类型，目前仅支持 TCP 和 UDP。若省略此参数，默认使用 TCP。

第二种构造函数形式适用于将其他网络编程工具创建的套接字转换为 QtNetworkNg 套接字。传入的套接字必须处于已连接状态。

以下是 ``Socket`` 类型的成员函数：

.. method:: Socket *accept()

    若套接字处于监听状态，``accept()`` 将阻塞当前协程，并在新客户端连接后返回新的 ``Socket`` 对象。该对象已与新客户端建立连接。若套接字被其他协程关闭，函数返回 ``0``。

.. method:: bool bind(HostAddress &address, quint16 port = 0, BindMode mode = DefaultForPlatform)

    将套接字绑定到 ``address`` 和 ``port``。若省略 ``port`` 参数，操作系统将自动分配未使用的随机端口（可通过 ``port()`` 函数获取）。参数 ``mode`` 当前未使用。
    
    成功绑定端口时返回 true。

.. method:: bool bind(quint16 port = 0, BindMode mode = DefaultForPlatform)

    将套接字绑定到任意地址和 ``port``。此函数为 ``bind(address, port)`` 的重载形式。

.. method:: bool connect(const HostAddress &host, quint16 port)

    连接到 ``host`` 和 ``port`` 指定的远程主机。阻塞当前协程直至连接建立或失败。
    
    连接成功时返回 true。

.. method:: bool connect(const QString &hostName, quint16 port, HostAddress::NetworkLayerProtocol protocol = AnyIPProtocol)

    使用 ``protocol`` 连接到 ``hostName`` 和 ``port`` 指定的远程主机。若 ``hostName`` 非 IP 地址，QtNetworkNg 将在连接前执行 DNS 查询。阻塞当前协程直至连接建立或失败。
    
    由于 DNS 查询耗时较长，建议对频繁连接的远程主机使用 ``setDnsCache()`` 缓存查询结果。
    
    若省略 ``protocol`` 或指定为 ``AnyIPProtocol``，QtNetworkNg 将优先尝试 IPv6 连接，失败后尝试 IPv4。DNS 返回多个 IP 时按顺序尝试连接。
    
    连接成功时返回 true。

.. method:: bool close()

    关闭套接字。

.. method:: bool listen(int backlog)

    将套接字设为监听模式，后续可通过 ``accept()`` 获取新客户端请求。参数 ``backlog`` 的具体含义与平台相关，请参考 ``man listen`` 手册。

.. method:: bool setOption(SocketOption option, const QVariant &value)

    将指定 ``option`` 设置为 ``value`` 描述的值。该函数用于配置套接字选项。

2.1 Socket
^^^^^^^^^^

套接字选项可通过以下表格配置：

.. list-table:: Socket 选项说明
   :header-rows: 1
   :widths: 30 70

   * - 选项名称
     - 描述
   * - ``BroadcastSocketOption``
     - UDP套接字发送广播数据报
   * - ``AddressReusable``
     - 允许bind()调用重用本地地址
   * - ``ReceiveOutOfBandData``
     - 启用时将带外数据直接放入接收数据流
   * - ``ReceivePacketInformation``
     - 保留选项，暂不支持
   * - ``ReceiveHopLimit``
     - 保留选项，暂不支持
   * - ``LowDelayOption``
     - 禁用Nagle算法
   * - ``KeepAliveOption``
     - 在面向连接的套接字上启用保活报文发送
   * - ``MulticastTtlOption``
     - 设置/读取组播报文的生存时间(TTL)
   * - ``MulticastLoopbackOption``
     - 控制是否回环发送的组播报文
   * - ``TypeOfServiceOption``
     - 设置/读取IP报文的服务类型字段(TOS)
   * - ``SendBufferSizeSocketOption``
     - 设置/获取发送缓冲区最大字节数
   * - ``ReceiveBufferSizeSocketOption``
     - 设置/获取接收缓冲区最大字节数
   * - ``MaxStreamsSocketOption``
     - 保留选项，暂不支持STCP协议
   * - ``NonBlockingSocketOption``
     - 保留选项，Socket内部要求非阻塞模式
   * - ``BindExclusively``
     - 保留选项，暂不支持

注意：Windows Runtime中必须在连接前设置Socket::KeepAliveOption

.. method:: QVariant option(SocketOption option) const

    返回指定选项的当前值
    
.. method:: qint32 recv(char *data, qint32 size)

    接收最多size字节数据，阻塞当前协程直至有数据到达。返回实际接收字节数（0表示连接关闭，-1表示错误）

.. method:: qint32 recvall(char *data, qint32 size)

    接收确切size字节数据，阻塞当前协程直至全部接收或连接关闭。建议在明确数据长度时使用

.. method:: qint32 send(const char *data, qint32 size)

    发送最多size字节数据，返回实际发送字节数（可能小于size）

.. method:: qint32 sendall(const char *data, qint32 size)

    发送全部size字节数据，阻塞直至完成或连接中断

.. method:: qint32 recvfrom(char *data, qint32 size, HostAddress *addr, quint16 *port)

    (仅数据报套接字)接收数据并获取发送方地址

.. method:: qint32 sendto(const char *data, qint32 size, const HostAddress &addr, quint16 port)

    (仅数据报套接字)向指定地址发送数据

.. method:: QByteArray recvall(qint32 size)

    QByteArray版本的全量接收方法

.. method:: QByteArray recv(qint32 size)

    QByteArray版本的接收方法

.. method:: qint32 send(const QByteArray &data)

    QByteArray版本的发送方法

.. method:: qint32 sendall(const QByteArray &data)

    QByteArray版本的全量发送方法

.. method:: QByteArray recvfrom(qint32 size, HostAddress *addr, quint16 *port)

    QByteArray版本的数据报接收方法

.. method:: qint32 sendto(const QByteArray &data, const HostAddress &addr, quint16 port)

    QByteArray版本的数据报发送方法

状态与信息查询
^^^^^^^^^^^^^^
.. method:: SocketError error() const

    返回最后一次错误类型
    
.. method:: QString errorString() const

    返回最后一次错误描述
    
.. method:: bool isValid() const

    检测套接字是否有效
    
.. method:: HostAddress localAddress() const

    获取本地绑定地址
    
.. method:: quint16 localPort() const

    获取本地绑定端口
    
.. method:: HostAddress peerAddress() const

    获取对端地址（仅连接状态有效）
    
.. method:: QString peerName() const

    获取对端主机名
    
.. method:: quint16 peerPort() const

    获取对端端口
    
.. method:: qintptr fileno() const

    获取原生套接字描述符
    
协议与类型
^^^^^^^^^^
.. method:: SocketType type() const

    返回套接字类型(TCP/UDP)
    
.. method:: SocketState state() const

    返回当前状态
    
.. method:: NetworkLayerProtocol protocol() const

    返回网络层协议
    
DNS相关
^^^^^^^
.. method:: static QList<HostAddress> resolve(const QString &hostName)

    执行DNS解析
    
.. method:: void setDnsCache(QSharedPointer<SocketDnsCache> dnsCache)

    设置DNS缓存

2.2 SslSocket
^^^^^^^^^^^^^

``SslSocket`` 设计类似 ``Socket``，继承大部分函数如 ``connect()``、``recv()``、``send()``、``peerName()`` 等，但排除仅用于 UDP 套接字的 ``recvfrom()`` 和 ``sendto()``。

构造函数提供三种形式：

.. code-block:: c++
    :caption: SslSocket 构造函数
    
    SslSocket(HostAddress::NetworkLayerProtocol protocol = Socket::AnyIPProtocol,
            const SslConfiguration &config = SslConfiguration());
    
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());

信息获取相关方法：

.. method:: bool handshake(bool asServer, const QString &verificationPeerName = QString())

    与对端进行握手协商。参数 ``asServer=true`` 时本端作为 SSL 服务器。仅当基于原生套接字创建时需手动调用此函数。
    
.. method:: Certificate localCertificate() const

    返回本地证书链的顶层证书，通常与 ``SslConfiguration::localCertificate()`` 一致。
    
.. method:: QList<Certificate> localCertificateChain() const

    返回本地完整证书链，包含 ``SslConfiguration::localCertificateChain()`` 及部分 ``SslConfiguration::caCertificates``。
    
.. method:: QByteArray nextNegotiatedProtocol() const

    返回 SSL 连接协商的下一层协议（如 HTTP/2 需 ALPN 扩展）。
    
    .. _The Application-Layer Protocol Negotiation: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation

.. method:: NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const

    返回协议协商状态。
    
.. method:: SslMode mode() const

    返回 SSL 连接模式（服务端/客户端）。
    
.. method:: Certificate peerCertificate() const

    返回对端证书链顶层证书。
    
.. method:: QList<Certificate> peerCertificateChain() const

    返回对端完整证书链。
    
.. method:: int peerVerifyDepth() const

    返回证书验证深度限制。若对端证书链层级超过此值则验证失败。
    
.. method:: Ssl::PeerVerifyMode peerVerifyMode() const

    返回对端验证模式。

2.2 SslSocket
^^^^^^^^^^^^^

``SslSocket`` 设计类似 ``Socket``，继承大部分函数如 ``connect()``、``recv()``、``send()``、``peerName()`` 等，但排除仅用于 UDP 套接字的 ``recvfrom()`` 和 ``sendto()``。

构造函数提供三种形式：

.. code-block:: c++
    :caption: SslSocket 构造函数
    
    SslSocket(HostAddress::NetworkLayerProtocol protocol = Socket::AnyIPProtocol,
            const SslConfiguration &config = SslConfiguration());
    
    SslSocket(qintptr socketDescriptor, const SslConfiguration &config = SslConfiguration());
    
    SslSocket(QSharedPointer<Socket> rawSocket, const SslConfiguration &config = SslConfiguration());

信息获取相关方法：

.. method:: bool handshake(bool asServer, const QString &verificationPeerName = QString())

    与对端进行握手协商。参数 ``asServer=true`` 时本端作为 SSL 服务器。仅当基于原生套接字创建时需手动调用此函数。
    
.. method:: Certificate localCertificate() const

    返回本地证书链的顶层证书，通常与 ``SslConfiguration::localCertificate()`` 一致。
    
.. method:: QList<Certificate> localCertificateChain() const

    返回本地完整证书链，包含 ``SslConfiguration::localCertificateChain()`` 及部分 ``SslConfiguration::caCertificates``。
    
.. method:: QByteArray nextNegotiatedProtocol() const

    返回 SSL 连接协商的下一层协议（如 HTTP/2 需 ALPN 扩展）。
    
    .. _The Application-Layer Protocol Negotiation: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation

.. method:: NextProtocolNegotiationStatus nextProtocolNegotiationStatus() const

    返回协议协商状态。
    
.. method:: SslMode mode() const

    返回 SSL 连接模式（服务端/客户端）。
    
.. method:: Certificate peerCertificate() const

    返回对端证书链顶层证书。
    
.. method:: QList<Certificate> peerCertificateChain() const

    返回对端完整证书链。
    
.. method:: int peerVerifyDepth() const

    返回证书验证深度限制。若对端证书链层级超过此值则验证失败。
    
.. method:: Ssl::PeerVerifyMode peerVerifyMode() const

    返回对端验证模式：

 .. list-table:: QSslSocket 对等验证模式说明
   :header-rows: 1
   :widths: 30 70

   * - PeerVerifyMode
     - 描述
   * - ``VerifyNone``
     - 不要求对端提供证书，连接仍加密但身份验证关闭
   * - ``QueryPeer``
     - 请求对端证书但不强制验证（服务端默认模式）
   * - ``VerifyPeer``
     - 强制验证对端证书有效性（客户端默认模式）
   * - ``AutoVerifyPeer``
     - 自动模式：服务端用 QueryPeer，客户端用 VerifyPeer


.. method:: QString peerVerifyName() const

    返回对端验证名称
    
.. method:: PrivateKey privateKey() const

    返回本端私钥（与 ``SslConfiguration::privateKey()`` 一致）
    
.. method:: SslCipher cipher() const

    返回当前加密套件（握手完成后生效，无效时 ``Cipher::isNull()==true``）
    
.. method:: Ssl::SslProtocol sslProtocol() const

    返回使用的 SSL/TLS 协议版本
    
.. method:: SslConfiguration sslConfiguration() const

    返回当前 SSL 配置
    
.. method:: QList<SslError> sslErrors() const

    返回握手及通信期间发生的错误列表
    
.. method:: void setSslConfiguration(const SslConfiguration &configuration)

    设置 SSL 配置（必须在握手前调用）

2.3 Socks5 代理
^^^^^^^^^^^^^^^^

``Socks5Proxy`` 提供 SOCKS5 客户端支持，支持通过代理服务器连接远程主机。

构造函数：

.. code-block:: c++
    :caption: Socks5Proxy 构造函数
    
    Socks5Proxy();  // 创建空代理对象
    
    Socks5Proxy(const QString &hostName, quint16 port,
                 const QString &user = QString(), const QString &password = QString());  // 带认证信息的代理

核心方法：

.. method:: QSharedPointer<Socket> connect(const QString &remoteHost, quint16 port)

    通过代理连接域名型目标（代理端执行DNS解析），阻塞协程直至连接成功/失败
    
.. method:: QSharedPointer<Socket> connect(const HostAddress &remoteHost, quint16 port)

    通过代理连接IP型目标，无DNS解析过程
    
.. method:: QSharedPointer<SocketLike> listen(quint16 port)

    请求代理服务器监听指定端口，返回监听对象
    
.. method:: bool isNull() const
    
    检测代理配置是否有效（hostName/port是否为空）
    
.. method:: Capabilities capabilities() const

    获取代理服务器支持的能力
    
属性访问器：

.. method:: QString hostName() const

    代理服务器主机名
    
.. method:: quint16 port() const

    代理服务器端口
    
.. method:: QString user() const

    代理认证用户名
    
.. method:: QString password() const

    代理认证密码
    
属性设置器：

.. method:: void setCapabilities(QFlags<Capability> capabilities)

    设置代理能力标识
    
.. method:: void setHostName(const QString &hostName)
    
    设置代理主机名
    
.. method:: void setPort(quint16 port)

    设置代理端口
    
.. method:: void setUser(const QString &user)

    设置认证用户
    
.. method:: void setPassword(const QString &password)

    设置认证密码

2.4 SocketServer
^^^^^^^^^^^^^^^^

2.4.1 BaseStreamServer
+++++++++++++++++++++++
 ``BaseStreamServer`` 是构建其他SocketServer基础核心类，提供了一些Socket服务器基础方法，以及保留了一些接口，用于进一步实现 ``TcpServer`` 和 ``KcpServer`` 等类型

.. method:: BaseStreamServer(const HostAddress &serverAddress, quint16 serverPort);

    初始化服务器监听的地址和端口，默认使用 HostAddress::Any 绑定到所有网络接口，同时初始化事件对象 started 和 stopped，用于跟踪服务器状态。

.. method:: bool serveForever()

    阻塞式运行服务器，循环接受客户端连接并处理请求。

.. method:: bool start()

    非阻塞式启动服务器，在后台协程中运行服务。

.. method:: void stop()

    立即关闭服务器套接字，终止所有连接

.. method:: bool wait()

    阻塞当前线程,直到服务器完全停止

.. method:: void setAllowReuseAddress(bool b)

    设置是否允许端口复用（SO_REUSEADDR）。

.. method:: bool isSecure()

    标识服务器是否使用加密协议（如SSL）。默认返回：false，子类（如 WithSsl）覆盖后返回 true。

.. method:: QSharedPointer<SocketLike> serverSocket()

    获取底层服务器套接字对象，首次调用会触发 serverCreate() 创建套接字。

.. method:: quint16 serverPort()

    获取服务器绑定的端口号

.. method:: HostAddress serverAddress()

    获取服务器绑定的ip地址

.. method:: virtual bool serverBind()

    绑定服务器到指定地址和端口，默认实现：设置 SO_REUSEADDR 选项（若允许复用地址），调用 Socket::bind() 完成系统调用。

.. method:: virtual bool serverActivate()

    将套接字置为监听状态,默认实现：调用 Socket::listen()，设置最大连接队列长度。

.. method:: virtual QSharedPointer<SocketLike> prepareRequest(QSharedPointer<SocketLike> request);

    预处理请求（如SSL握手）。

.. method:: virtual bool verifyRequest(QSharedPointer<SocketLike> request);

    验证请求是否合法（如IP黑名单），默认实现：直接返回 true，接受所有连接。

2.4.2 WithSsl 
++++++++++++++
通过模板组合，为任意流式服务器无缝添加 SSL/TLS 加密功能。

.. method:: WithSsl(const HostAddress &serverAddress, quint16 serverPort, const SslConfiguration &configuration);
    
    初始化 SSL 服务器，继承自 ServerType，还有几个其他类似方法

    .. code-block:: c++

        WithSsl(const HostAddress &serverAddress, quint16 serverPort);
        WithSsl(quint16 serverPort);
        WithSsl(quint16 serverPort, const SslConfiguration &configuration);
    
.. method:: void setSslConfiguration(const SslConfiguration &configuration);

    动态设置SSL配置。

.. method:: SslConfiguration sslConfiguration() const;

    获取SSL配置。

.. method:: void setSslHandshakeTimeout(float sslHandshakeTimeout)

    控制SSL握手阶段的时间，防止客户端恶意占用

.. method:: float sslHandshakeTimeout()

    获取当前设置SSL握手的超时时长

.. method:: virtual bool isSecure()

    标识服务器使用加密协议，供外部代码检查。

.. method:: prepareRequest()

    将原始 TCP 连接升级为 SSL 连接。

2.4.3 BaseRequestHandler
+++++++++++++++++++++++++
请求处理逻辑的基类，用户需继承并实现具体逻辑。

.. method:: void run()

    请求处理的主流程控制器，确保 setup → handle → finish 顺序执行。

.. method:: void setup()

    初始化请求处理环境（如验证权限、加载配置）。

.. method:: void handle()

    实现核心业务逻辑（如读取请求、处理数据、返回响应）。

.. method:: void finish()

    清理资源（如关闭连接、记录日志、释放内存），即使业务逻辑失败，finish() 也应确保资源释放。

.. method:: void userData()

    安全获取服务器关联的自定义数据（如数据库连接池、配置对象）。

2.4.4 Socks5RequestHandler
+++++++++++++++++++++++++++
``Socks5RequestHandler`` 是 SOCKS5 代理协议的具体实现，继承自 ``BaseRequestHandler``，用于处理客户端通过 SOCKS5 代理发起的连接请求。其核心功能包括协议握手、目标地址解析、连接建立和数据转发。

.. method:: virtual void handle()

    处理客户端 SOCKS5 请求的主入口。 

.. method:: bool handshake()

    处理 SOCKS5 握手与认证协商,返回值：true 表示握手成功，false 表示失败

.. method:: bool parseAddress(QString *hostName, HostAddress *addr, quint16 *port)

    解析客户端请求中的目标地址和端口。

.. method:: virtual QSharedPointer<SocketLike> makeConnection(const QString &hostName, const HostAddress &hostAddress,quint16 port, HostAddress *forwardAddress)

    建立到目标服务器的连接。hostName：目标域名(如 ATYP=0x03),hostAddress：目标 IP 地址(如 ATYP=0x01 或 0x04),port：目标端口,forwardAddress：输出参数，记录实际连接的服务器地址。

.. method:: bool sendConnectReply(const HostAddress &hostAddress, quint16 port)

    向客户端发送连接成功响应。

.. method:: bool sendFailedReply()

    发送连接失败响应。

.. method:: virtual void exchange(QSharedPointer<SocketLike> request, QSharedPointer<SocketLike> forward)

    在客户端和目标服务器之间双向转发数据。

.. method:: doConnect()

    供子类扩展连接成功的行为。

.. method:: doFailed()

    供子类扩展连接失败时的行为。

.. method:: virtual void logProxy(const QString &hostName, const HostAddress &hostAddress, quint16 port,const HostAddress &forwardAddress, bool success)

    记录代理请求的详细日志。 

2.4.5 TcpServer
++++++++++++++++
封装 TCP 服务器的创建、绑定、监听,通过模板参数 RequestHandler 实现业务逻辑解耦,基于协程的并发模型,支持高并发连接。

.. method:: TcpServer(const HostAddress &serverAddress, quint16 serverPort);

    初始化TCP服务器，绑定到指定地址和端口，直接调用 ``BaseStreamServer`` 的构造函数，若未指定地址则默认绑定所有网络接口(HostAddress::Any)

.. method:: virtual QSharedPointer<SocketLike> serverCreate();

    创建底层 TCP 服务器套接字。

.. method:: virtual void processRequest(QSharedPointer<SocketLike> request)

    处理单个客户端连接请求。

.. code-block:: c++
    :caption: 示例 : 简单的Tcp服务器
        #include <QCoreApplication>
        #include "qtnetworkng.h"
        using namespace  qtng;
        class EchoHandler : public BaseRequestHandler//需要继承BaseRequestHandle并重写handle方法
        {
        protected:
            void handle()  {
                qDebug()<<"收到消息";
                qint32 size=1024;
                QByteArray data=request->recvall(size);
                qDebug()<<QString(data);
            }
        };
        int main()
        {
            // 创建服务器，监听 8080 端口
            TcpServer<EchoHandler> server(8080);
            // 配置服务器参数
            server.setRequestQueueSize(100); // 设置连接队列长度
            server.setAllowReuseAddress(true); // 允许端口复用
            // 启动服务器（阻塞式运行）
            if (!server.serveForever()) {
                qDebug() << "服务器启动失败!";
                return 1;
            }
            return 0;
        }

2.4.6 KcpServer
++++++++++++++++
详细解释KcpServer 和 KcpServerV2这两个类和各个方法，并详细解释这两个类的实现区别

.. method:: KcpServer(const HostAddress &serverAddress, quint16 serverPort)
    
    初始化KCP服务器，绑定到指定地址和端口，直接调用 ``BaseStreamServer`` 的构造函数，若未指定地址则默认绑定所有网络接口(HostAddress::Any)

.. method:: virtual QSharedPointer<SocketLike> serverCreate()

    调用KcpSocket::createServer(),创建KCP服务器，底层通过KcpSocket类实现。此方法会初始化KCP会话，绑定到指定地址和端口，并设置默认参数（如MTU大小、窗口大小等）。

.. method:: virtual void processRequest(QSharedPointer<SocketLike> request)

    接收客户端连接后，实例化用户定义的RequestHandler，将KCP会话封装为SocketLike对象传递给业务逻辑处理模块。
    
2.4.7 KcpServerV2
++++++++++++++++++
更底层的KCP协议服务器实现，直接操作KCP会话实例。

.. method:: KcpServerV2(const HostAddress &serverAddress, quint16 serverPort)

    初始化KCP服务器，绑定到指定地址和端口，直接调用 ``BaseStreamServer`` 的构造函数，若未指定地址则默认绑定所有网络接口(HostAddress::Any)

.. method:: virtual QSharedPointer<SocketLike> serverCreate()

    调用createKcpServer()函数创建服务器。与KcpServer不同，此处可能直接管理UDP套接字，并通过回调函数处理KCP会话的输入/输出

.. method:: virtual void processRequest(QSharedPointer<SocketLike> request)

    与KcpServer类似，但可能直接操作KCP会话对象（如调用kcp_input()解析数据包、kcp_recv()提取应用层数据）

3. HTTP 客户端
--------------

``HttpSession`` 是支持 HTTP 1.0/1.1 的客户端，具备自动 Cookie 管理和自动重定向功能。核心方法 ``HttpSession::send()`` 用于发送请求并解析响应，同时提供快捷方法如 ``get()``、 ``post()``、 ``head()`` 等实现单行代码发起 HTTP 请求。

该组件支持 SOCKS5 代理（默认未启用），目前暂不支持 HTTP 代理。Cookie 管理通过 ``HttpSession::cookieJar()`` 实现，响应缓存使用 ``HttpSession::cacheManager()``（默认无缓存）。QtNetworkNg 提供内存缓存组件 ``HttpMemoryCacheManager``。

.. code-block:: c++
    :caption: HTTP 请求示例
    
    HttpSession session;
    
    // 使用 send() 方法
    HttpRequest request;
    request.setUrl("https://qtng.org/");
    request.setMethod("GET");
    request.setTimeout(10.0f);
    HttpResponse response = session.send(request);
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();

    // 使用快捷方法
    HttpResponse response = session.get("https://qtng.org/");
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();
    
    QMap<QString, QString> query;
    query.insert("username", "panda");
    query.insert("password", "xoxoxoxox");
    HttpResponse response = session.post("https://qtng.org/login/", query);
    qDebug() << response.statusCode() << request.statusText() << response.isOk() << response.body().size();
    
    // 启用缓存管理
    session.setCacheManager(QSharedPointer<HttpCacheManager>::create());

3.1 HttpSession
^^^^^^^^^^^^^^^

.. method:: HttpResponse send(HttpRequest &request)

    发送 HTTP 请求至服务器并解析响应
    
.. method:: QNetworkCookieJar &cookieJar()

    返回 cookie 管理器
    
    注意：设置方法 ``setCookieJar(...)`` 暂未实现
    
.. method:: QNetworkCookie cookie(const QUrl &url, const QString &name)

    获取指定 URL 的特定 cookie
    
    cookie 始终与 URL 关联，需同时提供 ``url`` 和 ``name`` 参数
    
.. method:: void setMaxConnectionsPerServer(int maxConnectionsPerServer)

    设置单服务器最大连接数（默认10），超过该限制的请求将被阻塞
    
    若 ``maxConnectionsPerServer < 0`` 则禁用限制
    
.. method:: int maxConnectionsPerServer()

    返回当前单服务器最大连接数
    
.. method:: void setDebugLevel(int level)

    调试级别控制：
    ◦ >0：打印请求/响应摘要
    ◦ >1：打印完整内容（可能导致大量输出）
    
.. method:: void disableDebug()

    禁用调试输出
    
.. method:: void setDefaultUserAgent(const QString &userAgent)

    设置默认 User-Agent（默认值为 Firefox 52 Linux 版）
    
.. method:: QString defaultUserAgent() const

    获取默认 User-Agent
    
    单个请求可通过 ``HttpRequest::setUserAgent()`` 覆盖
    
.. method:: HttpVersion defaultVersion() const

    返回默认 HTTP 版本（默认 1.1）
    
.. method:: void setDefaultConnectionTimeout(float timeout)

    设置默认连接超时（单位：秒，默认10秒）
    
    仅影响连接建立阶段
    
.. method:: float defaultConnnectionTimeout() const

    获取默认连接超时
    
.. method:: void setSocks5Proxy(QSharedPointer<Socks5Proxy> proxy)

    设置 SOCKS5 代理
    
.. method:: QSharedPointer<Socks5Proxy> socks5Proxy() const

    获取 SOCKS5 代理
    
.. method:: void setCacheManager(QSharedPointer<HttpCacheManager> cacheManager)

    设置缓存管理器
    
.. method:: QSharedPointer<HttpCacheManager> cacheManager() const

    获取缓存管理器
    
.. method:: HttpResponse get(const QString &url)

    发送 HTTP GET 请求
    
    支持多种参数形式：

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

    使用POST方法向web服务器发送HTTP请求。

    类似的函数有很多：

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

    返回响应 URL。通常与请求 URL 一致，若存在重定向则为最终 URL
    
.. method:: void setUrl(const QUrl &url)

    设置响应 URL（由 ``HttpSession`` 内部调用）
    
.. method:: int statusCode() const

    返回 HTTP 状态码（如 200 成功，404 未找到，500 服务器错误）
    
.. method:: void setStatusCode(int statusCode)

    设置状态码（由 ``HttpSession`` 内部调用）
    
.. method:: QString statusText() const

    返回状态描述文本（如 "OK"、"Not Found"）

.. method:: void setStatusText(const QString &statusText)

    设置状态描述文本（由 ``HttpSession`` 内部调用）
    
.. method:: QList<QNetworkCookie> cookies() const

    返回响应携带的 cookies
    
.. method:: void setCookies(const QList<QNetworkCookie> &cookies)

    设置 cookies（由 ``HttpSession`` 内部调用）
    
.. method:: HttpRequest request() const

    返回关联的请求对象（重定向时为最新请求）
    
.. method:: qint64 elapsed() const

    返回请求总耗时（毫秒），从发起请求到完成解析/出错
    
.. method:: void setElapsed(qint64 elapsed)

    设置耗时（由 ``HttpSession`` 内部调用）
    
.. method:: QList<HttpResponse> history() const

    返回重定向历史记录（若无重定向则为空列表）
    
.. method:: void setHistory(const QList<HttpResponse> &history)

    设置重定向历史（由 ``HttpSession`` 内部调用）
    
.. method:: HttpVersion version() const

    返回 HTTP 版本（当前支持 1.0/1.1）
    
.. method:: void setVersion(HttpVersion version)

    设置 HTTP 版本（由 ``HttpSession`` 内部调用）
    
.. method:: QByteArray body() const

    以字节数组形式返回响应体
    
.. method:: QJsonDocument json();

    将响应体解析为 JSON 文档
    
.. method:: QString text()

    将响应体解码为 UTF-8 字符串
    
.. method:: QString html()

    根据 HTTP 头/HTML 文档检测编码并返回字符串（暂未实现，功能同 text()）
    
.. method:: bool isOk() const

    检测请求是否成功（应首先调用此方法）
    
.. method:: bool hasNetworkError() const

    检测是否发生网络错误
    
.. method:: bool hasHttpError() const

    检测是否发生 HTTP 错误（状态码 >= 400）

.. method:: QSharedPointer<RequestError> error() const

    返回错误详情对象
    
.. method:: void setError(QSharedPointer<RequestError> error)

    设置错误对象（由 ``HttpSession`` 内部调用）

.. method:: QSharedPointer<SocketLike> takeStream(QByteArray *readBytes)

    当启用流式响应时（``HttpRequest::streamResponse(true)``），获取原始连接对象

3.3 HttpRequest
^^^^^^^^^^^^^^^

.. method:: QString method() const

    返回 HTTP 方法（GET/POST 等）
    
.. method:: void setMethod(const QString &method)

    设置 HTTP 方法（支持标准方法及自定义方法）
    
.. method:: QUrl url() const

    返回请求 URL
    
.. method:: void setUrl(const QUrl &url)

    设置请求 URL（QUrl 格式）
    
.. method:: void setUrl(const QString &url)

    设置请求 URL（字符串格式）
    
.. method:: QUrlQuery query() const

    返回 URL 查询参数
    
.. method:: void setQuery(const QMap<QString, QString> &query)

    通过 QMap 设置查询参数
    
.. method:: void setQuery(const QUrlQuery &query)

    通过 QUrlQuery 设置查询参数
    
.. method:: QList<QNetworkCookie> cookies() const

    返回请求携带的 cookies
    
.. method:: void setCookies(const QList<QNetworkCookie> &cookies)

    设置请求 cookies
    
.. method:: QByteArray body() const

    返回请求体数据

    .. method:: void setBody(const QByteArray &body)

    设置请求的正文。
    
    包含多个重载函数：
    
    .. code-block:: c++
        
        void setBody(const FormData &formData);
        void setBody(const QJsonDocument &json);
        void setBody(const QJsonObject &json);
        void setBody(const QJsonArray &json);
        void setBody(const QMap<QString, QString> form);
        void setBody(const QUrlQuery &form);

.. method:: QString userAgent() const

    返回请求的用户代理字符串。
    
.. method:: void setUserAgent(const QString &userAgent)

    设置请求的用户代理字符串。
    
.. method:: int maxBodySize() const

    返回响应的最大正文大小。
    
    注意：此限制应用于响应而非请求。若服务器返回超过此大小的响应，``HttpSession`` 将报告 ``UnrewindableBodyError`` 错误。
    
.. method:: void setMaxBodySize(int maxBodySize)

    设置响应的最大正文大小。
    
    注意：请参考 ``maxBodySize()``。
    
.. method:: int maxRedirects() const

    返回允许的最大重定向次数。设为0将禁用HTTP重定向。
    
    注意：超出此限制时，``HttpSession`` 将报告 ``TooManyRedirects`` 错误。
    
.. method:: void setMaxRedirects(int maxRedirects)

    设置允许的最大重定向次数。
    
    注意：请参考 ``maxRedirects()``。
    
.. method:: HttpVersion version() const

    返回请求的HTTP版本。默认为 ``Unkown``，表示使用 ``HttpSession::defaultVersion()``。
    
    注意：``HttpSession::defaultVersion()`` 默认使用 HTTP 1.1
    
.. method:: void setVersion(HttpVersion version)

    设置请求的HTTP版本。 
    
    注意：请参考 ``version()``。
    
.. method:: bool streamResponse() const

    若为true，表示返回的 ``HttpResponse`` 未读取HTTP内容。
    
    注意：请参考 ``HttpResponse::takeStream()``。
    
.. method:: void setStreamResponse(bool streamResponse)

    设为true以使 ``HttpSession`` 返回未读取HTTP内容的 ``HttpResponse``。
    
    注意：请参考 ``HttpResponse::takeStream()``。
    
.. method:: float tiemout() const

    返回连接超时时间（单位：秒）。
    
    注意：此限制仅作用于连接阶段。可使用 ``qtng::Timeout`` 管理整个请求的超时。
    
.. method:: void setTimeout(float timeout);

    设置连接超时时间。
    
    注意：请参考 ``timeout()``。


3.4 FormData
^^^^^^^^^^^^

``FormData`` 是用于POST的HTTP表单，用于文件上传。

注意：请参考 ``void HttpRequest::setBody(const FormData &formData)``。

.. method:: void addFile(const QString &name, const QString &filename, const QByteArray &data, const QString &contentType = QString())
    
    向表单的 ``name`` 字段添加文件。
    
.. method:: void addQuery(const QString &key, const QString &value)

    设置表单 ``name`` 字段的值为 ``value``。

3.4 HTTP errors
^^^^^^^^^^^^^^^

使用 ``HttpResponse`` 前应检查 ``HttpResonse::isOk()``。若返回false，则响应异常。此时 ``HttpResponse::error()`` 返回以下类型实例：

* RequestError

    所有错误均为请求错误。

* HTTPError

    服务器返回HTTP错误，错误码为 ``HTTPError::statusCode``。

* ConnectionError

    读写数据时连接中断。

* ProxyError

    无法通过代理连接服务器。

* SSLError

    SSL连接失败（握手错误）。

* RequestTimeout

    读写数据超时。

    ``RequestTimeout`` 同样属于 ``ConnectionError``。

* ConnectTimeout

    连接服务器超时。

    ``ConnectTimeout`` 同时属于 ``ConnectionError`` 和 ``RequestTimeout``。

* ReadTimeout

    读取超时。

    ``ReadTimeout`` 同样属于 ``RequestTimeout``。

* URLRequired

    请求中缺少URL。

* TooManyRedirects

    服务器返回过多重定向响应。

* MissingSchema

    请求URL缺少协议头。

    注意：``HttpSession`` 仅支持 ``http`` 和 ``https``。

* InvalidScheme

    请求URL包含不支持的协议（非 ``http``/``https``）。

* UnsupportedVersion

    不支持的HTTP版本。

    注意：``HttpSession`` 仅支持 HTTP 1.0 和 1.1。

* InvalidURL

    请求的URL无效。

* InvalidHeader

    服务器返回无效标头。

* ChunkedEncodingError

    服务器返回的分块编码正文错误。

* ContentDecodingError

    无法解码响应正文。

* StreamConsumedError

    读取正文时流已被消耗。

* UnrewindableBodyError

    正文过大无法回卷。

4. Http 服务器
--------------

4.1 Basic Http Server
^^^^^^^^^^^^^^^^^^^^^

4.1.1 BaseHttpRequestHandler
++++++++++++++++++++++++++++++
处理 HTTP 请求的基础类，提供 HTTP 协议解析、响应生成、错误处理等核心功能。

.. method:: BaseHttpRequestHandler()

    初始化默认参数，HTTP 版本默认为 Http1_1，请求超时时间 requestTimeout 默认 1 小时，最大请求体大小 maxBodySize 默认 32MB，连接状态 closeConnection 初始为 Maybe

.. method:: virtual void handle()

    循环处理请求，直到 closeConnection 标记为 Yes，调用 handleOneRequest() 处理单个请求

.. method:: virtual void handleOneRequest()

    设置超时限制（Timeout timeout(requestTimeout);）,调用 parseRequest() 解析请求头,调用 doMethod() 分发到具体 HTTP 方法处理器

.. method:: virtual bool parseRequest()

    解析请求行（如 GET /path HTTP/1.1）,提取 method、path、version,解析请求头并存储到 headers,处理 Connection 头决定是否保持连接,返回值: true 表示解析成功，false 表示失败（自动发送 400 错误）

.. method:: void doMethod

    http方法分发，所有方法默认返回 501 Not implemented，以下方法都需要子类进行重写具体实现

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

    生成标准错误页面（HTML 格式）,发送错误响应头（状态码、Content-Type 等）,记录错误日志（logError()）

.. method:: void sendCommandLine(HttpStatus status, const QString &shortMessage)

    发送状态行（如 HTTP/1.1 200 OK）

.. method:: void sendHeader(const QByteArray &name, const QByteArray &value)

    添加响应头（自动处理 Connection 逻辑）

.. method:: void sendHeader(KnownHeader name, const QByteArray &value)

    同sendHeader功能

.. method:: bool endHeader()

    结束头部并发送 \r\n，返回 true 表示成功

.. method:: QSharedPointer<FileLike> bodyAsFile(bool processEncoding = true)

    根据 Content-Length 或 Transfer-Encoding 读取请求体,自动处理 GZIP/DEFLATE 解压缩（需启用 QTNG_HAVE_ZLIB）,支持分块传输（Chunked Encoding,返回值: 返回可读的 FileLike 对象，包含请求体内容。

.. method:: bool switchToWebSocket()

    验证 Upgrade: websocket 和 Sec-WebSocket-Key,计算并返回 Sec-WebSocket-Accept,标记连接升级为 WebSocket

.. method:: virtual void logRequest(HttpStatus status, int bodySize);

    打印客户端地址、请求方法、状态码和响应体大小

.. method:: virtual void logError(HttpStatus status, const QString &shortMessage, const QString &longMessage);

    记录错误状态和消息

4.1.2 StaticHttpRequestHandler
+++++++++++++++++++++++++++++++
继承 ``BaseHttpRequestHandler``，处理静态资源请求，支持文件传输、目录列表、自动索引文件检测等功能,内置路径遍历防护、MIME类型自动识别、XSS防护

.. method:: QSharedPointer<FileLike> serveStaticFiles(const QDir &dir, const QString &subPath)

    根据给定的目录和子路径，返回对应的文件内容或目录列表。 

.. method:: QSharedPointer<FileLike> listDirectory(const QDir &dir, const QString &displayDir)

    生成目录列表的HTML页面。遍历目录中的文件和子目录，生成带有链接的HTML列表。

.. method:: QFileInfo getIndexFile(const QDir &dir)

    检查目录中是否存在`index.html`或`index.htm`，如果存在则返回该文件的信息，否则返回空,这决定了当访问目录时是否显示默认索引文件。

.. method:: virtual bool loadMissingFile(const QFileInfo &fileInfo);

    默认返回false，子类可以重写这个方法，尝试生成或获取缺失的文件。

4.1.3 SimpleHttpRequestHandler
+++++++++++++++++++++++++++++++
继承 ``SimpleHttpRequestHandler``, 预配置的静态文件服务器，提供开箱即用的基本HTTP文件服务功能

.. method:: void setRootDir(const QDir &rootDir)

    设置允许修改的目录,应确保运行进程对目标目录有读取权限,建议在服务器启动前设置，避免运行时修改导致竞态条件

.. method:: virtual void doGET() override;

    响应Get请求，调用父类的serveStaticFiles方法，进行文件处理

.. method:: virtual void doHEAD() override;

    响应HEAD请求，调用父类的serveStaticFiles方法，进行文件处理

4.1.4 BaseHttpProxyRequestHandler

    实现 HTTP 代理的核心逻辑，支持正向代理和隧道代理（如 HTTPS CONNECT 方法）

.. method:: virtual void logRequest(qtng::HttpStatus status, int bodySize)

    用于记录请求日志,这里是空实现，需要子类进行具体实现

.. method:: virtual void logError(qtng::HttpStatus status, const QString &shortMessage, const QString &longMessage)

    用于记录错误日志,这里是空实现，需要子类进行具体实现

.. method:: virtual void logProxy(const QString &remoteHostName, quint16 remotePort, const HostAddress &forwardAddress,bool success)

    提供代理专用日志接口 logProxy(),默认关闭常规请求日志（避免重复记录）

.. method:: virtual void doMethod()

    HTTP 请求分发入口，根据请求方法决定处理逻辑。检查 method 是否为 CONNECT,其他方法（GET/POST等）走普通代理流程

.. method:: virtual void doCONNECT()

    处理 CONNECT 隧道请求，建立客户端与目标服务器的双向通道。

.. method:: virtual void doProxy()

    处理普通HTTP代理请求，转发客户端请求到目标服务器并返回响应。

.. method:: virtual QSharedPointer<SocketLike> makeConnection(const QString &remoteHostName, quint16 remotePort,HostAddress *forwardAddress)

    负责根据传入的remoteHostName（目标主机名）和remotePort（目标端口），创建并初始化一个到目标服务器的Socket连接。此连接将用于后续的HTTP请求转发或HTTPS隧道代理（如CONNECT方法）。

4.2 Application Server
^^^^^^^^^^^^^^^^^^^^^^^
SimpleHttpServer : public TcpServer<SimpleHttpRequestHandler>
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
暂无具体实现

SimpleHttpsServer : public SslServer<SimpleHttpRequestHandler>
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
暂无具体实现

5. 密码学
---------------

5.1 密码哈希表
^^^^^^^^^^^^^^^^

5.2 对称加密和解密
^^^^^^^^^^^^^^^^^^^^

5.3 公钥算法
^^^^^^^^^^^^^^

5.4 证书和证书请求
^^^^^^^^^^^^^^^^^^^

5.5 密钥推导函数
^^^^^^^^^^^^^^^^^

5.6 TLS密码套件
^^^^^^^^^^^^^^^^^

6. 配置和构建
--------------

6.1 使用libev代替Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

6.2 禁用SSL支持
^^^^^^^^^^^^^^^^^^