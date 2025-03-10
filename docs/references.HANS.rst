QtNetworkNg 参考文档
============================

1. 使用协程
-----------------

1.1 基础与示例
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

协程是轻量级线程。在其他编程语言中，也被称为*fiber*、*goroutine*、*greenlet*等。协程拥有独立的栈空间，可以手动切换（yield）到其他协程。

.. code-block:: c++
    :caption: 示例1: 两个BaseCoroutine之间的切换

    // 警告：yield() 很少直接使用，此示例仅用于演示协程切换能力
    #include <qtnetworkng/qtnetworkng.h>
    #include <QCoreApplication>
    
    using namespace qtng;
    
    class MyCoroutine: public BaseCoroutine {
    public:
        MyCoroutine()
        :BaseCoroutine(nullptr) 
        {
            // 保存当前协程以便切换回来
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
    
    int main(int argc, char ​**argv) {
        QCoreApplication app(argc, argv);
        // 创建新协程时，主线程会隐式转换为主协程
        MyCoroutine m;
        qDebug() << "主协程在这里";
        // 切换到新协程，yield() 在切换回来后返回
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

``BaseCoroutine::raise()``与``BaseCoroutine::yield()``类似，但会向目标协程发送``CoroutineException``异常。

实际开发中更常用的是``Coroutine::start()``和``Coroutine::kill()``。QtNetworkNg 将协程功能分为``BaseCoroutine``和``Coroutine``两个类：

- ``BaseCoroutine``：提供基础切换功能
- ``Coroutine``：通过事件循环协程实现调度

示例展示两个协程交替执行：

.. code-block:: c++
    :caption: 示例2: 两个Coroutine交替运行
    
    #include "qtnetworkng/qtnetworkng.h"
    
    using namespace qtng;
    
    struct MyCoroutine: public Coroutine {
        MyCoroutine(const QString &name)
            : name(name) {}
        void run() override {
            for (int i = 0; i < 3; ++i) {
                qDebug() << name << i;
                msleep(100);  # 切换至事件循环协程，100ms后返回
            }
        }
        QString name;
    };
    
    int main(int argc, char ​**argv) {
        MyCoroutine coroutine1("coroutine1");
        MyCoroutine coroutine2("coroutine2");
        coroutine1.start();
        coroutine2.start();
        coroutine1.join();
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
^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

`Event`（事件信号量）是用于通知等待协程特定条件已触发的同步机制。

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

1.5.2 Event
+++++++++++

`Event`（事件信号量）是用于通知等待协程特定条件已触发的同步机制。

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

    获取当前等待此事件的协程数量。

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

待编写。

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

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Name                               | Description                                                                                                                          |
+====================================+======================================================================================================================================+
| ``BroadcastSocketOption``          | UDP套接字发送广播数据报                                                                                                              |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``AddressReusable``                | 允许bind()调用重用本地地址                                                                                                            |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``ReceiveOutOfBandData``           | 启用时将带外数据直接放入接收数据流                                                                                                    |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``ReceivePacketInformation``       | 保留选项，暂不支持                                                                                                                   |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``ReceiveHopLimit``                | 保留选项，暂不支持                                                                                                                   |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``LowDelayOption``                 | 禁用Nagle算法                                                                                                                        |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``KeepAliveOption``                | 在面向连接的套接字上启用保活报文发送                                                                                                  |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``MulticastTtlOption``             | 设置/读取组播报文的生存时间(TTL)                                                                                                      |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``MulticastLoopbackOption``        | 控制是否回环发送的组播报文                                                                                                            |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``TypeOfServiceOption``            | 设置/读取IP报文的服务类型字段(TOS)                                                                                                    |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``SendBufferSizeSocketOption``     | 设置/获取发送缓冲区最大字节数                                                                                                         |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``ReceiveBufferSizeSocketOption``  | 设置/获取接收缓冲区最大字节数                                                                                                         |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``MaxStreamsSocketOption``         | 保留选项，暂不支持STCP协议                                                                                                            |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``NonBlockingSocketOption``        | 保留选项，Socket内部要求非阻塞模式                                                                                                    |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| ``BindExclusively``                | 保留选项，暂不支持                                                                                                                   |
+------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+

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
^^^^^^^^^
.. method:: SocketType type() const

    返回套接字类型(TCP/UDP)
    
.. method:: SocketState state() const

    返回当前状态
    
.. method:: NetworkLayerProtocol protocol() const

    返回网络层协议
    
DNS相关
^^^^^^
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

    +----------------------+--------------------------------------------------------------------------------------+
    | PeerVerifyMode       | 描述                                                                                 |
    +======================+======================================================================================+
    | ``VerifyNone``       | 不要求对端提供证书，连接仍加密但身份验证关闭                                          |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``QueryPeer``        | 请求对端证书但不强制验证（服务端默认模式）                                            |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``VerifyPeer``       | 强制验证对端证书有效性                                                                |
    +----------------------+--------------------------------------------------------------------------------------+
    | ``AutoVerifyPeer``   | 自动模式：服务端用QueryPeer，客户端用VerifyPeer                                       |
    +----------------------+--------------------------------------------------------------------------------------+

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

还没有实现。

3. HTTP 客户端
--------------

``HttpSession`` 是支持 HTTP 1.0/1.1 的客户端，具备自动 Cookie 管理和自动重定向功能。核心方法 ``HttpSession::send()`` 用于发送请求并解析响应，同时提供快捷方法如 ``get()``、``post()``、``head()`` 等实现单行代码发起 HTTP 请求。

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

``HttpRequest``提供了许多函数，用于对web服务器的请求进行细粒度控制。最常用的功能是“setMethod () ' ', ' ' setUrl () ' ', ' ' setBody () ' ', ' ' setTimeout() ' '。

``HttpResponse``提供了解析HTTP响应的函数。如果发生了一些错误，例如连接超时、HTTP 500错误等，`HttpResonse::isOk()`将返回false。所以，在使用``HttpResonse``之前一定要检查它。错误的详细信息是``HttpResonse::error()``。

有一个特殊的函数``HttpRequest::setStreamResponse()``，它表明``HttpResponse``不解析响应体。然后，你可以使用``HttpResponse::takeStream()``将HTTP连接作为普通套接字。

好的，我现在需要处理用户提供的关于QtNetworkNg的HttpSession类的文档翻译任务。用户的要求是将英文的rst格式文档准确翻译成中文，保持原有格式和符号不变，不翻译专有名词，如类名、方法名等。

首先，我需要通读整个提供的文档部分，理解每个方法和参数的含义，确保在翻译时不会改变技术细节。用户已经提供了部分翻译示例，我需要遵循相同的风格和术语。例如，“HttpSession”应保留不翻译，方法名如“send()”或“get()”也要保持原样。

接下来，注意到用户特别强调不要改动任何符号，比如代码块中的星号、括号、引号等。因此，在翻译过程中，必须仔细检查格式，确保所有代码示例、表格结构、链接标记等都保持原样。例如，表格中的“VerifyNone”、“QueryPeer”等应保留英文，同时翻译其后的描述内容。

在处理每个方法时，要确保参数和返回值的描述准确无误。例如，“setMaxConnectionsPerServer(int maxConnectionsPerServer)”中的参数名和类型不应翻译，但说明部分需要转化为通顺的中文。同时，注意技术术语的一致性，比如“cookie”、“timeout”、“proxy”等在中文技术文档中通常保留英文，但根据用户要求可能需要调整，但用户示例显示这些术语被翻译了，所以需要统一。

对于重复出现的部分，例如多个重载的“get()”、“post()”等方法，要保持结构一致，使用相同的格式和术语。用户提供的示例中，这些方法用代码块列出，翻译时应保持代码块的格式，仅翻译参数说明部分。

还需要注意用户之前翻译中的一些细节，比如“HttpResponse::isOk()”翻译为“检测请求是否成功”，而错误处理部分要明确说明如何获取错误信息。同时，用户提到的一些注意事项，如“setCookieJar()暂未实现”，需要准确传达。

在翻译过程中，可能会遇到一些技术难点，比如某些术语在中文中没有直接对应的词汇，这时需要参考已有的技术文档或通用译法，确保术语的准确性和一致性。例如，“SOCKS5 proxy”通常译为“SOCKS5代理”，而“cache manager”译为“缓存管理器”。

此外，要确保整个文档的结构和层次清晰，使用适当的标题和子标题，保持与原文相同的章节编号和格式。例如，“3.1 HttpSession”应保持不变，下面的方法列表使用正确的rst语法，如“.. method::”和代码块标记。

最后，完成翻译后，需要通读检查，确保没有遗漏任何部分，格式正确，术语一致，语句通顺。特别是用户强调的不要改动任何符号，需仔细核对代码块、表格、链接等部分，确保与原文档完全一致，仅语言转换为中文。

总结来说，这个过程需要细致的技术理解、严格遵循格式要求、准确的术语翻译，以及多次校对确保质量。保持与用户提供的示例一致，同时处理大量重复和结构化的内容，是完成此任务的关键。




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

4.2 Application Server
^^^^^^^^^^^^^^^^^^^^^^^

5. 密码学
---------------

5.1 密码哈希表
^^^^^^^^^^^^^^^^^^^^^^

5.2 对称加密和解密
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.3 公钥算法
^^^^^^^^^^^^^^^^^^^^^^^^

5.4 证书和证书请求
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.5 密钥推导函数
^^^^^^^^^^^^^^^^^^^^^^^^^^^

5.6 TLS密码套件
^^^^^^^^^^^^^^^^^^^^

6. 配置和构建
--------------------------

6.1 使用libev代替Qt Eventloop
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

6.2 禁用SSL支持
^^^^^^^^^^^^^^^^^^^^^^^
```