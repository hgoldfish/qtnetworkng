#include <QtCore/qprocess.h>
#include <QtCore/qscopeguard.h>
#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <sys/wait.h>
#endif

#include "../include/coroutine_utils.h"
#include "../include/eventloop.h"
#include "debugger.h"

QTNG_LOGGER("qtng.coroutine");

QTNETWORKNG_NAMESPACE_BEGIN

bool LambdaFunctor::operator()()
{
    callback();
    return true;
}

class MarkDoneFunctor : public Functor
{
public:
    MarkDoneFunctor(const QSharedPointer<Event> &done)
        : done(done)
    {
    }
    virtual bool operator()() override;
    QSharedPointer<Event> done;
};

bool MarkDoneFunctor::operator()()
{
    done->set();
    return true;
}

DeferCallThread::DeferCallThread(std::function<void()> makeResult, QSharedPointer<Event> done,
                                 EventLoopCoroutine *eventloop)
    : makeResult(makeResult)
    , done(done)
    , eventloop(eventloop)
{
}

void DeferCallThread::run()
{
    auto clean = qScopeGuard([this] {
        if (eventloop.isNull()) {
            return;
        }
        eventloop->callLaterThreadSafe(0, new MarkDoneFunctor(done));
        eventloop->callLaterThreadSafe(100, new LambdaFunctor([this] {
            this->wait();
            delete this;
        }));
    });
    makeResult();
}

class CoroutineThreadPrivate : public BaseCoroutine
{
public:
    CoroutineThreadPrivate(quint32 capacity)
        : BaseCoroutine(nullptr)
        , tasks(capacity)
    {
    }
    virtual void run() override;
public:
    ThreadQueue<std::function<void()>> tasks;
};

void CoroutineThreadPrivate::run()
{
    CoroutineGroup operations;
    while (true) {
        std::function<void()> f = tasks.get();
        if (!f) {
            return;
        }
        operations.spawn(f);
    }
}

CoroutineThread::CoroutineThread(quint32 capacity)
    : dd_ptr(new CoroutineThreadPrivate(capacity))
{
}
CoroutineThread::~CoroutineThread()
{
    delete dd_ptr;
}
void CoroutineThread::run()
{
    currentLoop()->getOrCreate()->runUntil(dd_ptr);
}
void CoroutineThread::apply(const std::function<void()> &f)
{
    dd_ptr->tasks.put(f);
}

bool waitThread(QThread *thread)
{
    if (!thread) {
        return false;
    }
    if (thread->isFinished()) {
        return true;
    }
    QSharedPointer<ThreadEvent> event(new ThreadEvent());
    QMetaObject::Connection connection1 = QObject::connect(thread, &QThread::finished, [event] { event->set(); });
    QMetaObject::Connection connection2 = QObject::connect(thread, &QThread::destroyed, [event] { event->set(); });
    try {
        bool result = event->tryWait();
        QObject::disconnect(connection1);
        QObject::disconnect(connection2);
        return result;
    } catch (...) {
        QObject::disconnect(connection1);
        QObject::disconnect(connection2);
        throw;
    }
}

bool waitProcess(QProcess *process)
{
    if (!process) {
        return false;
    }

    if (!EventLoopCoroutine::get()->isQt()) {
        // fix a bug that the state of QProcesses is never changed if the qt eventloop is not run.

#ifdef Q_OS_UNIX
        int pid = process->processId();
#else
        HANDLE pid = process->pid() ? process->pid()->hProcess : NULL;
        if (!pid) {
            return false;
        }
#endif
        bool ok = callInThread<bool>([pid] {
#ifdef Q_OS_UNIX
            int wstatus = 0;
            return waitpid(pid, &wstatus, 0) == pid;
#else
            return WaitForSingleObject(pid, -1) == WAIT_OBJECT_0;
#endif
        });
        // qt will print warning message: Destroyed while process ("/path/..") is still running.
//        if (ok) {
//            process->waitForFinished(0);
//        }
        return ok;
    }

    if (process->state() == QProcess::NotRunning) {
        return true;
    }
    QSharedPointer<Event> event(new Event());
#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)
    QScopedPointer<detail::SetEventHelper> helper(new detail::SetEventHelper(event));
    QMetaObject::Connection connection = QObject::connect(process, SIGNAL(finished(int,QProcess::ExitStatus)),
                                                          helper.data(), SLOT(set()));
#else
    QMetaObject::Connection connection = QObject::connect(process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                     [event](int, QProcess::ExitStatus) { event->set(); });
#endif
    try {
        bool result = event->tryWait();
        QObject::disconnect(connection);
        return result;
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}

CoroutineGroup::CoroutineGroup()
    : QObject()
{
}

CoroutineGroup::~CoroutineGroup()
{
    killall(true);
}

bool CoroutineGroup::add(QSharedPointer<Coroutine> coroutine, const QString &name)
{
    if (!name.isEmpty()) {
        if (!get(name).isNull()) {
            return false;
        }
        coroutine->setObjectName(name);
    }
    QPointer<CoroutineGroup> self(this);
    coroutine->finished.addCallback([self](BaseCoroutine *coroutine) {
        if (self.isNull()) {
            return;
        }
        self->deleteCoroutine(coroutine);
    });
    coroutines.insert(coroutine);
    return true;
}

QSharedPointer<Coroutine> CoroutineGroup::get(const QString &name)
{
    QSetIterator<QSharedPointer<Coroutine>> itor(coroutines);
    while (itor.hasNext()) {
        QSharedPointer<Coroutine> coroutine = itor.next();
        if (coroutine->objectName() == name)
            return coroutine;
    }
    return QSharedPointer<Coroutine>();
}

bool CoroutineGroup::has(const QString &name)
{
    QSetIterator<QSharedPointer<Coroutine>> itor(coroutines);
    while (itor.hasNext()) {
        QSharedPointer<Coroutine> coroutine = itor.next();
        if (coroutine->objectName() == name) {
            return true;
        }
    }
    return false;
}

bool CoroutineGroup::isCurrent(const QString &name)
{
    QSetIterator<QSharedPointer<Coroutine>> itor(coroutines);
    while (itor.hasNext()) {
        QSharedPointer<Coroutine> coroutine = itor.next();
        if (coroutine->objectName() == name && coroutine == Coroutine::current()) {
            return true;
        }
    }
    return false;
}

bool CoroutineGroup::kill(const QString &name, bool join)
{
    QSharedPointer<Coroutine> found = get(name);
    if (!found.isNull()) {
        if (found.data() == Coroutine::current()) {
            qtng_warning << "killing current coroutine?";
        } else {
            if (join) {
                if (found->isRunning()) {
                    found->setPrevious(BaseCoroutine::current());
                    found->raise(new CoroutineExitException());
                } else {
                    found->kill();
                }
            } else {
                found->kill();
            }
            return true;
        }
    }
    return false;
}

bool CoroutineGroup::killall(bool join)
{
    bool done = false;
    QSet<QSharedPointer<Coroutine>> copy = coroutines;
    if (join) {
        BaseCoroutine *current = BaseCoroutine::current();
        for (QSharedPointer<Coroutine> coroutine : copy) {
            if (coroutine.data() == Coroutine::current()) {
                continue;
            }
            if (coroutine->isRunning()) {
                coroutine->setPrevious(current);
                coroutine->raise(new CoroutineExitException());
            } else {
                coroutine->kill();
            }
            done = true;
        }
    } else {
        for (QSharedPointer<Coroutine> coroutine : copy) {
            if (coroutine.data() == Coroutine::current()) {
                continue;
            }
            coroutine->kill();
            done = true;
        }
    }
    return done;
}

bool CoroutineGroup::join(const QString &name)
{
    QSharedPointer<Coroutine> found = get(name);
    if (!found.isNull()) {
        if (found.data() == Coroutine::current()) {
            qtng_warning << "joining current coroutine?";
        } else {
            found->join();
            return true;
        }
    }
    return false;
}

bool CoroutineGroup::joinall()
{
    bool hasCoroutines = !coroutines.isEmpty();
    QSet<QSharedPointer<Coroutine>> copy = coroutines;
    for (QSharedPointer<Coroutine> coroutine : copy) {
        if (coroutine == Coroutine::current()) {
            continue;
        }
        coroutine->join();
    }
    return hasCoroutines;
}

QSharedPointer<Coroutine> CoroutineGroup::any()
{
    QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>> event =
            QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>>::create();

    QList<QPair<QWeakPointer<Coroutine>, int>> toRemove;
    for (QSharedPointer<Coroutine> c : coroutines) {
        QWeakPointer<Coroutine> cw = c.toWeakRef();
        int callbackId = c->finished.addCallback([event, cw](BaseCoroutine *) { event->send(cw.toStrongRef()); });
        toRemove.append(qMakePair(cw, callbackId));
    }
    try {
        QSharedPointer<Coroutine> c = event->tryWait();
        for (const QPair<QWeakPointer<Coroutine>, int> &item : toRemove) {
            QSharedPointer<Coroutine> c = item.first.toStrongRef();
            if (!c.isNull()) {
                c->finished.remove(item.second);
            }
        }
        return c;
    } catch (...) {
        for (const QPair<QWeakPointer<Coroutine>, int> &item : toRemove) {
            QSharedPointer<Coroutine> c = item.first.toStrongRef();
            if (!c.isNull()) {
                c->finished.remove(item.second);
            }
        }
        throw;
    }
}

class DeleteCoroutineFunctor : public Functor
{
public:
    virtual ~DeleteCoroutineFunctor() override;
    virtual bool operator()() override;
    QSharedPointer<BaseCoroutine> coroutine;
};
DeleteCoroutineFunctor::~DeleteCoroutineFunctor() { }
bool DeleteCoroutineFunctor::operator()()
{
    return true;
}

void CoroutineGroup::deleteCoroutine(BaseCoroutine *baseCoroutine)
{
    Coroutine *coroutine = dynamic_cast<Coroutine *>(baseCoroutine);
    Q_ASSERT(coroutine != nullptr);
    QSharedPointer<Coroutine> c = coroutine->sharedFromThis();
    DeleteCoroutineFunctor *callback = new DeleteCoroutineFunctor();
    callback->coroutine = c;
    EventLoopCoroutine::get()->callLater(0, callback);
    coroutines.remove(c);
}

class ThreadPoolWorkItem
{
public:
    ThreadPoolWorkItem()
        : done(new Event())
    {
    }
    std::function<void()> makeResult;
    QSharedPointer<Event> done;
    QPointer<EventLoopCoroutine> eventloop;
};

class ThreadPoolWorkThread : public QThread
{
public:
    ThreadPoolWorkThread();
    void call(std::function<void()> func);
    void kill();
private:
    virtual void run() override;
private:
    QQueue<ThreadPoolWorkItem> queue;
    QMutex mutex;
    QWaitCondition hasWork;
    QAtomicInteger<int> exiting;
};

ThreadPoolWorkThread::ThreadPoolWorkThread()
    : exiting(false)
{
}

void ThreadPoolWorkThread::call(std::function<void()> func)
{
    if (exiting.loadAcquire()) {
        return;
    }
    ThreadPoolWorkItem item;
    item.makeResult = func;
    item.eventloop = EventLoopCoroutine::get();
    mutex.lock();
    queue.enqueue(item);
    hasWork.wakeAll();
    mutex.unlock();
    item.done->tryWait();
}

void ThreadPoolWorkThread::kill()
{
    mutex.lock();
    hasWork.wakeAll();
    exiting.storeRelease(true);
    mutex.unlock();
    wait();
}

void ThreadPoolWorkThread::run()
{
    while (!exiting.loadAcquire()) {
        mutex.lock();
        if (queue.isEmpty()) {
            hasWork.wait(&mutex);
            if (queue.isEmpty() || exiting.loadAcquire()) {
                mutex.unlock();
                return;
            }
        }
        const ThreadPoolWorkItem &item = queue.takeFirst();
        mutex.unlock();
        if (item.eventloop.isNull()) {
            return;
        }
        item.makeResult();
        if (!item.eventloop.isNull()) {
            item.eventloop->callLaterThreadSafe(0, new MarkDoneFunctor(item.done));
        }
    }
}

ThreadPool::ThreadPool(int threads)
{
    if (threads <= 0) {
        semaphore.reset(new Semaphore(QThread::idealThreadCount() * 2 + 1));
    } else {
        semaphore.reset(new Semaphore(threads));
    }
}

ThreadPool::~ThreadPool()
{
    for (QSharedPointer<ThreadPoolWorkThread> thread : threads) {
        thread->kill();
    }
}

void ThreadPool::call(std::function<void()> func)
{
    QSharedPointer<Semaphore> semaphore(this->semaphore);
    ScopedLock<Semaphore> lock(*semaphore);
    if (!lock.isSuccess()) {
        return;
    }
    QSharedPointer<ThreadPoolWorkThread> thread;
    if (threads.isEmpty()) {
        thread.reset(new ThreadPoolWorkThread());
        thread->start(QThread::LowPriority);
    } else {
        thread = threads.takeFirst();
    }
    QPointer<ThreadPool> self(this);
    try {
        thread->call(func);
        if (self) {
            threads.append(thread);
        } else {
            thread->kill();
        }
    } catch (...) {
        if (self) {
            threads.append(thread);
        } else {
            thread->kill();
        }
        throw;
    }
}

QTNETWORKNG_NAMESPACE_END
