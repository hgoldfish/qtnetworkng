#include "../include/coroutine_utils.h"
#include "../include/eventloop.h"
#include "debugger.h"

QTNG_LOGGER("qtng.coroutine");


QTNETWORKNG_NAMESPACE_BEGIN

void LambdaFunctor::operator ()()
{
    callback();
}


class MarkDoneFunctor: public Functor
{
public:
    MarkDoneFunctor(const QSharedPointer<Event> &done)
        : done(done) {}
    virtual void operator ()() override;
    QSharedPointer<Event> done;
};


void MarkDoneFunctor::operator ()()
{
    done->set();
}


DeferCallThread::DeferCallThread(std::function<void()> makeResult, QSharedPointer<Event> done, EventLoopCoroutine *eventloop)
    :makeResult(makeResult), done(done), eventloop(eventloop)
{
}


void DeferCallThread::run()
{
    makeResult();
    if (!eventloop.isNull()) {
        eventloop->callLaterThreadSafe(0, new MarkDoneFunctor(done));
        eventloop->callLaterThreadSafe(100, new DeleteLaterFunctor<DeferCallThread>(this));
    }
}


class CoroutineThreadPrivate: public BaseCoroutine
{
public:
    CoroutineThreadPrivate(quint32 capacity)
        : BaseCoroutine(nullptr), tasks(capacity) {}
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
    : dd_ptr(new CoroutineThreadPrivate(capacity)) {}
CoroutineThread::~CoroutineThread() { delete dd_ptr; }
void CoroutineThread::run() { currentLoop()->getOrCreate()->runUntil(dd_ptr); }
void CoroutineThread::apply(const std::function<void()> &f) { dd_ptr->tasks.put(f); }


bool waitThread(QSharedPointer<QThread> thread)
{
    if (thread.isNull()) {
        return false;
    }
    if (thread->isFinished()) {
        return true;
    }
    QSharedPointer<ThreadEvent> event(new ThreadEvent());
    QObject::connect(thread.data(), &QThread::finished, [event] { event->set(); });
    QObject::connect(thread.data(), &QThread::destroyed, [event] {  event->set(); });
    return event->wait();
}


CoroutineGroup::CoroutineGroup()
    :QObject()
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
    coroutine->finished.addCallback([self] (BaseCoroutine *coroutine) {
        if (self.isNull()) {
            return;
        }
        self->deleteCoroutine(coroutine);
    });
    coroutines.append(coroutine);
    return true;
}


QSharedPointer<Coroutine> CoroutineGroup::get(const QString &name)
{
    QListIterator<QSharedPointer<Coroutine>> itor(coroutines);
    while (itor.hasNext()) {
        QSharedPointer<Coroutine> coroutine = itor.next();
        if (coroutine->objectName() == name)
            return coroutine;
    }
    return QSharedPointer<Coroutine>();
}


bool CoroutineGroup::has(const QString &name)
{
    QListIterator<QSharedPointer<Coroutine>> itor(coroutines);
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
    QListIterator<QSharedPointer<Coroutine>> itor(coroutines);
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
    QList<QSharedPointer<Coroutine>> copy = coroutines;
    if (join) {
        BaseCoroutine *current = BaseCoroutine::current();
        for (QSharedPointer<Coroutine> coroutine: copy) {
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
        for (QSharedPointer<Coroutine> coroutine: copy) {
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
    QList<QSharedPointer<Coroutine>> copy = coroutines;
    for (QSharedPointer<Coroutine> coroutine: copy) {
        if (coroutine == Coroutine::current()) {
            continue;
        }
        coroutines.removeOne(coroutine);
        coroutine->join();
    }
    return hasCoroutines;
}


QSharedPointer<Coroutine> CoroutineGroup::any()
{
    QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>> event
            = QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>>::create();

    QList<QPair<QWeakPointer<Coroutine>, int>> toRemove;
    for (QSharedPointer<Coroutine> c: coroutines) {
        QWeakPointer<Coroutine> cw = c.toWeakRef();
        int callbackId = c->finished.addCallback([event, cw] (BaseCoroutine *) { event->send(cw.toStrongRef()); });
        toRemove.append(qMakePair(cw, callbackId));
    }
    try {
        QSharedPointer<Coroutine> c = event->wait();
        for (const QPair<QWeakPointer<Coroutine>, int> &item: toRemove) {
            QSharedPointer<Coroutine> c = item.first.toStrongRef();
            if (!c.isNull()) {
                c->finished.remove(item.second);
            }
        }
        return c;
    } catch (...) {
        for (const QPair<QWeakPointer<Coroutine>, int> &item: toRemove) {
            QSharedPointer<Coroutine> c = item.first.toStrongRef();
            if (!c.isNull()) {
                c->finished.remove(item.second);
            }
        }
        throw;
    }
}


class DeleteCoroutineFunctor: public Functor
{
public:
    virtual ~DeleteCoroutineFunctor() override;
    virtual void operator()() override;
    QSharedPointer<BaseCoroutine> coroutine;
};
DeleteCoroutineFunctor::~DeleteCoroutineFunctor() {}
void DeleteCoroutineFunctor::operator()() {}


void CoroutineGroup::deleteCoroutine(BaseCoroutine *baseCoroutine)
{
    Coroutine *coroutine = dynamic_cast<Coroutine*>(baseCoroutine);
    Q_ASSERT(coroutine != nullptr);
    for (QList<QSharedPointer<Coroutine>>::iterator itor = coroutines.begin(); itor != coroutines.end(); ++itor) {
        if (itor->data() == coroutine) {
            DeleteCoroutineFunctor *callback = new DeleteCoroutineFunctor();
            callback->coroutine = *itor;
            EventLoopCoroutine::get()->callLater(0, callback);
            coroutines.erase(itor);
            break;
        }
    }
}


class ThreadPoolWorkItem
{
public:
    ThreadPoolWorkItem()
        :done(new Event()) {}
    std::function<void()> makeResult;
    QSharedPointer<Event> done;
    QPointer<EventLoopCoroutine> eventloop;
};


class ThreadPoolWorkThread: public QThread
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
    item.done->wait();
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
    for (QSharedPointer<ThreadPoolWorkThread> thread: threads) {
        thread->kill();
    }
}


void ThreadPool::call(std::function<void()> func)
{
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
    thread->call(func);
    threads.append(thread);
}


QTNETWORKNG_NAMESPACE_END
