#include "../include/coroutine_utils.h"
#include "../include/eventloop.h"

QTNETWORKNG_NAMESPACE_BEGIN

void LambdaFunctor::operator ()()
{
    callback();
}


class MarkDoneFunctor: public Functor
{
public:
    MarkDoneFunctor(const QSharedPointer<Event> &done)
        :done(done) {}
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


void NewThreadCoroutine::run()
{
    callInThread(func);
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


bool CoroutineGroup::kill(const QString &name, bool join)
{
    QSharedPointer<Coroutine> found = get(name);
    if(!found.isNull()) {
        if(found.data() == Coroutine::current()) {
//            qWarning("killing current coroutine?");
        } else {
            found->kill();
            if(join) {
                bool success = found->join();
                coroutines.removeOne(found);
                return success;
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
    for (QSharedPointer<Coroutine> coroutine: copy) {
        if (coroutine.data() == Coroutine::current()) {
//            qWarning() << "will not kill current coroutine while killall() is called:" << BaseCoroutine::current();
            continue;
        }
        coroutine->kill();
        done = true;
    }

    if (join) {
        copy = coroutines;
        for (QSharedPointer<Coroutine> coroutine: copy) {
            if (coroutine.data() == Coroutine::current()) {
//                qWarning("will not join current coroutine while killall() is called.");
                continue;
            }
            coroutines.removeOne(coroutine);
            coroutine->join();
        }
    }
    return done;
}


bool CoroutineGroup::joinall()
{
    bool hasCoroutines = !coroutines.isEmpty();
    QList<QSharedPointer<Coroutine>> copy = coroutines;
    for (QSharedPointer<Coroutine> coroutine: copy) {
        if (coroutine == Coroutine::current()) {
//            qDebug("will not kill current coroutine while joinall() is called.");
            continue;
        }
        coroutines.removeOne(coroutine);
        coroutine->join();
    }
    return hasCoroutines;
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


void ThreadPoolWorkThread::kill()
{
    mutex.lock();
    queue.clear();
    hasWork.wakeAll();
    mutex.unlock();
    wait();
}


void ThreadPoolWorkThread::run()
{
    while (true) {
        mutex.lock();
        if (queue.isEmpty()) {
            hasWork.wait(&mutex);
            if (queue.isEmpty()) {
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
    :operations(new CoroutineGroup())
{
    if (threads <= 0) {
        semaphore.reset(new Semaphore(QThread::idealThreadCount()));
    } else {
        semaphore.reset(new Semaphore(threads));
    }
}


ThreadPool::~ThreadPool()
{
    operations->killall();
    for (QSharedPointer<ThreadPoolWorkThread> thread: threads) {
        thread->kill();
    }
    delete operations;
}


QTNETWORKNG_NAMESPACE_END
