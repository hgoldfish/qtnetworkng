#include <QtCore/qwaitcondition.h>
#include <QtCore/qmutex.h>
#include <QtCore/qpointer.h>
#include <QtCore/qelapsedtimer.h>
#include "../include/private/eventloop_p.h"
#include "../include/locks.h"
#include "debugger.h"

QTNG_LOGGER("qtng.locks");

QTNETWORKNG_NAMESPACE_BEGIN

class SemaphorePrivate
{
public:
    SemaphorePrivate(int value);
    virtual ~SemaphorePrivate();
public:
    bool acquire(QSharedPointer<SemaphorePrivate> self, int value, quint32 msecs);
    void release(QSharedPointer<SemaphorePrivate> self, int value);
    void scheduleDelete(QSharedPointer<SemaphorePrivate> self);
public:
    QList<QPointer<BaseCoroutine>> waiters;
    const int init_value;
    volatile int counter;
    int notified;
};

SemaphorePrivate::SemaphorePrivate(int value)
    : init_value(qMax(1, value))
    , counter(value)
    , notified(0)
{
    if (value < 1) {
        qtng_warning << "Semaphore got init value less than 1:" << value << ", we treat it as 1.";
    }
}

SemaphorePrivate::~SemaphorePrivate()
{
    Q_ASSERT(waiters.isEmpty());
}

bool SemaphorePrivate::acquire(QSharedPointer<SemaphorePrivate> self, int value, quint32 msecs)
{
    if (counter >= value) {
        counter -= value;
        return true;
    }
    if (msecs == 0) {
        return false;
    }
    // UINT_MAX: means wait until success
    int callbackId = 0;
    if (msecs != (UINT_MAX)) {
        callbackId = EventLoopCoroutine::get()->callLater(msecs, new YieldCurrentFunctor());
    }

    Q_ASSERT_X(EventLoopCoroutine::get() != BaseCoroutine::current(), "SemaphorePrivate",
               "coroutine locks should not be called from eventloop coroutine.");
    Q_ASSERT_X(value <= init_value, "SemaphorePrivate", "the value to acquire must not large than init_value.");

    int gotNum = counter;
    int remain = value - counter;
    counter = 0;

    while (remain > 0) {
        waiters.append(BaseCoroutine::current());

        try {
            EventLoopCoroutine::get()->yield();
        } catch (...) {
            // if we caught an exception, the release() must not touch me.
            // the waiter should be remove.
            bool found = waiters.removeOne(BaseCoroutine::current());
            Q_ASSERT(found);
            if (callbackId) {
                EventLoopCoroutine::get()->cancelCall(callbackId);
            }
            release(self, gotNum);
            throw;
        }

        bool found = waiters.removeOne(BaseCoroutine::current());
        if (found) {  // timeout
            release(self, gotNum);  // release what has been acquired
            return false;
        }

        Q_ASSERT_X(notified != 0, "SemaphorePrivate",
                   "if there are something other reason cause yield, it means the acquire action is failed");
        Q_ASSERT(counter > 0);
        if (counter >= remain) {
            counter -= remain;
            break;
        } else {
            gotNum += counter;
            remain -= counter;
            counter = 0;
        }
    }
    if (callbackId) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
    }
    return true;
}

class SemaphoreNotifyWaitersFunctor : public Functor
{
public:
    SemaphoreNotifyWaitersFunctor(QSharedPointer<SemaphorePrivate> sp, bool doDelete)
        : sp(sp)
        , doDelete(doDelete)
    {
    }
    QSharedPointer<SemaphorePrivate> sp;
    bool doDelete;
    virtual bool operator()() override
    {
        while ((doDelete || (sp->notified != 0 && sp->counter > 0)) && !sp->waiters.isEmpty()) {
            QPointer<BaseCoroutine> waiter = sp->waiters.takeFirst();
            if (waiter.isNull()) {
                qtng_debug << "waiter was deleted.";
                continue;
            }
            waiter->yield();
        }
        // do not move this line above the loop, see the Q_ASSERT_X(notified != 0) in SemaphorePrivate::acquire()
        sp->notified = 0;
        return true;
    }
};

void SemaphorePrivate::release(QSharedPointer<SemaphorePrivate> self, int value)
{
    if (value <= 0) {
        return;
    }
    if (counter > INT_MAX - value) {
        counter = INT_MAX;
    } else {
        counter += value;
    }
    counter = qMin(static_cast<int>(counter), init_value);
    if (!notified && !waiters.isEmpty()) {
        notified = EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(self, false));
    }
}

void SemaphorePrivate::scheduleDelete(QSharedPointer<SemaphorePrivate> self)
{
    if (notified) {
        EventLoopCoroutine::get()->cancelCall(notified);
        notified = 0;
    }
    counter = init_value;
    EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(self, true));
}

Semaphore::Semaphore(int value)
    : d(new SemaphorePrivate(value))
{
}

Semaphore::~Semaphore()
{
    d->scheduleDelete(d);
    d.clear();
}

bool Semaphore::acquireMany(int value, quint32 msecs)
{
    if (!d) {
        return false;
    }
    QSharedPointer<SemaphorePrivate> d(this->d);
    if (value > d->init_value) {
        return false;
    }
    return d->acquire(d, value, msecs);
}

bool Semaphore::tryAcquire(quint32 msecs /*= (UINT_MAX)*/)
{
    if (!d) {
        return false;
    }
    QSharedPointer<SemaphorePrivate> d(this->d);
    if (1 > d->init_value) {
        return false;
    }
    return d->acquire(d, 1, msecs);
}

void Semaphore::release(int value)
{
    if (!d) {
        return;
    }
    d->release(d, value);
}

bool Semaphore::isLocked() const
{
    if (!d) {
        return false;
    }
    return d->counter <= 0;
}

bool Semaphore::isUsed() const
{
    if (!d) {
        return false;
    }
    return d->counter < d->init_value;
}

quint32 Semaphore::getting() const
{
    if (!d) {
        return 0;
    }
    return d->waiters.size();
}

Lock::Lock()
    : Semaphore(1)
{
}

struct RLockState
{
    quintptr holder;
    int counter;
};

class RLockPrivate
{
public:
    RLockPrivate(RLock *q);
    ~RLockPrivate();
public:
    bool acquire(quint32 msecs);
    void release();
    RLockState reset();
    void set(const RLockState &state);
private:
    RLock * const q_ptr;
    Lock lock;
    quintptr holder;
    int counter;
    Q_DECLARE_PUBLIC(RLock)
};

RLockPrivate::RLockPrivate(RLock *q)
    : q_ptr(q)
    , holder(0)
    , counter(0)
{
}

RLockPrivate::~RLockPrivate() { }

bool RLockPrivate::acquire(quint32 msecs)
{
    if (holder == BaseCoroutine::current()->id()) {
        counter += 1;
        return true;
    }
    if (lock.tryAcquire(msecs)) {
        counter = 1;
        holder = BaseCoroutine::current()->id();
        return true;
    }
    return false;  // XXX lock is deleted.
}

void RLockPrivate::release()
{
    if (holder != BaseCoroutine::current()->id()) {
        qtng_warning << "do not release other coroutine's rlock.";
        return;
    }
    counter -= 1;
    if (counter == 0) {
        holder = 0;
        lock.release();
    }
}

RLockState RLockPrivate::reset()
{
    RLockState state;
    state.counter = counter;
    counter = 0;
    state.holder = holder;
    holder = 0;
    if (state.counter > 0) {
        lock.release();
    }
    return state;
}

void RLockPrivate::set(const RLockState &state)
{
    counter = state.counter;
    holder = state.holder;
    if (counter > 0) {
        lock.tryAcquire();
    }
}

RLock::RLock()
    : d_ptr(new RLockPrivate(this))
{
}

RLock::~RLock()
{
    delete d_ptr;
}

bool RLock::tryAcquire(quint32 msecs)
{
    Q_D(RLock);
    return d->acquire(msecs);
}

void RLock::release()
{
    Q_D(RLock);
    d->release();
}

bool RLock::isLocked() const
{
    Q_D(const RLock);
    return d->lock.isLocked();
}

bool RLock::isOwned() const
{
    Q_D(const RLock);
    return d->holder == BaseCoroutine::current()->id();
}

class ConditionPrivate
{
public:
    QList<QSharedPointer<Lock>> waiters;
};

Condition::Condition()
    : d_ptr(new ConditionPrivate())
{
}

Condition::~Condition()
{
    notify(d_ptr->waiters.size());
    delete d_ptr;
}

bool Condition::wait(quint32 msecs)
{
    Q_D(Condition);
    QSharedPointer<Lock> waiter(new Lock());
    if (!waiter->tryAcquire(0)) {
        return false;
    }
    d->waiters.append(waiter);

    bool ok = false;
    try {
        ok = waiter->tryAcquire(msecs);
    } catch (...) {
        waiter->release();
        d->waiters.removeOne(waiter);
        throw;
    }

    if (ok) {
        waiter->release();
    }
    d->waiters.removeOne(waiter);
    return ok;
}

void Condition::notify(int value)
{
    Q_D(Condition);
    for (int i = 0; i < value && !d->waiters.isEmpty(); ++i) {
        QSharedPointer<Lock> waiter = d->waiters.takeFirst();
        waiter->release();
    }
}

void Condition::notifyAll()
{
    Q_D(Condition);
    notify(d->waiters.size());
}

quint32 Condition::getting() const
{
    Q_D(const Condition);
    return static_cast<quint32>(d->waiters.size());
}

class EventPrivate
{
public:
    EventPrivate(Event *q);
    ~EventPrivate();
public:
    void set();
    void clear();
    bool wait(quint32 msecs);
private:
    Event * const q_ptr;
    Condition condition;
    volatile bool flag;
    QList<Event *> linkTo;
    QList<Event *> linkFrom;
    Q_DECLARE_PUBLIC(Event)
};

EventPrivate::EventPrivate(Event *q)
    : q_ptr(q)
    , flag(false)
{
}

EventPrivate::~EventPrivate()
{
    if (!flag && condition.getting() > 0) {
        condition.notifyAll();
    }
    for (Event *event : linkFrom) {
        event->d_ptr->linkTo.removeOne(q_ptr);
    }
    for (Event *event : linkTo) {
        event->d_ptr->linkFrom.removeOne(q_ptr);
    }
}

void EventPrivate::set()
{
    if (!flag) {
        flag = true;
        condition.notifyAll();
        for (Event *other : linkTo) {
            other->set();
        }
    }
}

void EventPrivate::clear()
{
    flag = false;
}

bool EventPrivate::wait(quint32 msecs)
{
    if (msecs == 0 || flag) {
        return flag;
    }

    if (msecs == UINT_MAX) {
        do {
            try {
                if (!condition.wait(UINT_MAX)) {
                    return false;
                }
            } catch (...) {
                throw;
            }
        } while (!flag);
    } else {
        QElapsedTimer timer;
        timer.start();

        quint32 elapsed = 0;
        while (true) {
            try {
                if (!condition.wait(msecs - elapsed)) {
                    return false;
                }
            } catch (...) {
                throw;
            }
            if (flag) {
                break;
            }
            elapsed = timer.elapsed();
            if (elapsed >= msecs) {
                return false;
            }
        }
    }
    return flag;
}

Event::Event()
    : d_ptr(new EventPrivate(this))
{
}

Event::~Event()
{
    delete d_ptr;
}

bool Event::tryWait(quint32 msecs)
{
    Q_D(Event);
    return d->wait(msecs);
}

void Event::set()
{
    Q_D(Event);
    d->set();
}

bool Event::isSet() const
{
    Q_D(const Event);
    return d->flag;
}

void Event::clear()
{
    Q_D(Event);
    d->clear();
}

quint32 Event::getting() const
{
    Q_D(const Event);
    return d->condition.getting();
}

void Event::link(Event &other)
{
    Q_D(Event);
    d->linkTo.append(&other);
    other.d_func()->linkFrom.append(this);
}

void Event::unlink(Event &other)
{
    Q_D(Event);
    d->linkTo.removeOne(&other);
    other.d_ptr->linkFrom.removeOne(this);
}

struct Behold
{
    QPointer<EventLoopCoroutine> eventloop;
    QSharedPointer<Condition> condition;
};

class ThreadEventPrivate
{
public:
    ThreadEventPrivate();
    void notify();
    bool wait(quint32 msecs);
    quint32 getting();
    inline void incref();
    inline bool decref();
public:
    QWaitCondition condition;
    QMutex mutex;
    QList<Behold> holds;
    QList<ThreadEvent *> linkTo;
    QList<ThreadEvent *> linkFrom;
    QAtomicInteger<int> flag;
    QAtomicInteger<int> count;  // only for condition
    QAtomicInteger<quint32> ref;
};

class NotifiyCondition : public Functor
{
public:
    NotifiyCondition(QSharedPointer<Condition> condition)
        : condition(condition)
    {
    }
    virtual bool operator()()
    {
        condition->notifyAll();
        return true;
    }
    QSharedPointer<Condition> condition;
};

ThreadEventPrivate::ThreadEventPrivate()
    : flag(false)
    , count(0)
    , ref(1)
{
}

void ThreadEventPrivate::notify()
{
    incref();
    mutex.lock();
    QSharedPointer<EventLoopCoroutine> current = currentLoop()->get();
    QMutableListIterator<Behold> itor(holds);
    // XXX the flag can be false.
    while (itor.hasNext() && ref.loadAcquire() > 1) {
        const Behold &hold = itor.next();
        QSharedPointer<Condition> holdCondition = hold.condition;
        EventLoopCoroutine *holdEventloop = hold.eventloop.data();
        if (holdEventloop) {
            if (holdEventloop == current) {
                holdCondition->notifyAll();
            } else {
                holdEventloop->callLaterThreadSafe(0, new NotifiyCondition(holdCondition));
            }
        } else {
            itor.remove();
        }
    }
    mutex.unlock();
    // XXX the flag can be false.
    if (count.loadAcquire() > 0) {
        condition.wakeAll();
    }
    decref();
}

bool ThreadEventPrivate::wait(quint32 msecs)
{
    bool f = flag.loadAcquire();
    if (msecs == 0 || f) {
        return f;
    }

    QSharedPointer<QElapsedTimer> timer;
    if (msecs != UINT_MAX) {
        timer.reset(new QElapsedTimer());
        timer->start();
    }

    incref();
    mutex.lock();
    EventLoopCoroutine *current = currentLoop()->get().data();
    Q_ASSERT(!f);
    if (!current) {
        if (msecs != UINT_MAX) {
            qtng_warning << "useless arg:msecs when call ThreadEvent::wait";
        }

        ++count;
        while (!(f = flag.loadAcquire()) && ref.loadAcquire() > 1) {
            this->condition.wait(&mutex);
        }
        --count;
        mutex.unlock();
    } else {
        QSharedPointer<Condition> condition;
        // should we use QMap<EventLoopCoroutine *, Hold> to accelerate?
        for (const Behold &hold : holds) {
            if (hold.eventloop.data() == current) {
                condition = hold.condition;
                break;
            }
        }
        if (condition.isNull()) {
            condition.reset(new Condition());
            Behold hold;
            hold.condition = condition;
            hold.eventloop = current;
            holds.append(hold);
        }
        mutex.unlock();
        bool ok = false;

        while (!(f = flag.loadAcquire()) && ref.loadAcquire() > 1) {
            try {
                if (msecs == UINT_MAX) {
                    ok = condition->wait();
                } else {
                    quint32 elapsed = timer->elapsed();
                    if (msecs <= elapsed) {
                        return false;
                    }
                    ok = condition->wait(msecs - elapsed);
                }
            } catch (...) {
                decref();
                throw;
            }
            if (!ok) {
                decref();
                return false;
            }
        }
    }
    decref();
    return f;
}

quint32 ThreadEventPrivate::getting()
{
    incref();
    mutex.lock();
    quint32 count = this->count.loadAcquire();
    for (const Behold &hold : holds) {
        if (!hold.condition.isNull()) {
            count += hold.condition->getting();
        }
    }
    mutex.unlock();
    decref();
    return count;
}

void ThreadEventPrivate::incref()
{
    ref.ref();
}

bool ThreadEventPrivate::decref()
{
    if (!ref.deref()) {
        delete this;
        return false;
    }
    return true;
}

ThreadEvent::ThreadEvent()
    : d(new ThreadEventPrivate())
{
}

ThreadEvent::~ThreadEvent()
{
    if (d->decref()) {
        d->notify();
    }
    d = nullptr;
}

bool ThreadEvent::tryWait(quint32 msecs)
{
    if (d) {
        return d->wait(msecs);
    } else {
        return false;
    }
}

void ThreadEvent::set()
{
    if (!d) {
        return;
    }

    if (d->flag.fetchAndStoreRelease(true)) {
        return;
    }
    d->notify();
}

void ThreadEvent::clear()
{
    if (!d) {
        return;
    }
    d->flag.storeRelease(false);
    // d->flag.testAndSetAcquire(true, false);
}

bool ThreadEvent::isSet() const
{
    if (!d) {
        return false;
    }
    return d->flag.loadAcquire();
}

quint32 ThreadEvent::getting() const
{
    if (!d) {
        return 0;
    }
    return d->getting();
}

void ThreadEvent::link(ThreadEvent &other)
{
    if (!d) {
        return;
    }
    d->mutex.lock();
    d->linkTo.append(&other);
    d->mutex.unlock();
    other.d->mutex.lock();
    other.d->linkFrom.append(this);
    other.d->mutex.unlock();
}

void ThreadEvent::unlink(ThreadEvent &other)
{
    if (!d) {
        return;
    }
    d->mutex.lock();
    d->linkTo.removeOne(&other);
    d->mutex.unlock();
    other.d->mutex.lock();
    other.d->linkFrom.removeOne(this);
    other.d->mutex.unlock();
}

class GatePrivate
{
public:
    Lock lock;
};

bool Gate::tryWait(quint32 msecs /*= (UINT_MAX)*/)
{
    if (!lock.isLocked()) {
        return true;
    } else {
        bool success = lock.tryAcquire(msecs);
        if (!success) {
            return false;
        } else {
            lock.release();
            return true;
        }
    }
}

QTNETWORKNG_NAMESPACE_END
