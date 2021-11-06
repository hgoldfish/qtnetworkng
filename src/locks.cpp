#include <QtCore/qwaitcondition.h>
#include <QtCore/qmutex.h>
#include <QtCore/qpointer.h>
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
    bool acquire(bool blocking);
    void release(QSharedPointer<SemaphorePrivate> self, int value);
    void scheduleDelete(QSharedPointer<SemaphorePrivate> self);
public:
    QList<QPointer<BaseCoroutine> > waiters;
    const int init_value;
    volatile int counter;
    int notified;

    friend QSharedPointer<Semaphore> acquireAny(const QList<QSharedPointer<Semaphore>> &semaphores, int value, bool blocking);
};


SemaphorePrivate::SemaphorePrivate(int value)
    : init_value(value), counter(value), notified(0)
{
}


SemaphorePrivate::~SemaphorePrivate()
{
    Q_ASSERT(waiters.isEmpty());
}


bool SemaphorePrivate::acquire(bool blocking)
{
    if (counter > 0) {
        --counter;
        return true;
    }
    if (!blocking)
        return false;

    waiters.append(BaseCoroutine::current());
    try {
        Q_ASSERT_X(EventLoopCoroutine::get() != BaseCoroutine::current(), "SemaphorePrivate",
                   "coroutine locks should not be called from eventloop coroutine.");
        EventLoopCoroutine::get()->yield();
        // if there is no exception, the release() has remove the waiter.
        bool found = waiters.contains(BaseCoroutine::current());
        Q_ASSERT_X(!found, "SemaphorePrivate",
                   "have you forget to start a new coroutine?");  // usually caused by locks running in eventloop.
    } catch(...) {
        // if we caught an exception, the release() must not touch me.
        // the waiter should be remove.
        bool found = waiters.removeAll(BaseCoroutine::current());
        Q_ASSERT(found);
        throw;
    }
    return notified != 0;
}


class SemaphoreNotifyWaitersFunctor: public Functor
{
public:
    SemaphoreNotifyWaitersFunctor(QSharedPointer<SemaphorePrivate> sp, bool doDelete)
        :sp(sp), doDelete(doDelete) {}
    QSharedPointer<SemaphorePrivate> sp;
    bool doDelete;
    virtual void operator() () override
    {
        while ((sp->notified != 0 || doDelete) &&
               (sp->counter > 0 || doDelete) &&
               !sp->waiters.isEmpty()) {
            QPointer<BaseCoroutine> waiter = sp->waiters.takeFirst();
            if (waiter.isNull()) {
                qtng_debug << "waiter was deleted.";
                continue;
            }
            if (!doDelete) {
                --sp->counter;
            }
            waiter->yield();
        }
        if (doDelete) {
            if (sp->counter != sp->init_value) {
                qtng_warning << "Semaphore is deleting but caught by some one.";
            }
        } else {
            sp->notified = 0;  // do not move this line above the loop, see the return statement in ::acquire()
        }
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
    counter += waiters.count();
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


bool Semaphore::acquire(bool blocking)
{
    if (!d) {
        return false;
    }
    return d->acquire(blocking);
}


bool Semaphore::acquire(int value, bool blocking)
{
    if (!d) {
        return false;
    }
    if (value > d->init_value) {
        return false;
    }
    for (int i = 0; i < value; ++i) {
        if (!d->acquire(blocking)) {
            return false;
        }
    }
    return true;
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
    :Semaphore(1)
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
    bool acquire(bool blocking);
    void release();
    RLockState reset();
    void set(const RLockState& state);
private:
    RLock * const q_ptr;
    Lock lock;
    quintptr holder;
    int counter;
    Q_DECLARE_PUBLIC(RLock)
};


RLockPrivate::RLockPrivate(RLock *q)
    :q_ptr(q), holder(0), counter(0)
{}


RLockPrivate::~RLockPrivate()
{
}


bool RLockPrivate::acquire(bool blocking)
{
    if (holder == BaseCoroutine::current()->id()) {
        counter += 1;
        return true;
    }
    if (lock.acquire(blocking)) {
        counter = 1;
        holder = BaseCoroutine::current()->id();
        return true;
    }
    return false; // XXX lock is deleted.
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
        lock.acquire();
    }
}


RLock::RLock()
    :d_ptr(new RLockPrivate(this))
{}


RLock::~RLock()
{
    delete d_ptr;
}


bool RLock::acquire(bool blocking)
{
    Q_D(RLock);
    return d->acquire(blocking);
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
    QList<QSharedPointer<Lock> > waiters;
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


bool Condition::wait()
{
    Q_D(Condition);
    QSharedPointer<Lock> waiter(new Lock());
    if (!waiter->acquire())
        return false;
    d->waiters.append(waiter);
    try {
        if (waiter->acquire()) {
            waiter->release();
            d->waiters.removeOne(waiter);
            return true;
        } else {
            d->waiters.removeOne(waiter);
            return false;
        }
    } catch (...) {
        waiter->release();
        d->waiters.removeOne(waiter);
        throw;
    }
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
    bool wait(bool blocking);
private:
    Event * const q_ptr;
    Condition condition;
    volatile bool flag;
    Q_DECLARE_PUBLIC(Event)
};


EventPrivate::EventPrivate(Event *q)
    :q_ptr(q), flag(false)
{
}


EventPrivate::~EventPrivate()
{
    if (!flag && condition.getting() > 0) {
        condition.notifyAll();
    }
}


void EventPrivate::set()
{
    if (!flag) {
        flag = true;
        condition.notifyAll();
    }
}


void EventPrivate::clear()
{
    flag = false;
}


bool EventPrivate::wait(bool blocking)
{
    if (!blocking) {
        return flag;
    } else {
        while(!flag) {
            if (!condition.wait()) {
                qtng_debug << "event is deleted.";
                return false;
            }
        }
        return flag;
    }
}


Event::Event()
    :d_ptr(new EventPrivate(this))
{
}


Event::~Event()
{
    delete d_ptr;
}


bool Event::wait(bool blocking)
{
    Q_D(Event);
    return d->wait(blocking);
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


struct Behold {
    QPointer<EventLoopCoroutine> eventloop;
    QWeakPointer<Condition> condition;
};


class ThreadEventPrivate
{
public:
    ThreadEventPrivate();
    void notify();
    bool wait(bool blocking);
    quint32 getting() const;
public:
    QSharedPointer<QWaitCondition> condition;
    QSharedPointer<QMutex> mutex;
    QList<Behold> holds;
    QAtomicInteger<bool> flag;
    QAtomicInteger<int> count;  // only for condition
};


class NotifiyCondition: public Functor
{
public:
    NotifiyCondition(QSharedPointer<Condition> condition) : condition(condition) {}
    virtual void operator()() { condition->notifyAll(); }
    QSharedPointer<Condition> condition;
};


ThreadEventPrivate::ThreadEventPrivate()
    : condition(new QWaitCondition())
    , mutex(new QMutex())
    , flag(false)
    , count(0)
{}


void ThreadEventPrivate::notify()
{
    condition->wakeAll();
    mutex->lock();
    QSharedPointer<EventLoopCoroutine> eventloop = currentLoop()->get();
    for (const Behold &hold: holds) {
        if (hold.eventloop.data() == eventloop.data() && !hold.condition.isNull()) {
            hold.condition.toStrongRef()->notifyAll();
        } else if (!hold.eventloop.isNull() && !hold.condition.isNull()) {
            hold.eventloop.data()->callLaterThreadSafe(0, new NotifiyCondition(hold.condition.toStrongRef()));
        }
    }
    mutex->unlock();
}


bool ThreadEventPrivate::wait(bool blocking)
{
    if (!blocking || flag.loadAcquire()) {
        return flag.loadAcquire();
    }

    EventLoopCoroutine *eventloop = currentLoop()->get().data();

    if (!eventloop) {
        mutex->lock();
        ++count;
        this->condition->wait(mutex.data());
        --count;
        mutex->unlock();
    } else {
        QSharedPointer<Condition> condition;
        mutex->lock();
        for (const Behold &hold: holds) {
            if (hold.eventloop.data() == eventloop) {
                condition = hold.condition.toStrongRef();
                break;
            }
        }
        if (condition.isNull()) {
            condition.reset(new Condition());
            Behold hold;
            hold.condition = condition.toWeakRef();
            hold.eventloop = eventloop;
            holds.append(hold);
        }
        mutex->unlock();
        condition->wait();
    }
    return flag.loadAcquire();
}


quint32 ThreadEventPrivate::getting() const
{
    quint32 count = 0;
    mutex->lock();
    for (const Behold &hold: holds) {
        if (!hold.condition.isNull()) {
            count += hold.condition.toStrongRef()->getting();
        }
    }
    mutex->unlock();
    return count;
}


ThreadEvent::ThreadEvent()
    : d(new ThreadEventPrivate())
{}


ThreadEvent::~ThreadEvent()
{
    d->notify();
}


bool ThreadEvent::wait(bool blocking)
{
    return d->wait(blocking);
}


void ThreadEvent::set()
{
    if (d->flag.loadAcquire()) {
        return;
    }
    d->flag.storeRelease(true);
    d->notify();
}


void ThreadEvent::clear()
{
    d->flag.storeRelease(false);
}


bool ThreadEvent::isSet() const
{
    return d->flag.loadAcquire();
}


quint32 ThreadEvent::getting() const
{
    return d->getting();
}


class GatePrivate
{
public:
    Lock lock;
};


Gate::Gate()
    :d_ptr(new GatePrivate())
{
}


Gate::~Gate()
{
    delete d_ptr;
}


bool Gate::goThrough(bool blocking)
{
    Q_D(Gate);
    if (!d->lock.isLocked()) {
        return true;
    } else {
        bool success = d->lock.acquire(blocking);
        if (!success) {
            return false;
        } else {
            d->lock.release();
            return true;
        }
    }
}


void Gate::open()
{
    Q_D(Gate);
    if (d->lock.isLocked()) {
        d->lock.release();
    }
}


bool Gate::isOpen() const
{
    Q_D(const Gate);
    return !d->lock.isLocked();
}


bool Gate::isClosed() const
{
    Q_D(const Gate);
    return d->lock.isLocked();
}


void Gate::close()
{
    Q_D(Gate);
    if (!d->lock.isLocked()) {
        d->lock.acquire();
    }
}

QTNETWORKNG_NAMESPACE_END
