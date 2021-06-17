#include <QtCore/qpointer.h>
#include <QtCore/qsharedpointer.h>
#include "../include/private/eventloop_p.h"
#include "../include/locks.h"

QTNETWORKNG_NAMESPACE_BEGIN


class SemaphorePrivate: public QObject
{
public:
    SemaphorePrivate(Semaphore *q, int value);
    virtual ~SemaphorePrivate();
public:
    bool acquire(bool blocking);
    void release(int value);
    void scheduleDelete();
    static SemaphorePrivate *getPrivate(QSharedPointer<Semaphore> q) { return q ? q->d_ptr : nullptr;  }
public:
    Semaphore * const q_ptr;
    QList<QPointer<BaseCoroutine> > waiters;
    const int init_value;
    volatile int counter;
    int notified;
    Q_DECLARE_PUBLIC(Semaphore)

    friend QSharedPointer<Semaphore> acquireAny(const QList<QSharedPointer<Semaphore>> &semaphores, int value, bool blocking);
};


SemaphorePrivate::SemaphorePrivate(Semaphore *q, int value)
    :q_ptr(q), init_value(value), counter(value), notified(0)
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
    SemaphoreNotifyWaitersFunctor(SemaphorePrivate *sp, bool doDelete)
        :sp(sp), doDelete(doDelete) {}
    QPointer<SemaphorePrivate> sp;
    bool doDelete;
    virtual void operator() () override
    {
        if (sp.isNull()) {
            qWarning("SemaphorePrivate is deleted while calling notifyWaitersCallback.");
            return;
        }
        while (!sp.isNull() && (sp->notified != 0 || doDelete)
                            && (sp->counter > 0 || doDelete)
                            && !sp->waiters.isEmpty()) {
            QPointer<BaseCoroutine> waiter = sp->waiters.takeFirst();
            if (waiter.isNull()) {
                qDebug() << "waiter was deleted.";
                continue;
            }
            if (!doDelete) {
                --sp->counter;
            }
            waiter->yield();
        }
        if (!sp.isNull()) {
            if (doDelete) {
                if (sp->counter != sp->init_value) {
                    qWarning("Semaphore is deleting but caught by some one.");
                }
                delete sp.data();
            } else {
                sp->notified = 0;  // do not move this line above the last loop, see the return statement in ::acquire()
            }
        }
    }
};


void SemaphorePrivate::release(int value)
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
        notified = EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(this, false));
    }
}


void SemaphorePrivate::scheduleDelete()
{
    if (notified) {
        EventLoopCoroutine::get()->cancelCall(notified);
        notified = 0;
    }
    counter += waiters.count();
    EventLoopCoroutine::get()->callLater(0, new SemaphoreNotifyWaitersFunctor(this, true));
}


Semaphore::Semaphore(int value)
    :d_ptr(new SemaphorePrivate(this, value))
{
}


Semaphore::~Semaphore()
{
    d_ptr->scheduleDelete();
    d_ptr = nullptr;
}


bool Semaphore::acquire(bool blocking)
{
    Q_D(Semaphore);
    if (!d) {
        return false;
    }
    return d->acquire(blocking);
}


bool Semaphore::acquire(int value, bool blocking)
{
    Q_D(Semaphore);
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
    Q_D(Semaphore);
    if (!d) {
        return;
    }
    d->release(value);
}


bool Semaphore::isLocked() const
{
    Q_D(const Semaphore);
    if (!d) {
        return false;
    }
    return d->counter <= 0;
}


bool Semaphore::isUsed() const
{
    Q_D(const Semaphore);
    if (!d) {
        return false;
    }
    return d->counter < d->init_value;
}


quint32 Semaphore::getting() const
{
    Q_D(const Semaphore);
    if (!d) {
        return false;
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
        qWarning("do not release other coroutine's rlock.");
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
    ConditionPrivate(Condition *q);
    ~ConditionPrivate();
public:
    bool wait();
    void notify(int value);
private:
    QList<QSharedPointer<Lock> > waiters;
    Condition * const q_ptr;
    Q_DECLARE_PUBLIC(Condition)
};


ConditionPrivate::ConditionPrivate(Condition *q)
    :q_ptr(q)
{
}


ConditionPrivate::~ConditionPrivate()
{
    notify(waiters.size());
}


bool ConditionPrivate::wait()
{
    QSharedPointer<Lock> waiter(new Lock());
    if (!waiter->acquire())
        return false;
    waiters.append(waiter);
    try {
        if (waiter->acquire()) {
            waiter->release();
            waiters.removeOne(waiter);
            return true;
        } else {
            waiters.removeOne(waiter);
            return false;
        }
    } catch (...) {
        waiter->release();
        waiters.removeOne(waiter);
        throw;
    }
}


void ConditionPrivate::notify(int value)
{
    for (int i = 0; i < value && !waiters.isEmpty(); ++i) {
        QSharedPointer<Lock> waiter = waiters.takeFirst();
        waiter->release();
    }
}


Condition::Condition()
    :d_ptr(new ConditionPrivate(this))
{
}


Condition::~Condition()
{
    delete d_ptr;
}


bool Condition::wait()
{
    Q_D(Condition);
    return d->wait();
}


void Condition::notify(int value)
{
    Q_D(Condition);
    d->notify(value);
}


void Condition::notifyAll()
{
    Q_D(Condition);
    d->notify(d->waiters.size());
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
                qDebug() << "event is deleted.";
                break;
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
            return success;
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
