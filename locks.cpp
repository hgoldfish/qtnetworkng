#include <QPointer>
#include <QSharedPointer>
#include "eventloop.h"
#include "locks.h"


class SemaphorePrivate: public QObject
{
public:
    SemaphorePrivate(Semaphore *q, int value);
    virtual ~SemaphorePrivate();
public:
    bool acquire(bool blocking);
    void release(int value);
    void notifyWaiters();
private:
    const int init_value;
    volatile int counter;
    int notified;
    QList<QPointer<QBaseCoroutine> > waiters;
    Semaphore * const q_ptr;
    Q_DECLARE_PUBLIC(Semaphore)
};

SemaphorePrivate::SemaphorePrivate(Semaphore *q, int value)
    :init_value(value), counter(value), notified(0), q_ptr(q)
{
}

SemaphorePrivate::~SemaphorePrivate()
{
    if(!waiters.isEmpty()) {
        qWarning("Semaphore is deleted but some one waited.");
    }
    if(notified) {
        EventLoopCoroutine::get()->cancelCall(notified);
    }
    while(!waiters.isEmpty()) {
        const QPointer<QBaseCoroutine> &waiter = waiters.takeFirst();
        if(waiter.isNull())
            continue;
        waiter->yield();
    }
}

bool SemaphorePrivate::acquire(bool blocking)
{
    if(counter > 0)
    {
        counter -= 1;
        return true;
    }
    if(!blocking)
        return false;

    waiters.append(QBaseCoroutine::current());
    try
    {
        EventLoopCoroutine::get()->yield();
        // if there is no exception, the release() has remove the waiter.
        Q_ASSERT(!waiters.contains(QBaseCoroutine::current()));
    }
    catch(...)
    {
        // if we caught an exception, the release() must not touch me.
        // the waiter should be remove.
        waiters.removeOne(QBaseCoroutine::current());
        throw;
    }
    return true;
}

struct SemaphoreNotifyWaitersArguments: public Arguments
{
    QPointer<SemaphorePrivate> sp;
};


void notifyWaitersCallback(const Arguments *args)
{
    const SemaphoreNotifyWaitersArguments *snwargs = dynamic_cast<const SemaphoreNotifyWaitersArguments*>(args);
    if(!snwargs)
    {
        qWarning("call notifyWaitersCallback without arguments.");
        return;
    }
    if(!snwargs->sp)
    {
        qWarning("SemaphorePrivate is deleted while calling notifyWaitersCallback.");
        return;
    }
    snwargs->sp->notifyWaiters();
}

void SemaphorePrivate::release(int value)
{
    counter += value;
    counter = qMin(static_cast<int>(counter), init_value);
    if(!notified && !waiters.isEmpty())
    {
        SemaphoreNotifyWaitersArguments *snwargs = new SemaphoreNotifyWaitersArguments;
        snwargs->sp = this;
        notified = EventLoopCoroutine::get()->callLater(0, new CallbackFunctor(notifyWaitersCallback, snwargs));
    }
}

void SemaphorePrivate::notifyWaiters()
{
    while(!waiters.isEmpty() && counter > 0)
    {
        const QPointer<QBaseCoroutine> &waiter = waiters.takeFirst();
        if(waiter.isNull())
            continue;
        counter -= 1;
        waiter->yield();
    }

    Q_ASSERT(notified > 0);
    notified = 0;
}

Semaphore::Semaphore(int value)
    :d_ptr(new SemaphorePrivate(this, value))
{
}

Semaphore::~Semaphore()
{
    d_ptr->deleteLater();
}

bool Semaphore::acquire(bool blocking)
{
    Q_D(Semaphore);
    return d->acquire(blocking);
}

void Semaphore::release()
{
    Q_D(Semaphore);
    d->release(1);
}

bool Semaphore::isLocked() const
{
    const Q_D(Semaphore);
    return d->counter <= 0;
}


Lock::Lock()
    :Semaphore(1)
{
}

struct RLockState
{
    qintptr holder;
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
    Lock lock;
    quintptr holder;
    int counter;
    RLock * const q_ptr;
    Q_DECLARE_PUBLIC(RLock)
};

RLockPrivate::RLockPrivate(RLock *q)
    :holder(0), counter(0), q_ptr(q)
{}

RLockPrivate::~RLockPrivate()
{
}

bool RLockPrivate::acquire(bool blocking)
{
    if(holder == QBaseCoroutine::current()->id())
    {
        counter += 1;
        return true;
    }
    if(lock.acquire(blocking))
    {
        counter = 1;
        holder = QBaseCoroutine::current()->id();
        return true;
    }
    return false; // how can i reach here?
}

void RLockPrivate::release()
{
    if(holder != QBaseCoroutine::current()->id())
    {
        qWarning("do not release other coroutine's rlock.");
        return;
    }
    counter -= 1;
    if(counter == 0)
    {
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
    if(state.counter > 0) {
        lock.release();
    }
    return state;
}

void RLockPrivate::set(const RLockState &state)
{
    counter = state.counter;
    holder = state.holder;
    if(counter > 0) {
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
    const Q_D(RLock);
    return d->lock.isLocked();
}

bool RLock::isOwned() const
{
    const Q_D(RLock);
    return d->holder == QBaseCoroutine::current()->id();
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
    waiter->acquire();
    waiters.append(waiter);
    return waiter->acquire();
}

void ConditionPrivate::notify(int value)
{
    for(int i = 0; i < value && !waiters.isEmpty(); ++i)
    {
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
    Condition condition;
    bool flag;
    Event * const q_ptr;
    Q_DECLARE_PUBLIC(Event)
};

EventPrivate::EventPrivate(Event *q)
    :flag(false), q_ptr(q)
{
}

EventPrivate::~EventPrivate()
{
    set();
}

void EventPrivate::set()
{
    if(!flag) {
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
    if(!blocking)
    {
        return flag;
    }
    else
    {
        if(!flag)
        {
            condition.wait();
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
    const Q_D(Event);
    return d->flag;
}

void Event::clear()
{
    Q_D(Event);
    d->clear();
}


class GatePrivate
{
public:
    Event event;
};

Gate::Gate()
    :d_ptr(new GatePrivate())
{
    Q_D(Gate);
    d->event.set();
}

Gate::~Gate()
{
    delete d_ptr;
}

bool Gate::goThrough(bool blocking)
{
    Q_D(Gate);
    return d->event.wait(blocking);
}

void Gate::open()
{
    Q_D(Gate);
    d->event.set();
}

bool Gate::isOpen() const
{
    const Q_D(Gate);
    return d->event.isSet();
}

void Gate::close()
{
    Q_D(Gate);
    d->event.clear();
}
