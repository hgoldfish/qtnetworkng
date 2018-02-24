#include <QtCore/QPointer>
#include <QtCore/QSharedPointer>
#include "../include/eventloop.h"
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
    void notifyWaiters(bool force);
    void scheduleDelete();
private:
    const int init_value;
    volatile int counter;
    int notified;
    QList<QPointer<BaseCoroutine> > waiters;
    Semaphore * const q_ptr;
    Q_DECLARE_PUBLIC(Semaphore)
};

SemaphorePrivate::SemaphorePrivate(Semaphore *q, int value)
    :init_value(value), counter(value), notified(0), q_ptr(q)
{
}

SemaphorePrivate::~SemaphorePrivate()
{
    Q_ASSERT(waiters.isEmpty());
}

void SemaphorePrivate::scheduleDelete()
{
    if(notified) {
        EventLoopCoroutine::get()->cancelCall(notified);
        notified = 0;
    }
    notifyWaiters(true);
    if(counter != init_value) {
        qWarning("Semaphore is deleted but caught by some one.");
    }
    EventLoopCoroutine::get()->callLater(0, new DeleteLaterFunctor<SemaphorePrivate>(this));
}

bool SemaphorePrivate::acquire(bool blocking)
{
    if(counter > 0) {
        counter -= 1;
        return true;
    }
    if(!blocking)
        return false;

    waiters.append(BaseCoroutine::current());
    try {
        EventLoopCoroutine::get()->yield();
        // if there is no exception, the release() has remove the waiter.
        bool found = waiters.contains(BaseCoroutine::current());
        Q_ASSERT(!found);
    } catch(...) {
        // if we caught an exception, the release() must not touch me.
        // the waiter should be remove.
        bool found = waiters.removeOne(BaseCoroutine::current());
        Q_ASSERT(found);
        throw;
    }
    return notified != 0;
}

struct SemaphoreNotifyWaitersArguments: public Arguments
{
    QPointer<SemaphorePrivate> sp;
};


void notifyWaitersCallback(const Arguments *args)
{
    const SemaphoreNotifyWaitersArguments *snwargs = dynamic_cast<const SemaphoreNotifyWaitersArguments*>(args);
    if(!snwargs) {
        qWarning("call notifyWaitersCallback without arguments.");
        return;
    }
    if(!snwargs->sp) {
        qWarning("SemaphorePrivate is deleted while calling notifyWaitersCallback.");
        return;
    }
    snwargs->sp->notifyWaiters(false);
}

void SemaphorePrivate::release(int value)
{
    if(value <= 0) {
        return;
    }
    if(counter > INT_MAX - value) {
        counter = INT_MAX;
    } else {
        counter += value;
    }
    counter = qMin(static_cast<int>(counter), init_value);
    if(!notified && !waiters.isEmpty()) {
        SemaphoreNotifyWaitersArguments *snwargs = new SemaphoreNotifyWaitersArguments;
        snwargs->sp = this;
        notified = EventLoopCoroutine::get()->callLater(0, new CallbackFunctor(notifyWaitersCallback, snwargs));
    }
}

void SemaphorePrivate::notifyWaiters(bool force)
{
    if(notified == 0 && !force) {
        return;
    }
    while(!waiters.isEmpty() && counter > 0) {
        const QPointer<BaseCoroutine> &waiter = waiters.takeFirst();
        if(waiter.isNull()) {
            qDebug() << "waiter was deleted.";
            continue;
        }
        counter -= 1;
        waiter->yield();
    }
    notified = 0;
}

Semaphore::Semaphore(int value)
    :d_ptr(new SemaphorePrivate(this, value))
{
}

Semaphore::~Semaphore()
{
    d_ptr->scheduleDelete();
    d_ptr = 0;
}

bool Semaphore::acquire(bool blocking)
{
    Q_D(Semaphore);
    if(!d) {
        return false;
    }
    return d->acquire(blocking);
}

void Semaphore::release()
{
    Q_D(Semaphore);
    if(!d) {
        return;
    }
    d->release(1);
}

bool Semaphore::isLocked() const
{
    Q_D(const Semaphore);
    if(!d) {
        return false;
    }
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
    if(holder == BaseCoroutine::current()->id()) {
        counter += 1;
        return true;
    }
    if(lock.acquire(blocking)) {
        counter = 1;
        holder = BaseCoroutine::current()->id();
        return true;
    }
    return false; // XXX lock is deleted.
}

void RLockPrivate::release()
{
    if(holder != BaseCoroutine::current()->id()) {
        qWarning("do not release other coroutine's rlock.");
        return;
    }
    counter -= 1;
    if(counter == 0) {
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
    if(!waiter->acquire())
        return false;
    waiters.append(waiter);
    try{
        if(waiter->acquire()) {
            waiter->release();
            return true;
        } else {
            return false;
        }
    } catch (...) {
        waiter->release();
        throw;
    }
}

void ConditionPrivate::notify(int value)
{
    for(int i = 0; i < value && !waiters.isEmpty(); ++i) {
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

int Condition::getting() const
{
    Q_D(const Condition);
    return d->waiters.size();
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
    if(!flag) {
        condition.notifyAll();
    }
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
    if(!blocking) {
        return flag;
    } else {
        if(!flag) {
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
    Q_D(const Event);
    return d->flag;
}

void Event::clear()
{
    Q_D(Event);
    d->clear();
}

int Event::getting() const
{
    Q_D(const Event);
    return d->condition.getting();
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
    Q_D(const Gate);
    return d->event.isSet();
}

void Gate::close()
{
    Q_D(Gate);
    d->event.clear();
}

QTNETWORKNG_NAMESPACE_END
