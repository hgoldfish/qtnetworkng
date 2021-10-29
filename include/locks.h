#ifndef QTNG_LOCKS_H
#define QTNG_LOCKS_H

#include <QtCore/qqueue.h>
#include <QtCore/qsharedpointer.h>
#include "coroutine.h"

QTNETWORKNG_NAMESPACE_BEGIN


class SemaphorePrivate;
class Semaphore
{
public:
    explicit Semaphore(int value = 1);
    virtual ~Semaphore();
public:
    bool acquire(bool blocking = true);
    bool acquire(int value, bool blocking = true);
    void release(int value = 1);
    bool isLocked() const;
    bool isUsed() const;
    quint32 getting() const;
private:
    QSharedPointer<SemaphorePrivate> d;
    Q_DISABLE_COPY(Semaphore)
};


class Lock: public Semaphore
{
public:
    Lock();
private:
    Q_DISABLE_COPY(Lock)
};


class RLockPrivate;
class RLock
{
public:
    RLock();
    virtual ~RLock();
public:
    bool acquire(bool blocking = true);
    void release();
    bool isLocked() const;
    bool isOwned() const;
private:
    RLockPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(RLock)
    Q_DISABLE_COPY(RLock)
    friend class ConditionPrivate;
};


class ConditionPrivate;
class Condition
{
public:
    Condition();
    virtual ~Condition();
public:
//    bool acquire(bool blocking = true);
//    void release();
    bool wait();
    void notify(int value = 1);
    void notifyAll();
    quint32 getting() const;
private:
    ConditionPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Condition)
    Q_DISABLE_COPY(Condition)
};


class EventPrivate;
class Event
{
public:
    Event();
    virtual ~Event();
public:
    bool wait(bool blocking = true);
    void set();
    void clear();
    bool isSet() const;
    quint32 getting() const;
private:
    EventPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Event)
    Q_DISABLE_COPY(Event)
};


class ThreadEventPrivate;
class ThreadEvent
{
public:
    ThreadEvent();
    virtual ~ThreadEvent();
public:
    bool wait(bool blocking = true);
    void set();
    void clear();
    bool isSet() const;
    quint32 getting() const;
private:
    const QSharedPointer<ThreadEventPrivate> d;
    Q_DISABLE_COPY(ThreadEvent);
};


template<typename Value>
class ValueEvent
{
public:
    ValueEvent() {}
    ~ValueEvent() {}
    void send(const Value &value);
    Value wait(bool blocking = true);
    void set() { event.set(); }
    void clear() { event.clear(); }
    bool isSet() const { return event.isSet(); }
    quint32 getting() const { return event.getting(); }
public:
    Event event;
    Value value;
private:
    Q_DISABLE_COPY(ValueEvent)
};


template<typename Value>
void ValueEvent<Value>::send(const Value &value)
{
    this->value = value;
    event.set();
}


template<typename Value>
Value ValueEvent<Value>::wait(bool blocking)
{
    if (!event.wait(blocking)) {
        return Value();
    } else {
        return value;
    }
}


class GatePrivate;
class Gate
{
public:
    Gate();
    virtual ~Gate();
public:
    bool goThrough(bool blocking = true);
    bool wait(bool blocking = true) { return goThrough(blocking); }
    void open();
    void close();
    bool isOpen() const;
    bool isClosed() const;
private:
    GatePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Gate)
    Q_DISABLE_COPY(Gate)
};


template <typename LockType>
class ScopedLock
{
public:
    ScopedLock(LockType &lock)
        : lock(lock), success(false)
    {
        success = lock.acquire();
    }
    ~ScopedLock()
    {
        if (success) {
            lock.release();
        }
    }
    bool isSuccess() const { return success; }
private:
    LockType &lock;
    bool success;
};


template <typename T, typename EventType>
class QueueType
{
public:
    explicit QueueType(quint32 capacity);
    QueueType() : QueueType(UINT_MAX) {}
    ~QueueType();
    void setCapacity(quint32 capacity);
    bool put(const T &e);             // insert e to the tail of queue. blocked until not full.
    bool putForcedly(const T& e);     // insert e to the tail of queue ignoring capacity.
    bool returns(const T &e);         // like put() but insert e to the head of queue.
    bool returnsForcely(const T& e);  // like putForcedly() but insert e to the head of queue.
    T get();
    T peek();
    bool isEmpty() const;
    bool isFull() const;
    quint32 capacity() const { return mCapacity; }
    quint32 size() const { return queue.size(); }
    quint32 getting() const { return notEmpty.getting();}

    void clear();
    bool contains(const T &e) const { return queue.contains(e); }
    bool remove(const T &e);
private:
    QQueue<T> queue;
    EventType notEmpty;
    EventType notFull;
    quint32 mCapacity;
    Q_DISABLE_COPY(QueueType)
};


template <typename T>
class Queue: public QueueType<T, Event>
{
public:
    explicit Queue(quint32 capacity) : QueueType<T, Event>(capacity) {}
    explicit Queue() : QueueType<T, Event>() {}
};


template <typename T>
class ThreadQueue: public QueueType<T, ThreadEvent>
{
public:
    explicit ThreadQueue(quint32 capacity) : QueueType<T, ThreadEvent>(capacity) {}
    explicit ThreadQueue() : QueueType<T, ThreadEvent>() {}
};


template <typename T, typename EventType>
QueueType<T, EventType>::QueueType(quint32 capacity)
    : mCapacity(capacity)
{
    notEmpty.clear();
    notFull.set();
}


template <typename T, typename EventType>
QueueType<T, EventType>::~QueueType()
{
//    if (queue.size() > 0) {
//        qDebug() << "queue is free with element left.";
//    }
}


template <typename T, typename EventType>
void QueueType<T, EventType>::setCapacity(quint32 capacity)
{
    this->mCapacity = capacity;
    if (isFull()) {
        notFull.clear();
    } else {
        notFull.set();
    }
}


template <typename T, typename EventType>
void QueueType<T, EventType>::clear()
{
    this->queue.clear();
    notFull.set();
    notEmpty.clear();
}


template <typename T, typename EventType>
bool QueueType<T, EventType>::remove(const T &e)
{
    int n = this->queue.removeAll(e);
    if (n > 0) {
        if (isEmpty()) {
            notEmpty.clear();
        } else {
            notEmpty.set();
        }
        if (isFull()) {
            clear();
        } else {
            notFull.set();
        }
        return true;
    } else {
        return false;
    }
}


template <typename T, typename EventType>
bool QueueType<T, EventType>::put(const T &e)
{
    if (!notFull.wait()) {
        return false;
    }
    queue.enqueue(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template <typename T, typename EventType>
bool QueueType<T, EventType>::putForcedly(const T& e)
{
    queue.enqueue(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template <typename T, typename EventType>
bool QueueType<T, EventType>::returns(const T &e)
{
    if (!notFull.wait()) {
        return false;
    }
    queue.prepend(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template <typename T, typename EventType>
bool QueueType<T, EventType>::returnsForcely(const T& e)
{
    queue.prepend(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template <typename T, typename EventType>
T QueueType<T, EventType>::get()
{
    if (!notEmpty.wait())
        return T();
    const T &e = queue.dequeue();
    if (isEmpty()) {
        notEmpty.clear();
    }
    if (!isFull()) {
        notFull.set();
    }
    return e;
}


template <typename T, typename EventType>
T QueueType<T, EventType>::peek()
{
    if (!isEmpty())
        return T();
    return queue.head();
}


template <typename T, typename EventType>
inline bool QueueType<T, EventType>::isEmpty() const
{
    return queue.isEmpty();
}


template <typename T, typename EventType>
inline bool QueueType<T, EventType>::isFull() const
{
    return static_cast<quint32>(queue.size()) >= mCapacity;
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_LOCKS_H
