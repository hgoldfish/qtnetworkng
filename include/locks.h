#ifndef QTNG_LOCKS_H
#define QTNG_LOCKS_H

#include <QtCore/qqueue.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qreadwritelock.h>
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

class Lock : public Semaphore
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
public:
    void link(Event &other);
    void unlink(Event &other);
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
public:
    void link(ThreadEvent &other);
    void unlink(ThreadEvent &other);
private:
    ThreadEventPrivate *d;
    Q_DISABLE_COPY(ThreadEvent)
};

template<typename EventType>
bool waitAnyEvent(const QList<QSharedPointer<EventType>> &events)
{
    EventType event;
    for (int i = 0; i < events.size(); ++i) {
        if (events[i]->isSet()) {
            return true;
        }
        event.link(*events[i]);
    }
    return event.wait();
}

template<typename EventType>
bool waitAllEvents(const QList<QSharedPointer<EventType>> &events)
{
    for (int i = 0; i < events.size(); ++i) {
        if (!events[i]->wait()) {
            // Q_UNRECHABLE()
            return false;
        }
    }
    return true;
}

template<typename Value>
class ValueEvent
{
public:
    ValueEvent() { }
    ~ValueEvent() { }
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

template<typename LockType>
class ScopedLock
{
public:
    ScopedLock(LockType &lock)
        : lock(lock)
        , success(false)
    {
        success = lock.acquire();
    }
    ~ScopedLock()
    {
        if (success) {
            lock.release();
        }
    }
    inline void release()
    {
        if (success) {
            lock.release();
            success = false;
        }
    }
    inline bool isSuccess() const { return success; }
private:
    LockType &lock;
    bool success;
};

template<typename T, typename EventType, typename ReadWriteLockType>
class QueueType
{
public:
    explicit QueueType(quint32 capacity);
    QueueType()
        : QueueType(UINT_MAX)
    {
    }
    ~QueueType();
    void setCapacity(quint32 capacity);
    bool put(const T &e);  // insert e to the tail of queue. blocked until not full.
    bool putForcedly(const T &e);  // insert e to the tail of queue ignoring capacity.
    bool returns(const T &e);  // like put() but insert e to the head of queue.
    bool returnsForcely(const T &e);  // like putForcedly() but insert e to the head of queue.
    T get();
    T peek();
    void clear();
    bool remove(const T &e);
public:
    inline bool isEmpty();
    inline bool isFull();
    inline quint32 capacity() const;
    inline quint32 size() const;
    inline quint32 getting() const;
    inline bool contains(const T &e);
public:
    QQueue<T> queue;
    EventType notEmpty;
    EventType notFull;
    ReadWriteLockType lock;
    quint32 mCapacity;
    Q_DISABLE_COPY(QueueType)
};

template<typename T, typename EventType, typename ReadWriteLockType>
class MultiQueueType
{
public:
    inline void addQueue(QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue);
    inline void removeQueue(QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue);
    inline T wait();
private:
    EventType notEmpty;
    QList<QSharedPointer<QueueType<T, EventType, ReadWriteLockType>>> queues;
    ReadWriteLockType lock;
};

struct DummpyReadWriteLock
{
    inline void lockForRead() { }
    inline void lockForWrite() { }
    inline void unlock() { }
};

template<typename T>
class Queue : public QueueType<T, Event, DummpyReadWriteLock>
{
public:
    explicit Queue(quint32 capacity)
        : QueueType<T, Event, DummpyReadWriteLock>(capacity)
    {
    }
    explicit Queue()
        : QueueType<T, Event, DummpyReadWriteLock>()
    {
    }
};

template<typename T>
class MultiQueue : public MultiQueueType<T, Event, DummpyReadWriteLock>
{
};

template<typename T>
class ThreadQueue : public QueueType<T, ThreadEvent, QReadWriteLock>
{
public:
    explicit ThreadQueue(quint32 capacity)
        : QueueType<T, ThreadEvent, QReadWriteLock>(capacity)
    {
    }
    explicit ThreadQueue()
        : QueueType<T, ThreadEvent, QReadWriteLock>()
    {
    }
};

template<typename T>
class MultiThreadQueue : public MultiQueueType<T, ThreadEvent, QReadWriteLock>
{
};

template<typename T, typename EventType, typename ReadWriteLockType>
QueueType<T, EventType, ReadWriteLockType>::QueueType(quint32 capacity)
    : mCapacity(capacity)
{
    notEmpty.clear();
    notFull.set();
}

template<typename T, typename EventType, typename ReadWriteLockType>
QueueType<T, EventType, ReadWriteLockType>::~QueueType()
{
    //    if (queue.size() > 0) {
    //        qtng_debug << "queue is free with element left.";
    //    }
}

template<typename T, typename EventType, typename ReadWriteLockType>
void QueueType<T, EventType, ReadWriteLockType>::setCapacity(quint32 capacity)
{
    lock.lockForWrite();
    this->mCapacity = capacity;
    if (static_cast<quint32>(queue.size()) >= mCapacity) {
        notFull.clear();
    } else {
        notFull.set();
    }
    lock.unlock();
}

template<typename T, typename EventType, typename ReadWriteLockType>
void QueueType<T, EventType, ReadWriteLockType>::clear()
{
    lock.lockForWrite();
    this->queue.clear();
    notFull.set();
    notEmpty.clear();
    lock.unlock();
}

template<typename T, typename EventType, typename ReadWriteLockType>
bool QueueType<T, EventType, ReadWriteLockType>::remove(const T &e)
{
    lock.lockForWrite();
    int n = this->queue.removeAll(e);
    if (n > 0) {
        if (this->queue.isEmpty()) {
            notEmpty.clear();
        } else {
            notEmpty.set();
        }
        if (static_cast<quint32>(queue.size()) >= mCapacity) {
            notFull.clear();
        } else {
            notFull.set();
        }
        lock.unlock();
        return true;
    } else {
        lock.unlock();
        return false;
    }
}

template<typename T, typename EventType, typename ReadWriteLockType>
bool QueueType<T, EventType, ReadWriteLockType>::put(const T &e)
{
    if (!notFull.wait()) {
        return false;
    }
    lock.lockForWrite();
    queue.enqueue(e);
    notEmpty.set();
    if (static_cast<quint32>(queue.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

template<typename T, typename EventType, typename ReadWriteLockType>
bool QueueType<T, EventType, ReadWriteLockType>::putForcedly(const T &e)
{
    lock.lockForWrite();
    queue.enqueue(e);
    notEmpty.set();
    if (static_cast<quint32>(queue.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

template<typename T, typename EventType, typename ReadWriteLockType>
bool QueueType<T, EventType, ReadWriteLockType>::returns(const T &e)
{
    if (!notFull.wait()) {
        return false;
    }
    lock.lockForWrite();
    queue.prepend(e);
    notEmpty.set();
    if (static_cast<quint32>(queue.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

template<typename T, typename EventType, typename ReadWriteLockType>
bool QueueType<T, EventType, ReadWriteLockType>::returnsForcely(const T &e)
{
    lock.lockForWrite();
    queue.prepend(e);
    notEmpty.set();
    if (static_cast<quint32>(queue.size()) >= mCapacity) {
        notFull.clear();
    }
    lock.unlock();
    return true;
}

template<typename T, typename EventType, typename ReadWriteLockType>
T QueueType<T, EventType, ReadWriteLockType>::get()
{
    if (!notEmpty.wait()) {
        return T();
    }
    lock.lockForWrite();
    const T &e = queue.dequeue();
    if (this->queue.isEmpty()) {
        notEmpty.clear();
    }
    if (static_cast<quint32>(queue.size()) < mCapacity) {
        notFull.set();
    }
    lock.unlock();
    return e;
}

template<typename T, typename EventType, typename ReadWriteLockType>
T QueueType<T, EventType, ReadWriteLockType>::peek()
{
    lock.lockForRead();
    if (this->queue.isEmpty()) {
        return T();
    }
    const T &t = queue.head();
    lock.unlock();
    return t;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline bool QueueType<T, EventType, ReadWriteLockType>::isEmpty()
{
    lock.lockForRead();
    bool t = queue.isEmpty();
    lock.unlock();
    return t;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline bool QueueType<T, EventType, ReadWriteLockType>::isFull()
{
    lock.lockForRead();
    bool t = static_cast<quint32>(queue.size()) >= mCapacity;
    lock.unlock();
    return t;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline quint32 QueueType<T, EventType, ReadWriteLockType>::capacity() const
{
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.lockForRead();
    quint32 c = mCapacity;
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.unlock();
    return c;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline quint32 QueueType<T, EventType, ReadWriteLockType>::size() const
{
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.lockForRead();
    int s = queue.size();
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.unlock();
    return s;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline quint32 QueueType<T, EventType, ReadWriteLockType>::getting() const
{
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.lockForRead();
    int g = notEmpty.getting();
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.unlock();
    return g;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline bool QueueType<T, EventType, ReadWriteLockType>::contains(const T &e)
{
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.lockForRead();
    bool t = queue.contains(e);
    const_cast<QueueType<T, EventType, ReadWriteLockType> *>(this)->lock.unlock();
    return t;
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline void MultiQueueType<T, EventType, ReadWriteLockType>::addQueue(
        QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue)
{
    lock.lockForWrite();
    queue.notEmpty.link(notEmpty);
    queues.append(queue);
    lock.unlock();
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline void MultiQueueType<T, EventType, ReadWriteLockType>::removeQueue(
        QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue)
{
    lock.lockForWrite();
    queue.notEmpty.unlink(notEmpty);
    queues.removeOne(queue);
    lock.unlock();
}

template<typename T, typename EventType, typename ReadWriteLockType>
inline T MultiQueueType<T, EventType, ReadWriteLockType>::wait()
{
    notEmpty.wait();
    T result;
    lock.lockForWrite();
    bool allEmpty = true;
    int i = 0;
    for (; i < queues.size(); ++i) {
        QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue = queues.at(i);
        if (!queue->isEmpty()) {
            result = queue.get();
            //            // let's move the queue to the first
            //            if (i >= 10) {
            //                for (int j = i; j > 0; --j) {
            //                    queues[j] = queues[j - 1];
            //                }
            //                queues[0] = queue;
            //            }
            allEmpty = queue.isEmpty();
            break;
        }
    }
    if (allEmpty) {
        // resume from the i + 1 element.
        ++i;
        for (; i < queues.size(); ++i) {
            QSharedPointer<QueueType<T, EventType, ReadWriteLockType>> queue = queues.at(i);
            if (!queue.isEmpty()) {
                allEmpty = false;
                break;
            }
        }
    }
    lock.unlock();
    return result;
}

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_LOCKS_H
