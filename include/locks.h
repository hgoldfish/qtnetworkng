#ifndef QTNG_LOCKS_H
#define QTNG_LOCKS_H

#include <QtCore/qqueue.h>
#include <QtCore/qdebug.h>
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
    void release();
    void release(int value);
    bool isLocked() const;
    bool isUsed() const;
private:
    SemaphorePrivate * d_ptr;
    Q_DECLARE_PRIVATE(Semaphore)
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


template<typename Value>
class ValueEvent
{
public:
    ValueEvent() {}
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
    event.wait(blocking);
    return value;
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
    ScopedLock(QSharedPointer<LockType> lock)
        :lock(lock), success(false)
    {
        success = lock->acquire();
    }
    ~ScopedLock()
    {
        if (success && !lock.isNull()) {
            lock.data()->release();
        }
    }
    bool isSuccess() const { return success; }
private:
    QWeakPointer<LockType> lock;
    bool success;
};


template <typename T>
class Queue
{
public:
    explicit Queue(quint32 capacity);
    Queue() : Queue(UINT_MAX) {}
    ~Queue();
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
    Event notEmpty;
    Event notFull;
    quint32 mCapacity;
    Q_DISABLE_COPY(Queue)
};


template<typename T>
Queue<T>::Queue(quint32 capacity)
    :mCapacity(capacity)
{
    notEmpty.clear();
    notFull.set();
}


template<typename T>
Queue<T>::~Queue()
{
//    if (queue.size() > 0) {
//        qDebug() << "queue is free with element left.";
//    }
}


template<typename T>
void Queue<T>::setCapacity(quint32 capacity)
{
    this->mCapacity = capacity;
    if (isFull()) {
        notFull.clear();
    } else {
        notFull.set();
    }
}


template<typename T>
void Queue<T>::clear()
{
    this->queue.clear();
    notFull.set();
    notEmpty.clear();
}


template<typename T>
bool Queue<T>::remove(const T &e)
{
    int n = this->queue.removeAll(e);
    if (n > 0) {
        if (isEmpty()) {
            notEmpty.clear();
        } else {
            notEmpty.set();
        }
        if (isFull()) {
            notFull.clear();
        } else {
            notFull.set();
        }
        return true;
    } else {
        return false;
    }
}


template<typename T>
bool Queue<T>::put(const T &e)
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


template<typename T>
bool Queue<T>::putForcedly(const T& e)
{
    queue.enqueue(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template<typename T>
bool Queue<T>::returns(const T &e)
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


template<typename T>
bool Queue<T>::returnsForcely(const T& e)
{
    queue.prepend(e);
    notEmpty.set();
    if (isFull()) {
        notFull.clear();
    }
    return true;
}


template<typename T>
T Queue<T>::get()
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


template<typename T>
T Queue<T>::peek()
{
    if (!isEmpty())
        return T();
    return queue.head();
}


template<typename T>
inline bool Queue<T>::isEmpty() const
{
    return queue.isEmpty();
}


template<typename T>
inline bool Queue<T>::isFull() const
{
    return static_cast<quint32>(queue.size()) >= mCapacity;
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_LOCKS_H
