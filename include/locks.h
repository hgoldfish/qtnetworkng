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
    Semaphore(int value = 1);
    virtual ~Semaphore();
public:
    bool acquire(bool blocking = true);
    void release();
    bool isLocked() const;
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
    int getting() const;
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
    int getting() const;
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
    value = Value();
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
        :lock(lock), success(false)
    {
        success = lock.acquire();
    }
    ~ScopedLock()
    {
        if(success) {
            lock.release();
        }
    }
private:
    LockType & lock;
    bool success;
};


template <typename T>
class Queue
{
public:
    Queue(int capacity);
    ~Queue();
    void setCapacity(int capacity);
    bool put(const T &e);
    T get();
    bool isEmpty() const;
    bool isFull() const;
    int getCapacity() const { return capacity; }
    int size() const { return queue.size(); }
    int getting() const { return notEmpty.getting();}
private:
    QQueue<T> queue;
    Event notEmpty;
    Event notFull;
    int capacity;
    Q_DISABLE_COPY(Queue)
};

template<typename T>
Queue<T>::Queue(int capacity)
    :capacity(capacity)
{
    notEmpty.clear();
    notFull.set();
}

template<typename T>
Queue<T>::~Queue()
{
    if(queue.size() > 0) {
        qDebug() << "queue is free with element left.";
    }
}

template<typename T>
void Queue<T>::setCapacity(int capacity)
{
    this->capacity = capacity;
    if(isFull()) {
        notFull.clear();
    }
}

template<typename T>
bool Queue<T>::put(const T &e)
{
    if(!notFull.wait()) {
        return false;
    }
    queue.enqueue(e);
    notEmpty.set();
    if(isFull()) {
        notFull.clear();
    }
    return true;
}

template<typename T>
T Queue<T>::get()
{
    if(!notEmpty.wait())
        return T();
    const T &e = queue.dequeue();
    if(isEmpty()) {
        notEmpty.clear();
    }
    if(!isFull()) {
        notFull.set();
    }
    return e;
}

template<typename T>
inline bool Queue<T>::isEmpty() const
{
    return queue.isEmpty();
}

template<typename T>
inline bool Queue<T>::isFull() const
{
    return capacity > 0 && queue.size() >= capacity;
}

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_LOCKS_H
