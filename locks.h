#ifndef LOCKS_H
#define LOCKS_H

#include <QtGlobal>
#include <QQueue>

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
    SemaphorePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Semaphore)
};

class Lock: public Semaphore
{
public:
    Lock();
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
private:
    ConditionPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Condition)
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
private:
    EventPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Event)
};

class GatePrivate;
class Gate
{
public:
    Gate();
    virtual ~Gate();
public:
    bool goThrough(bool blocking = true);
    void open();
    void close();
    bool isOpen() const;
private:
    GatePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Gate)
};

template <typename LockType>
class ScopedLock
{
public:
    ScopedLock(LockType &lock)
        :lock(lock)
    {
        lock.acquire();
    }
    ~ScopedLock()
    {
        lock.release();
    }
private:
    LockType & lock;
};


template <typename T>
class Queue
{
public:
    Queue(int capacity);
    ~Queue();
    void setCapacity(int capacity);
    void put(const T &e);
    T get();
    bool isEmpty() const;
    bool isFull() const;
private:
    QQueue<T> queue;
    Event notEmpty;
    Event notFull;
    int capacity;
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
    notFull.set();
    notEmpty.set();
}

template<typename T>
void Queue<T>::setCapacity(int capacity)
{
    this->capacity = capacity;
    if(this->capacity <= 0 || queue.size() < this->capacity)
        notFull.set();
}

template<typename T>
void Queue<T>::put(const T &e)
{
    notFull.wait();
    queue.enqueue(e);
    notEmpty.set();
}

template<typename T>
T Queue<T>::get()
{
    notEmpty.wait();
    const T &e = queue.dequeue();
    if(this->capacity <= 0 || queue.size() < this->capacity)
        notFull.set();
    return e;
}

template<typename T>
bool Queue<T>::isEmpty() const
{
    return queue.isEmpty();
}

template<typename T>
bool Queue<T>::isFull() const
{
    return this->capacity > 0 && queue.size() >= this->capacity;
}

#endif // LOCKS_H
