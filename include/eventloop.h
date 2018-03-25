#ifndef QTNG_EVENTLOOP_NG_H
#define QTNG_EVENTLOOP_NG_H

#include <functional>
#include <QtCore/qthreadstorage.h>
#include <QtCore/qvariant.h>
#include <QtCore/qdebug.h>
#include <QtCore/qpointer.h>
#include "coroutine.h"


QTNETWORKNG_NAMESPACE_BEGIN

struct Functor
{
    virtual ~Functor();
    virtual void operator()() = 0;
};

struct Arguments
{
    virtual ~Arguments();
};

typedef void (*Callback)(const Arguments *args);


struct DoNothingFunctor: public Functor
{
    virtual void operator()();
};


struct CallbackFunctor:public Functor
{
    explicit CallbackFunctor(Callback callback, Arguments *args);
    ~CallbackFunctor();
    virtual void operator()();
    const Callback callback;
    Arguments * const args;
};


struct YieldCurrentFunctor: public Functor
{
    explicit YieldCurrentFunctor();
    virtual void operator()();
    QPointer<BaseCoroutine> coroutine;
};

template<typename T>
struct DeleteLaterFunctor: public Functor
{
    explicit DeleteLaterFunctor(const T* p)
        :p(p) {}
    virtual void operator()()
    {
        delete p;
    }
    const T* p;
};

#if QT_VERSION < 0x050000
typedef qptrdiff qintptr;
#endif

class EventLoopCoroutinePrivate;
class EventLoopCoroutine: public BaseCoroutine
{
    Q_OBJECT

public:
    enum EventType
    {
        Read = 1,
        Write = 2,
        ReadWrite = 3,
    };

public:
    EventLoopCoroutine();
    virtual ~EventLoopCoroutine();
    virtual void run();
public:
    int createWatcher(EventType event, qintptr fd, Functor *callback);
    void startWatcher(int watcherId);
    void stopWatcher(int watcherId);
    void removeWatcher(int watcherId);
    void triggerIoWatchers(qintptr fd);
    int callLater(int msecs, Functor *callback);
    void callLaterThreadSafe(int msecs, Functor *callback);
    int callRepeat(int msecs, Functor *callback);
    void cancelCall(int callbackId);
    int exitCode();
    void runUntil(BaseCoroutine *coroutine);
public:
    static EventLoopCoroutine *get();
private:
    EventLoopCoroutinePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(EventLoopCoroutine)
};

inline QDebug &operator <<(QDebug &out, const EventLoopCoroutine& el)
{
    return out << QString::fromLatin1("EventLoopCoroutine(id=%1)").arg(el.id());
}

class ScopedIoWatcher
{
public:
    ScopedIoWatcher(EventLoopCoroutine::EventType event, qintptr fd);
    ~ScopedIoWatcher();
    void start();
private:
    int watcherId;
};

class CoroutinePrivate;
class Coroutine: public BaseCoroutine
{
    Q_OBJECT
    Q_DISABLE_COPY(Coroutine)
public:
    explicit Coroutine(size_t stackSize = 1024 * 1024 * 8);
    Coroutine(QObject *obj, const char *slot, size_t stackSize = 1024 * 1024 * 8);
    virtual ~Coroutine();
public:
    bool isActive() const;
    Coroutine *start(int msecs = 0);
    void kill(CoroutineException *e = 0, int msecs = 0);
    void cancelStart();
    bool join();
    virtual void run();
    static Coroutine *current();
    static void sleep(int msecs);
    inline static Coroutine *spawn(std::function<void()> f);
private:
    CoroutinePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Coroutine)
};

inline QDebug &operator <<(QDebug &out, const Coroutine& el)
{
    return out << QString::fromLatin1("Coroutine(id=%1)").arg(el.id());
}

class CoroutineSpawnHelper: public Coroutine
{
public:
    CoroutineSpawnHelper(std::function<void()> f)
        :f(f){}
    virtual void run(){f(); }
private:
    std::function<void()> f;
};

Coroutine *Coroutine::spawn(std::function<void()> f)
{
    Coroutine *c =  new CoroutineSpawnHelper(f);
    c->start();
    return c;
}

class EventLoopCoroutinePrivate
{
public:
    explicit EventLoopCoroutinePrivate(EventLoopCoroutine* q);
    virtual ~EventLoopCoroutinePrivate();
public:
    virtual void run() = 0;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) = 0;
    virtual void startWatcher(int watcherId) = 0;
    virtual void stopWatcher(int watcherId) = 0;
    virtual void removeWatcher(int watcherId) = 0;
    virtual void triggerIoWatchers(qintptr fd) = 0;
    virtual int callLater(int msecs, Functor * callback) = 0;
    virtual void callLaterThreadSafe(int msecs, Functor *callback) = 0;
    virtual int callRepeat(int msecs, Functor * callback) = 0;
    virtual void cancelCall(int callbackId) = 0;
    virtual int exitCode() = 0;
    virtual void runUntil(BaseCoroutine *coroutine) = 0;
protected:
    EventLoopCoroutine * const q_ptr;
};

class TimeoutException: public CoroutineException
{
public:
    explicit TimeoutException();
    virtual QString what() const throw();
    virtual void raise();
};

class Timeout: public QObject
{
public:
    Timeout(int msecs);
    ~Timeout();
public:
    void restart();
private:
    int msecs;
    int timeoutId;
};

int start_application();


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_EVENTLOOP_NG_H
