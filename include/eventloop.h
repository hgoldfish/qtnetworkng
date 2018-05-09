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


struct DoNothingFunctor: public Functor
{
    virtual void operator()();
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
    explicit DeleteLaterFunctor(T* p)
        :p(p) {}
    virtual void operator()()
    {
        delete p;
    }
    T* const p;
};

#if QT_VERSION < 0x050000
typedef qptrdiff qintptr;
#endif

class EventLoopCoroutinePrivate;
class EventLoopCoroutine: public BaseCoroutine
{
    Q_DISABLE_COPY(EventLoopCoroutine)
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
    bool runUntil(BaseCoroutine *coroutine);
    void yield();
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
    Q_DISABLE_COPY(Coroutine)
public:
    explicit Coroutine(size_t stackSize = 1024 * 1024 * 8);
    Coroutine(QObject *obj, const char *slot, size_t stackSize = 1024 * 1024 * 8);
    virtual ~Coroutine();
public:
    bool isRunning() const;
    bool isFinished() const;
    Coroutine *start(int msecs = 0);
    void kill(CoroutineException *e = 0, int msecs = 0);
    void cancelStart();
    bool join();
    virtual void run();
    static Coroutine *current();
    static void msleep(int msecs);
    static void sleep(float secs) { msleep(secs * 1000); }
    inline static Coroutine *spawn(std::function<void()> f);
protected:
    virtual void cleanup() override;
private:
    CoroutinePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Coroutine)
};


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
    virtual bool runUntil(BaseCoroutine *coroutine) = 0;
    virtual void yield() = 0;
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

// useful for qt application.
int start_application(std::function<void()> coroutine_entry);


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_EVENTLOOP_NG_H
