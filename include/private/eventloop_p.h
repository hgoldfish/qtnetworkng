#ifndef QTNG_EVENTLOOP_P_H
#define QTNG_EVENTLOOP_P_H

#include "../eventloop.h"

QTNETWORKNG_NAMESPACE_BEGIN

class Functor
{
public:
    virtual ~Functor();
    virtual bool operator()() = 0;
};

class DoNothingFunctor : public Functor
{
public:
    virtual bool operator()();
};

class YieldCurrentFunctor : public Functor
{
public:
    explicit YieldCurrentFunctor();
    virtual bool operator()();
    QPointer<BaseCoroutine> coroutine;
};

template<typename T>
class DeleteLaterFunctor : public Functor
{
public:
    explicit DeleteLaterFunctor(T *p)
        : p(p)
    {
    }
    virtual bool operator()() { delete p; return true; }
    T * const p;
};

class LambdaFunctor : public Functor
{
public:
    LambdaFunctor(const std::function<void()> &callback)
        : callback(callback)
    {
    }
    virtual bool operator()() override;
    std::function<void()> callback;
};

/*
#if QT_VERSION < 0x050000
typedef qptrdiff qintptr;
#endif
*/

class EventLoopCoroutinePrivate;
class EventLoopCoroutine : public BaseCoroutine
{
    Q_DISABLE_COPY(EventLoopCoroutine)
public:
    enum EventType {
        Read = 1,
        Write = 2,
        ReadWrite = 3,
    };
public:
    virtual ~EventLoopCoroutine() override;
    virtual void run() override;
public:
    int createWatcher(EventType event, qintptr fd, Functor *callback);  // the ownership of callback is taken
    void startWatcher(int watcherId);
    void stopWatcher(int watcherId);
    void removeWatcher(int watcherId);
    void triggerIoWatchers(qintptr fd);
    int callLater(quint32 msecs, Functor *callback);  // the ownership of callback is taken
    void callLaterThreadSafe(quint32 msecs, Functor *callback);  // the ownership of callback is taken
    int callRepeat(quint32 msecs, Functor *callback);  // the ownership of callback is taken
    void cancelCall(int callbackId);
    int exitCode();
    bool runUntil(BaseCoroutine *coroutine);
    bool yield();
    bool isQt() const { return objectName() == QString::fromUtf8("qt_eventloop_coroutine"); }
    bool isEv() const { return objectName() == QString::fromUtf8("libev_eventloop_coroutine"); }
    bool isWin() const { return objectName() == QString::fromUtf8("win_eventloop_coroutine"); }
public:
    static EventLoopCoroutine *get();
protected:
    // eventloop coroutine should use a bigger stack size instead of DEFAULT_COROUTINE_STACK_SIZE, which may be defined
    // smaller.
    EventLoopCoroutine(EventLoopCoroutinePrivate *d, size_t stackSize = 1024 * 1024 * 8);
private:
    EventLoopCoroutinePrivate * const dd_ptr;
    Q_DECLARE_PRIVATE_D(dd_ptr, EventLoopCoroutine)
};

class ScopedIoWatcher
{
public:
    ScopedIoWatcher(EventLoopCoroutine::EventType event, qintptr fd);
    ~ScopedIoWatcher();
    bool start();
private:
    EventLoopCoroutine::EventType event;
    qintptr fd;
    int watcherId;
};

class EventLoopCoroutinePrivate
{
public:
    explicit EventLoopCoroutinePrivate(EventLoopCoroutine *q);
    virtual ~EventLoopCoroutinePrivate();
public:
    virtual void run() = 0;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) = 0;
    virtual void startWatcher(int watcherId) = 0;
    virtual void stopWatcher(int watcherId) = 0;
    virtual void removeWatcher(int watcherId) = 0;
    virtual void triggerIoWatchers(qintptr fd) = 0;
    virtual int callLater(quint32 msecs, Functor *callback) = 0;
    virtual void callLaterThreadSafe(quint32 msecs, Functor *callback) = 0;
    virtual int callRepeat(quint32 msecs, Functor *callback) = 0;
    virtual void cancelCall(int callbackId) = 0;
    virtual int exitCode() = 0;
    virtual bool runUntil(BaseCoroutine *coroutine) = 0;
protected:
    EventLoopCoroutine * const q_ptr;
    QPointer<BaseCoroutine> loopCoroutine;
    static EventLoopCoroutinePrivate *getPrivateHelper(EventLoopCoroutine *coroutine) { return coroutine->d_func(); }
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
};

class CurrentLoopStorage
{
public:
    QSharedPointer<EventLoopCoroutine> getOrCreate();
    QSharedPointer<EventLoopCoroutine> get();
    void set(QSharedPointer<EventLoopCoroutine> eventLoop);
    void clean();
private:
    QThreadStorage<QSharedPointer<EventLoopCoroutine>> storage;
};

CurrentLoopStorage *currentLoop();

#if QTNETWOKRNG_USE_EV
class EvEventLoopCoroutine : public EventLoopCoroutine
{
public:
    EvEventLoopCoroutine();
};
#endif

#if QTNETWORKNG_USE_WIN
class WinEventLoopCoroutine : public EventLoopCoroutine
{
public:
    WinEventLoopCoroutine();
};
#endif

class QtEventLoopCoroutine : public EventLoopCoroutine
{
public:
    QtEventLoopCoroutine();
};

QTNETWORKNG_NAMESPACE_END

class QDebug;
QDebug operator<<(QDebug out, const QTNETWORKNG_NAMESPACE::EventLoopCoroutine &el);

#endif
