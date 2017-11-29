#ifndef QTNG_EVENTLOOP_NG_H
#define QTNG_EVENTLOOP_NG_H

#include <functional>
#include <QtCore/QThreadStorage>
#include <QtCore/QVariantList>
#include <QtCore/QDebug>
#include <QtCore/QPointer>
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
    QPointer<QBaseCoroutine> coroutine;
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
class EventLoopCoroutine: public QBaseCoroutine
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

class QCoroutinePrivate;
class QCoroutine: public QBaseCoroutine
{
    Q_OBJECT
    Q_DISABLE_COPY(QCoroutine)
public:
    explicit QCoroutine(size_t stackSize = 1024 * 1024 * 8);
    QCoroutine(QObject *obj, const char *slot, size_t stackSize = 1024 * 1024 * 8);
    virtual ~QCoroutine();
public:
    bool isActive() const;
    QCoroutine *start(int msecs = 0);
    void kill(QCoroutineException *e = 0, int msecs = 0);
    void cancelStart();
    bool join();
    virtual void run();
    static QCoroutine *current();
    static void sleep(int msecs);
    inline static QCoroutine *spawn(std::function<void()> f);
private:
    QCoroutinePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(QCoroutine)
};

inline QDebug &operator <<(QDebug &out, const QCoroutine& el)
{
    return out << QString::fromLatin1("QCoroutine(id=%1)").arg(el.id());
}

class QCoroutineSpawnHelper: public QCoroutine
{
public:
    QCoroutineSpawnHelper(std::function<void()> f)
        :f(f){}
    virtual void run(){f(); }
private:
    std::function<void()> f;
};

QCoroutine *QCoroutine::spawn(std::function<void()> f)
{
    QCoroutine *c =  new QCoroutineSpawnHelper(f);
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
protected:
    EventLoopCoroutine * const q_ptr;
};

class QTimeoutException: public QCoroutineException
{
public:
    explicit QTimeoutException();
    virtual QString what() const throw();
    virtual void raise();
};

class QTimeout: public QObject
{
public:
    QTimeout(int msecs);
    ~QTimeout();
public:
    void restart();
private:
    int msecs;
    int timeoutId;
};

int start_application();


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_EVENTLOOP_NG_H
