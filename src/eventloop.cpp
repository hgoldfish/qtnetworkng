#include <QtCore/qdebug.h>
#include <QtCore/qpointer.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qthread.h>
#include "../include/private/eventloop_p.h"
#include "../include/locks.h"
#include "debugger.h"

QTNG_LOGGER("qtng.eventloop");

QTNETWORKNG_NAMESPACE_BEGIN

Q_GLOBAL_STATIC(CurrentLoopStorage, currentLoopStorage)
Q_GLOBAL_STATIC(QAtomicInteger<int>, preferLibevFlag);

CurrentLoopStorage *currentLoop()
{
    return currentLoopStorage();
}

class CoroutineSpawnHelper : public Coroutine
{
public:
    CoroutineSpawnHelper(std::function<void()> f)
        : f(new std::function<void()>(f))
    {
    }
    virtual ~CoroutineSpawnHelper() override;
    virtual void run() override;
private:
    QScopedPointer<std::function<void()>> f;
};

CoroutineSpawnHelper::~CoroutineSpawnHelper() { }

void CoroutineSpawnHelper::run()
{
    (*f)();
    f.reset();
}

Coroutine *Coroutine::spawn(std::function<void()> f)
{
    Coroutine *c = new CoroutineSpawnHelper(f);
    c->start();
    return c;
}

void Coroutine::preferLibev()
{
    preferLibevFlag->storeRelease(true);
}

Functor::~Functor() { }

bool DoNothingFunctor::operator()()
{
    return false;
}

YieldCurrentFunctor::YieldCurrentFunctor()
{
    coroutine = BaseCoroutine::current();
}

bool YieldCurrentFunctor::operator()()
{
    if (coroutine.isNull()) {
        qtng_debug << "coroutine is deleted while YieldCurrentFunctor called.";
        return false;
    }
    try {
        return coroutine->yield();
    } catch (CoroutineException &e) {
        qtng_debug << "do not send exception to event loop, just delete event loop:" << e.what();
    }
    return false;
}

EventLoopCoroutinePrivate::EventLoopCoroutinePrivate(EventLoopCoroutine *q)
    : q_ptr(q)
{
}

EventLoopCoroutinePrivate::~EventLoopCoroutinePrivate() { }

EventLoopCoroutine::EventLoopCoroutine(EventLoopCoroutinePrivate *d, size_t stackSize)
    : BaseCoroutine(BaseCoroutine::current(), stackSize)
    , dd_ptr(d)
{
}

EventLoopCoroutine::~EventLoopCoroutine()
{
    delete dd_ptr;
}

EventLoopCoroutine *EventLoopCoroutine::get()
{
    return currentLoopStorage->getOrCreate().data();
}

void EventLoopCoroutine::run()
{
    Q_D(EventLoopCoroutine);
    d->run();
}

int EventLoopCoroutine::createWatcher(EventType event, qintptr fd, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    return d->createWatcher(event, fd, callback);
}

void EventLoopCoroutine::startWatcher(int watcherId)
{
    Q_D(EventLoopCoroutine);
    return d->startWatcher(watcherId);
}

void EventLoopCoroutine::stopWatcher(int watcherId)
{
    Q_D(EventLoopCoroutine);
    return d->stopWatcher(watcherId);
}

void EventLoopCoroutine::removeWatcher(int watcherId)
{
    Q_D(EventLoopCoroutine);
    return d->removeWatcher(watcherId);
}

void EventLoopCoroutine::triggerIoWatchers(qintptr fd)
{
    Q_D(EventLoopCoroutine);
    return d->triggerIoWatchers(fd);
}

int EventLoopCoroutine::callLater(quint32 msecs, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    return d->callLater(msecs, callback);
}

void EventLoopCoroutine::callLaterThreadSafe(quint32 msecs, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    d->callLaterThreadSafe(msecs, callback);
}

int EventLoopCoroutine::callRepeat(quint32 msecs, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    return d->callRepeat(msecs, callback);
}

void EventLoopCoroutine::cancelCall(int callbackId)
{
    Q_D(EventLoopCoroutine);
    return d->cancelCall(callbackId);
}

int EventLoopCoroutine::exitCode()
{
    Q_D(EventLoopCoroutine);
    return d->exitCode();
}

bool EventLoopCoroutine::runUntil(BaseCoroutine *coroutine)
{
    Q_D(EventLoopCoroutine);
    return d->runUntil(coroutine);
}

bool EventLoopCoroutine::yield()
{
    Q_D(EventLoopCoroutine);
    if (d->loopCoroutine) {
        return d->loopCoroutine->yield();
    } else {
        return BaseCoroutine::yield();
    }
}

QSharedPointer<EventLoopCoroutine> CurrentLoopStorage::getOrCreate()
{
    QSharedPointer<EventLoopCoroutine> eventLoop;
    if (storage.hasLocalData()) {
        eventLoop = storage.localData();
    }
    if (eventLoop.isNull()) {
#if QTNETWOKRNG_USE_EV
        if (preferLibevFlag->loadAcquire()) {
            eventLoop.reset(new EvEventLoopCoroutine());
            eventLoop->setObjectName(QString::fromLatin1("libev_eventloop_coroutine"));
            storage.setLocalData(eventLoop);
            // qtng_debug << "create libev eventloop coroutine.";
        } else {
            if (QCoreApplication::instance() && QCoreApplication::instance()->thread() == QThread::currentThread()) {
                eventLoop.reset(new QtEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("qt_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
                // qtng_debug << "create qt eventloop coroutine.";
            } else {
                eventLoop.reset(new EvEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("libev_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
                // qtng_debug << "create libev eventloop coroutine.";
            }
        }
#elif QTNETWORKNG_USE_WIN
        if (preferLibevFlag->loadAcquire()) {
            eventLoop.reset(new WinEventLoopCoroutine());
            eventLoop->setObjectName(QString::fromLatin1("win_eventloop_coroutine"));
            storage.setLocalData(eventLoop);
        } else {
            if (QCoreApplication::instance() && QCoreApplication::instance()->thread() == QThread::currentThread()) {
                eventLoop.reset(new QtEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("qt_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
            } else {
                eventLoop.reset(new WinEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("win_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
            }
        }
#else
        eventLoop.reset(new QtEventLoopCoroutine());
        eventLoop->setObjectName(QString::fromLatin1("qt_eventloop_coroutine"));
        storage.setLocalData(eventLoop);
#endif
    }
    return eventLoop;
}

QSharedPointer<EventLoopCoroutine> CurrentLoopStorage::get()
{
    if (storage.hasLocalData()) {
        return storage.localData();
    } else {
        return QSharedPointer<EventLoopCoroutine>();
    }
}

void CurrentLoopStorage::set(QSharedPointer<EventLoopCoroutine> eventLoop)
{
    storage.setLocalData(eventLoop);
}

void CurrentLoopStorage::clean()
{
    if (storage.hasLocalData()) {
        storage.localData().reset();
    }
}

ScopedIoWatcher::ScopedIoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
    : event(event)
    , fd(fd)
    , watcherId(0)
{
}

bool ScopedIoWatcher::start()
{
    QSharedPointer<EventLoopCoroutine> eventLoop = currentLoopStorage->getOrCreate();
    if (watcherId <= 0) {
        watcherId = eventLoop->createWatcher(event, fd, new YieldCurrentFunctor());
    }
    eventLoop->startWatcher(watcherId);
    return eventLoop->yield();
}

ScopedIoWatcher::~ScopedIoWatcher()
{
    if (watcherId > 0) {
        QSharedPointer<EventLoopCoroutine> eventLoop = currentLoopStorage->getOrCreate();
        eventLoop->removeWatcher(watcherId);
    }
}

class CoroutinePrivate : public QObject
{
public:
    CoroutinePrivate(Coroutine *q, QObject *obj, const char *slot);
    virtual ~CoroutinePrivate();
private:
    Coroutine * const q_ptr;
    Event finishedEvent;
    QObject * const obj;
    const char * const slot;
    int callbackId;

    Q_DECLARE_PUBLIC(Coroutine)
    friend struct StartCoroutineFunctor;
    friend struct KillCoroutineFunctor;
};

CoroutinePrivate::CoroutinePrivate(Coroutine *q, QObject *obj, const char *slot)
    : q_ptr(q)
    , obj(obj)
    , slot(slot)
    , callbackId(0)
{
    q->finished.addCallback([this](BaseCoroutine *) { finishedEvent.set(); });
}

CoroutinePrivate::~CoroutinePrivate() { }

struct StartCoroutineFunctor : public Functor
{
    StartCoroutineFunctor(CoroutinePrivate *cp)
        : cp(cp)
    {
    }
    virtual ~StartCoroutineFunctor() override;
    QPointer<CoroutinePrivate> cp;
    virtual bool operator()() override
    {
        if (cp.isNull()) {
            qtng_warning << "startCouroutine is called without coroutine.";
            return false;
        }
        cp->callbackId = 0;
        if (cp->q_func()->state() != BaseCoroutine::Initialized) {
            //            qtng_debug << "coroutine has been started or stopped.";
            return false;
        }
        cp->q_func()->yield();
        return true;
    }
};

StartCoroutineFunctor::~StartCoroutineFunctor() { }

struct KillCoroutineFunctor : public Functor
{
    KillCoroutineFunctor(CoroutinePrivate *cp, CoroutineException *e)
        : cp(cp)
        , e(e)
    {
    }
    virtual ~KillCoroutineFunctor() override;
    QPointer<CoroutinePrivate> cp;
    CoroutineException *e;
    virtual bool operator()() override;
};

KillCoroutineFunctor::~KillCoroutineFunctor()
{
    if (e) {  // raise() consumed it!
        delete e;
    }
}

bool KillCoroutineFunctor::operator()()
{
    if (cp.isNull()) {
        qtng_warning << "killCoroutine is called without coroutine";
        delete e;
        return false;
    } else if (cp->q_func()->state() != BaseCoroutine::Started) {
        delete e;
    } else {
        cp->q_func()->raise(e);
    }
    e = nullptr;
    return true;
}

Coroutine::Coroutine(size_t stackSize)
    : BaseCoroutine(nullptr, stackSize)
    , d_ptr(new CoroutinePrivate(this, nullptr, nullptr))
{
}

Coroutine::Coroutine(QObject *obj, const char *slot, size_t stackSize)
    : BaseCoroutine(nullptr, stackSize)
    , d_ptr(new CoroutinePrivate(this, obj, slot))
{
}

Coroutine::~Coroutine()
{
    delete d_ptr;
}

Coroutine *Coroutine::start(quint32 msecs)
{
    Q_D(Coroutine);
    if (d->callbackId > 0 || isRunning() || isFinished()) {
        return this;
    }
    d->callbackId = EventLoopCoroutine::get()->callLater(msecs, new StartCoroutineFunctor(d));
    return this;
}

void Coroutine::kill(CoroutineException *e, quint32 msecs)
{
    Q_D(Coroutine);
    if (!e) {
        e = new CoroutineExitException();
    }
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if (state() == Coroutine::Initialized) {
        if (dynamic_cast<CoroutineExitException *>(e)) {
            if (d->callbackId > 0) {
                EventLoopCoroutine::get()->cancelCall(d->callbackId);
                d->callbackId = 0;
            }
            setState(Coroutine::Stopped);
            delete e;
            finished.callback(this);
        } else {
            if (d->callbackId == 0) {
                d->callbackId = c->callLater(msecs, new StartCoroutineFunctor(d));
            }
            c->callLater(msecs, new KillCoroutineFunctor(d, e));
        }
    } else if (isFinished()) {
        delete e;
    } else if (isRunning()) {
        c->callLater(msecs, new KillCoroutineFunctor(d, e));
    } else {
        qtng_warning << "invalid state while kiling coroutine.";
        delete e;
    }
}

void Coroutine::run()
{
    Q_D(Coroutine);
    d->callbackId = 0;
    if (d->obj && d->slot) {
        QMetaObject::invokeMethod(d->obj, d->slot);
    }
}

void Coroutine::cleanup()
{
    if (previous()) {
        previous()->yield();
    } else {
        EventLoopCoroutine::get()->yield();
    }
}

bool Coroutine::join()
{
    Q_D(Coroutine);
    if (state() == BaseCoroutine::Initialized || state() == BaseCoroutine::Started) {
        bool ok;
        if (!dynamic_cast<Coroutine *>(BaseCoroutine::current())) {
            ok = EventLoopCoroutine::get()->runUntil(this);
        } else {
            ok = d->finishedEvent.tryWait();
        }
        if (ok) {
            Q_ASSERT(isFinished());
            setState(Joined);
        }
        return ok;
    } else {
        return true;
    }
}

Coroutine *Coroutine::current()
{
    BaseCoroutine *c = BaseCoroutine::current();
    return dynamic_cast<Coroutine *>(c);
}

struct QScopedCallLater
{
    QScopedCallLater(int callbackId)
        : callbackId(callbackId)
    {
    }
    ~QScopedCallLater() { EventLoopCoroutine::get()->cancelCall(callbackId); }
    int callbackId;
};

void Coroutine::msleep(quint32 msecs)
{
    int callbackId = EventLoopCoroutine::get()->callLater(msecs, new YieldCurrentFunctor());
    QScopedCallLater scl(callbackId);
    Q_UNUSED(scl);
    EventLoopCoroutine::get()->yield();
}

struct TimeoutFunctor : public Functor
{
    TimeoutFunctor(Timeout *out, BaseCoroutine *coroutine)
        : out(out)
        , coroutine(coroutine)
    {
    }
    virtual ~TimeoutFunctor() override;
    QPointer<Timeout> out;
    QPointer<BaseCoroutine> coroutine;
    virtual bool operator()() override;
};

TimeoutFunctor::~TimeoutFunctor() { }

bool TimeoutFunctor::operator()()
{
    if (out.isNull() || coroutine.isNull()) {
        qtng_debug << "triggerTimeout is called while timeout or coroutine is deleted.";
        return false;
    }
    coroutine->raise(new TimeoutException());
    return true;
}

TimeoutException::TimeoutException() { }

QString TimeoutException::what() const
{
    return QString::fromLatin1("coroutine had set timeout.");
}

void TimeoutException::raise()
{
    throw *this;
}

CoroutineException *TimeoutException::clone() const
{
    return new TimeoutException();
}

Timeout::Timeout(float secs)
    : msecs(static_cast<quint32>((secs > 0.0f ? secs : 0.0f) * 1000))
    , timeoutId(0)
{
    if (msecs) {
        restart();
    }
}

Timeout::Timeout(quint32 msecs, int)
    : msecs(msecs)
    , timeoutId(0)
{
    if (msecs) {
        restart();
    }
}

Timeout::~Timeout()
{
    if (timeoutId) {
        EventLoopCoroutine::get()->cancelCall(timeoutId);
    }
}

void Timeout::cancel()
{
    if (timeoutId) {
        EventLoopCoroutine::get()->cancelCall(timeoutId);
        timeoutId = 0;
    }
}

void Timeout::restart()
{
    if (timeoutId) {
        EventLoopCoroutine::get()->cancelCall(timeoutId);
    }
    timeoutId = EventLoopCoroutine::get()->callLater(msecs, new TimeoutFunctor(this, BaseCoroutine::current()));
}

QTNETWORKNG_NAMESPACE_END

QDebug operator<<(QDebug out, const QTNETWORKNG_NAMESPACE::EventLoopCoroutine &el)
{
    return out << QString::fromLatin1("EventLoopCoroutine(id=%1)").arg(el.id());
}
