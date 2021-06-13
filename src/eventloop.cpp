#include <QtCore/qdebug.h>
#include <QtCore/qpointer.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qthread.h>
#include "../include/private/eventloop_p.h"
#include "../include/locks.h"
#ifdef Q_OS_UNIX
#include <signal.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN

Q_GLOBAL_STATIC(CurrentLoopStorage, currentLoopStorage)
Q_GLOBAL_STATIC(QAtomicInteger<int>, preferLibevFlag);


CurrentLoopStorage *currentLoop()
{
    return currentLoopStorage();
}


class CoroutineSpawnHelper: public Coroutine
{
public:
    CoroutineSpawnHelper(std::function<void()> f)
        :f(new std::function<void()>(f)){}
    virtual ~CoroutineSpawnHelper() override;
    virtual void run() override;
private:
    QScopedPointer<std::function<void()>> f;
};


CoroutineSpawnHelper::~CoroutineSpawnHelper() {}


void CoroutineSpawnHelper::run()
{
    (*f)();
    f.reset();
}


Coroutine *Coroutine::spawn(std::function<void()> f)
{
    Coroutine *c =  new CoroutineSpawnHelper(f);
    c->start();
    return c;
}


void Coroutine::preferLibev()
{
    preferLibevFlag->storeRelease(true);
}


Functor::~Functor()
{}


void DoNothingFunctor::operator ()()
{

}


YieldCurrentFunctor::YieldCurrentFunctor()
{
    coroutine = BaseCoroutine::current();
}


void YieldCurrentFunctor::operator ()()
{
    if (coroutine.isNull()) {
        qDebug() << "coroutine is deleted while YieldCurrentFunctor called.";
        return;
    }
    try {
        coroutine->yield();
    } catch(CoroutineException &e) {
        qDebug() << "do not send exception to event loop, just delete event loop:" << e.what();
    }
}


EventLoopCoroutinePrivate::EventLoopCoroutinePrivate(EventLoopCoroutine *q)
    :q_ptr(q){}


EventLoopCoroutinePrivate::~EventLoopCoroutinePrivate(){}


EventLoopCoroutine::EventLoopCoroutine(EventLoopCoroutinePrivate *d, size_t stackSize)
    :BaseCoroutine(BaseCoroutine::current(), stackSize), dd_ptr(d)
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
    return d->yield();
}


QSharedPointer<EventLoopCoroutine> CurrentLoopStorage::getOrCreate()
{
    QSharedPointer<EventLoopCoroutine> eventLoop;
    if (storage.hasLocalData()) {
        eventLoop = storage.localData();
    }
    if (eventLoop.isNull()) {
#ifdef QTNETWOKRNG_USE_EV
        if (preferLibevFlag->loadAcquire()) {
            eventLoop.reset(new EvEventLoopCoroutine());
            eventLoop->setObjectName(QString::fromLatin1("libev_eventloop_coroutine"));
            storage.setLocalData(eventLoop);
        } else {
            if (QCoreApplication::instance() && QCoreApplication::instance()->thread() == QThread::currentThread()) {
                eventLoop.reset(new QtEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("qt_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
            } else {
                eventLoop.reset(new EvEventLoopCoroutine());
                eventLoop->setObjectName(QString::fromLatin1("libev_eventloop_coroutine"));
                storage.setLocalData(eventLoop);
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
{
    QSharedPointer<EventLoopCoroutine> eventLoop = currentLoopStorage->getOrCreate();
    watcherId = eventLoop->createWatcher(event, fd, new YieldCurrentFunctor());
}


void ScopedIoWatcher::start()
{
    QSharedPointer<EventLoopCoroutine> eventLoop = currentLoopStorage->getOrCreate();
    eventLoop->startWatcher(watcherId);
    eventLoop->yield();
}


ScopedIoWatcher::~ScopedIoWatcher()
{
    QSharedPointer<EventLoopCoroutine> eventLoop = currentLoopStorage->getOrCreate();
    eventLoop->removeWatcher(watcherId);
}


class CoroutinePrivate: public QObject
{
public:
    CoroutinePrivate(Coroutine *q, QObject *obj, const char *slot);
    virtual ~CoroutinePrivate();
    void start(quint32 msecs);
    void kill(CoroutineException *e, quint32 msecs);
    void killSync();//raise CoroutineExitException immediately
    void cancelStart();
    bool join();
private:
    void setFinishedEvent();
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
    :q_ptr(q), obj(obj), slot(slot), callbackId(0)
{
    q->finished.addCallback([this] (BaseCoroutine *) {
        setFinishedEvent();
    });
}


CoroutinePrivate::~CoroutinePrivate()
{
}


struct StartCoroutineFunctor: public Functor
{
    StartCoroutineFunctor(CoroutinePrivate *cp)
        :cp(cp) {}
    virtual ~StartCoroutineFunctor() override;
    QPointer<CoroutinePrivate> cp;
    virtual void operator()() override
    {
        if (cp.isNull()) {
            qWarning("startCouroutine is called without coroutine.");
            return;
        }
        cp->callbackId = 0;
        if(cp->q_func()->state() != BaseCoroutine::Initialized) {
//            qDebug("coroutine has been started or stopped.");
            return;
        }
        cp->q_func()->yield();
    }
};


StartCoroutineFunctor::~StartCoroutineFunctor() {}


struct KillCoroutineFunctor: public Functor
{
    KillCoroutineFunctor(CoroutinePrivate *cp, CoroutineException *e)
        :cp(cp), e(e) {}
    virtual ~KillCoroutineFunctor() override;
    QPointer<CoroutinePrivate> cp;
    CoroutineException *e;
    virtual void operator()() override;
};


KillCoroutineFunctor::~KillCoroutineFunctor()
{
    if (e) {
        delete e;
    }
}


void KillCoroutineFunctor::operator()()
{
    if (cp.isNull()) {
        qWarning("killCoroutine is called without coroutine");
        delete e;
        e = nullptr;
        return;
    }
    if (cp->q_func()->state() != BaseCoroutine::Started) {
        delete e;
        e = nullptr;
        return;
    }
    cp->q_func()->raise(e);
    e = nullptr;
}


void CoroutinePrivate::start(quint32 msecs)
{
    if (callbackId > 0) {
        return;
    }
    callbackId = EventLoopCoroutine::get()->callLater(msecs, new StartCoroutineFunctor(this));
}


void CoroutinePrivate::kill(CoroutineException *e, quint32 msecs)
{
    Q_Q(Coroutine);
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if (q->state() == Coroutine::Initialized) {
        if (dynamic_cast<CoroutineExitException *>(e)) {
            if (callbackId > 0) {
                c->cancelCall(callbackId);
                callbackId = 0;
            }
            q->setState(Coroutine::Stopped);
            delete e;
            setFinishedEvent();
        } else {
            if (callbackId == 0) {
                callbackId = c->callLater(msecs, new StartCoroutineFunctor(this));
            }
            c->callLater(msecs, new KillCoroutineFunctor(this, e));
        }
    } else if (q->state() == Coroutine::Stopped || q->state() == Coroutine::Joined) {
        delete e;
    } else if (q->state() == Coroutine::Started){
        c->callLater(msecs, new KillCoroutineFunctor(this, e));
    } else {
        qWarning("invalid state while kiling coroutine.");
        delete e;
    }
}


void CoroutinePrivate::killSync()
{
    Q_Q(Coroutine);
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if (q->state() == Coroutine::Initialized) {
        if (callbackId > 0) {
            c->cancelCall(callbackId);
            callbackId = 0;
        }
        q->setState(Coroutine::Stopped);
        setFinishedEvent();
    } else if (q->state() == Coroutine::Started) {
        q->raise(new CoroutineExitException());
    }
}


void CoroutinePrivate::cancelStart()
{
    Q_Q(Coroutine);
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if (callbackId > 0)
        c->cancelCall(callbackId);
    if (q->state() == Coroutine::Initialized) {
        q->setState(Coroutine::Stopped);
        setFinishedEvent();
    } else if (q->state() == Coroutine::Started) {
        c->callLater(0, new KillCoroutineFunctor(this, new CoroutineExitException()));
    }
    callbackId = 0;
}


void CoroutinePrivate::setFinishedEvent()
{
    finishedEvent.set();
}


bool CoroutinePrivate::join()
{
    Q_Q(Coroutine);

    if (q->state() == BaseCoroutine::Initialized || q->state() == BaseCoroutine::Started) {
        if (!dynamic_cast<Coroutine*>(BaseCoroutine::current())) {
            return EventLoopCoroutine::get()->runUntil(q);
        }
        return finishedEvent.wait();
    } else {
        return true;
    }
}


Coroutine::Coroutine(size_t stackSize)
    :BaseCoroutine(EventLoopCoroutine::get(), stackSize), d_ptr(new CoroutinePrivate(this, nullptr, nullptr))
{
}


Coroutine::Coroutine(QObject *obj, const char *slot, size_t stackSize)
    :BaseCoroutine(EventLoopCoroutine::get(), stackSize), d_ptr(new CoroutinePrivate(this, obj, slot))
{

}


Coroutine::~Coroutine()
{
    delete d_ptr;
}


bool Coroutine::isRunning() const
{
    return state() == BaseCoroutine::Started;
}


bool Coroutine::isFinished() const
{
    const BaseCoroutine::State s = state();
    return s == BaseCoroutine::Stopped || s == BaseCoroutine::Joined;
}


Coroutine *Coroutine::start(quint32 msecs)
{
    Q_D(Coroutine);
    d->start(msecs);
    return this;
}


void Coroutine::kill(CoroutineException *e, quint32 msecs)
{
    Q_D(Coroutine);
    if (!e) {
        d->kill(new CoroutineExitException(), msecs);
    } else {
        d->kill(e, msecs);
    }
}


void Coroutine::killSync()
{
    Q_D(Coroutine);
    d->killSync();
}


void Coroutine::cancelStart()
{
    Q_D(Coroutine);
    d->cancelStart();
}


void Coroutine::run()
{
    Q_D(Coroutine);
    d->callbackId = 0;
    if (d->obj && d->slot) {
        QMetaObject::invokeMethod(d->obj, d->slot);
    }
}


bool Coroutine::join()
{
    Q_D(Coroutine);
    return d->join();
}


Coroutine *Coroutine::current()
{
    BaseCoroutine *c = BaseCoroutine::current();
    return dynamic_cast<Coroutine*>(c);
}


struct QScopedCallLater
{
    QScopedCallLater(int callbackId):callbackId(callbackId){}
    ~QScopedCallLater(){EventLoopCoroutine::get()->cancelCall(callbackId);}
    int callbackId;
};


void Coroutine::msleep(quint32 msecs)
{
    int callbackId = EventLoopCoroutine::get()->callLater(msecs, new YieldCurrentFunctor());
    QScopedCallLater scl(callbackId);
    Q_UNUSED(scl);
    EventLoopCoroutine::get()->yield();
}


struct TimeoutFunctor: public Functor
{
    TimeoutFunctor(Timeout *out, BaseCoroutine *coroutine)
        :out(out), coroutine(coroutine) {}
    virtual ~TimeoutFunctor() override;
    QPointer<Timeout> out;
    QPointer<BaseCoroutine> coroutine;
    virtual void operator()() override;
};


TimeoutFunctor::~TimeoutFunctor() {}


void TimeoutFunctor::operator()()
{
    if (out.isNull() || coroutine.isNull()) {
        qDebug("triggerTimeout is called while timeout or coroutine is deleted.");
        return;
    }
    coroutine->raise(new TimeoutException());
}


TimeoutException::TimeoutException()
{
}


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
    : msecs(static_cast<quint32>((secs > 0.0f ? secs: 0.0f) * 1000)), timeoutId(0)
{
    if (msecs) {
        restart();
    }
}


Timeout::Timeout(quint32 msecs, int)
    : msecs(msecs), timeoutId(0)
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


void Timeout::restart()
{
    if (timeoutId) {
        EventLoopCoroutine::get()->cancelCall(timeoutId);
    }
    timeoutId = EventLoopCoroutine::get()->callLater(msecs, new TimeoutFunctor(this, BaseCoroutine::current()));
}


QTNETWORKNG_NAMESPACE_END


QDebug operator <<(QDebug out, const QTNETWORKNG_NAMESPACE::EventLoopCoroutine& el)
{
    return out << QString::fromLatin1("EventLoopCoroutine(id=%1)").arg(el.id());
}
