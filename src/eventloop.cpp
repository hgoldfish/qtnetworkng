#include <QtCore/QDebug>
#include <QtCore/QPointer>
#include <QtCore/QObject>
#include "../include/eventloop.h"
#include "../include/locks.h"
#ifdef Q_OS_UNIX
#include <signal.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN


Functor::~Functor()
{}

Arguments::~Arguments()
{
}

void DoNothingFunctor::operator ()()
{

}

CallbackFunctor::CallbackFunctor(Callback callback, Arguments *args)
    :callback(callback), args(args)
{}

CallbackFunctor::~CallbackFunctor()
{
    delete args;
}

void CallbackFunctor::operator ()()
{
    callback(args);
}

YieldCurrentFunctor::YieldCurrentFunctor()
{
    coroutine = BaseCoroutine::current();
}

void YieldCurrentFunctor::operator ()()
{
    if(coroutine.isNull()) {
        qDebug() << "coroutine is deleted while YieldCurrentFunctor called.";
        return;
    }
    try {
        coroutine->yield();
    } catch(CoroutineException &e) {
        qDebug() << "do not send exception to event loop, just delete event loop:" << e.what();
    }
}


// 开始写 CurrentLoopStorage 的定义
class CurrentLoopStorage
{
public:
    EventLoopCoroutine* get();
    void set(EventLoopCoroutine* loop);
    void clean();
private:
    struct CurrentLoop
    {
        EventLoopCoroutine *value;
    };
    QThreadStorage<CurrentLoop> storage;
};

CurrentLoopStorage &currentLoop();


// 开始写 EventLoopCoroutinePrivate 的实现代码。

EventLoopCoroutinePrivate::EventLoopCoroutinePrivate(EventLoopCoroutine *q)
    :q_ptr(q){}

EventLoopCoroutinePrivate::~EventLoopCoroutinePrivate(){}


// 开始写 EventLoopCoroutine 的实现代码。

EventLoopCoroutine::~EventLoopCoroutine()
{
    delete d_ptr;
}

EventLoopCoroutine *EventLoopCoroutine::get()
{
    return currentLoop().get();
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

int EventLoopCoroutine::callLater(int msecs, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    return d->callLater(msecs, callback);
}


void EventLoopCoroutine::callLaterThreadSafe(int msecs, Functor *callback)
{
    Q_D(EventLoopCoroutine);
    d->callLaterThreadSafe(msecs, callback);
}


int EventLoopCoroutine::callRepeat(int msecs, Functor *callback)
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

// 开始写 CurrentLoopStorage 的实现

EventLoopCoroutine* CurrentLoopStorage::get()
{
    if(storage.hasLocalData()) {
        return storage.localData().value;
    }
    EventLoopCoroutine *eventLoop = new EventLoopCoroutine();
    eventLoop->setObjectName("eventloop_coroutine");
    storage.setLocalData(CurrentLoop());
    storage.localData().value = eventLoop;
    return eventLoop;
}

void CurrentLoopStorage::set(EventLoopCoroutine *loop)
{
    storage.localData().value = loop;
}

void CurrentLoopStorage::clean()
{
    if(storage.hasLocalData()) {
        delete storage.localData().value;
    }
}

CurrentLoopStorage &currentLoop()
{
    static CurrentLoopStorage storage;
    return storage;
}

// 开始写 ScopedWatcher 的实现

ScopedIoWatcher::ScopedIoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
{
    EventLoopCoroutine *eventLoop = currentLoop().get();
    watcherId = eventLoop->createWatcher(event, fd, new YieldCurrentFunctor());
}

void ScopedIoWatcher::start()
{
    EventLoopCoroutine *eventLoop = currentLoop().get();
    eventLoop->startWatcher(watcherId);
    eventLoop->yield();
}

ScopedIoWatcher::~ScopedIoWatcher()
{
    EventLoopCoroutine *eventLoop = currentLoop().get();
    eventLoop->removeWatcher(watcherId);
}

// 开始写 CoroutinePrivate 的定义

class CoroutinePrivate: public QObject
{
    Q_OBJECT
public:
    CoroutinePrivate(Coroutine *q, QObject *obj, const char *slot);
    virtual ~CoroutinePrivate();
    void start(int msecs);
    void kill(CoroutineException *e, int msecs);
    void cancelStart();
    bool join();
private slots:
    void setFinishedEvent();
private:
    QObject * const obj;
    const char * const slot;
    int callbackId;
    Coroutine * const q_ptr;
    Event finishedEvent;
    Q_DECLARE_PUBLIC(Coroutine)
    friend void startCoroutine(const Arguments *args);
    friend void killCoroutine(const Arguments *args);
};

// 开始写 CoroutinePrivate的实现

CoroutinePrivate::CoroutinePrivate(Coroutine *q, QObject *obj, const char *slot)
    :obj(obj), slot(slot), callbackId(0), q_ptr(q)
{
    connect(q_ptr, SIGNAL(finished()), SLOT(setFinishedEvent()), Qt::DirectConnection);
}

CoroutinePrivate::~CoroutinePrivate()
{
}

struct StartCoroutineArguments: public Arguments
{
    QPointer<CoroutinePrivate> cp;
};

void startCoroutine(const Arguments *args)
{
    const StartCoroutineArguments *cargs = dynamic_cast<const StartCoroutineArguments*>(args);
    if(!cargs || cargs->cp.isNull()) {
        qWarning("startCouroutine is called without coroutine.");
        return;
    }
    if(cargs->cp->q_func()->state() != BaseCoroutine::Initialized) {
        qDebug("coroutine has been started or stopped.");
        return;
    }
    cargs->cp->callbackId = 0;
    cargs->cp->q_func()->yield();
}

struct KillCoroutineArguments: public Arguments
{
    QPointer<CoroutinePrivate> cp;
    CoroutineException *e;
};

void killCoroutine(const Arguments *args)
{
    const KillCoroutineArguments *cargs = dynamic_cast<const KillCoroutineArguments*>(args);
    if(!cargs || cargs->cp.isNull()) {
        qWarning("killCoroutine is called without coroutine");
        return;
    }
    if(cargs->cp->q_func()->state() != BaseCoroutine::Started) {
//        qDebug("killCoroutine try to kill a non-running coroutine.");
        return;
    }
    cargs->cp->q_func()->raise(cargs->e);
}

void CoroutinePrivate::start(int msecs)
{
    if(callbackId > 0)
        return;
    StartCoroutineArguments *cargs = new StartCoroutineArguments();
    cargs->cp = this;
    callbackId = EventLoopCoroutine::get()->callLater(msecs, new CallbackFunctor(startCoroutine, cargs));
}


void CoroutinePrivate::kill(CoroutineException *e, int msecs)
{
    Q_Q(Coroutine);
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if(q->state() == Coroutine::Initialized) {
        qDebug("coroutine is not started yet, will be starting now. would you check isAlive()?");
    } else if(q->state() == Coroutine::Stopped || q->state() == Coroutine::Joined) {
        qWarning("coroutine was dead. do you check isAlive()?");
        return;
    } else if(q->state() == Coroutine::Started){
        KillCoroutineArguments *cargs = new KillCoroutineArguments();
        cargs->cp = this;
        cargs->e = e;
        c->callLater(msecs, new CallbackFunctor(killCoroutine, cargs));
    } else {
        qFatal("invalid state while kiling coroutine.");
    }
}

void CoroutinePrivate::cancelStart()
{
    Q_Q(Coroutine);
    EventLoopCoroutine *c = EventLoopCoroutine::get();
    if(callbackId > 0)
        c->cancelCall(callbackId);
    if(q->state() == Coroutine::Initialized) {
        q->setState(Coroutine::Stopped);
        setFinishedEvent();
    }
    else if(q->state() == Coroutine::Started) {
        KillCoroutineArguments *cargs = new KillCoroutineArguments();
        cargs->cp = this;
        cargs->e = new CoroutineExitException();
        c->callLater(0, new CallbackFunctor(killCoroutine, cargs));
    }
    callbackId = 0;
}

void CoroutinePrivate::setFinishedEvent()
{
    finishedEvent.set();
}

bool CoroutinePrivate::join()
{
    Q_Q(const Coroutine);

    if(q->state() == BaseCoroutine::Initialized || q->state() == BaseCoroutine::Started) {
        return finishedEvent.wait();
    } else {
        return true;
    }
}

// 开始写 Coroutine 的实现

Coroutine::Coroutine(size_t stackSize)
    :BaseCoroutine(EventLoopCoroutine::get(), stackSize), d_ptr(new CoroutinePrivate(this, 0, 0))
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

bool Coroutine::isActive() const
{
    return state() == BaseCoroutine::Started;
}

Coroutine *Coroutine::start(int msecs)
{
    Q_D(Coroutine);
    d->start(msecs);
    return this;
}

void Coroutine::kill(CoroutineException *e, int msecs)
{
    Q_D(Coroutine);
    d->kill(e, msecs);
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
    if(d->obj && d->slot) {
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

void Coroutine::sleep(int msecs)
{
    int callbackId = EventLoopCoroutine::get()->callLater(msecs, new YieldCurrentFunctor());
    QScopedCallLater scl(callbackId);
    Q_UNUSED(scl);
    EventLoopCoroutine::get()->yield();
}

struct TimeoutArguments:public Arguments
{
    QPointer<Timeout> out;
    QPointer<BaseCoroutine> coroutine;
};

void triggerTimeout(const Arguments *args)
{
    const TimeoutArguments* targs = dynamic_cast<const TimeoutArguments*>(args);
    if(!targs) {
        qWarning("triggerTimeout is called without arguments.");
        return;
    }
    if(targs->out.isNull() || targs->coroutine.isNull()) {
        qDebug("triggerTimeout is called while timeout or coroutine is deleted.");
        return;
    }
    targs->coroutine->raise(new TimeoutException());
}

TimeoutException::TimeoutException()
{
}

QString TimeoutException::what() const throw()
{
    return QString::fromLatin1("coroutine had set timeout.");
}

void TimeoutException::raise()
{
    throw *this;
}

Timeout::Timeout(int msecs)
    :msecs(msecs), timeoutId(0)
{
    restart();
}

Timeout::~Timeout()
{
    if(timeoutId)
        EventLoopCoroutine::get()->cancelCall(timeoutId);
}

void Timeout::restart()
{
    if(timeoutId)
        EventLoopCoroutine::get()->cancelCall(timeoutId);
    TimeoutArguments *targs = new TimeoutArguments;
    targs->coroutine = BaseCoroutine::current();
    targs->out = this;
    timeoutId = EventLoopCoroutine::get()->callLater(msecs, new CallbackFunctor(triggerTimeout, targs));
}

#ifdef Q_OS_UNIX

QPointer<EventLoopCoroutine> mainLoop;
QPointer<BaseCoroutine> mainCoroutine;

struct ExitLoopFunctor: public Functor
{
    virtual void operator ()()
    {
        if(mainCoroutine.isNull())
            return;
        mainCoroutine->yield();
    }
};

void handle_sigint(int sig)
{
    Q_UNUSED(sig)
    qDebug() << "terminate event loop.";
    if(mainLoop.isNull()) {
        return;
    }
    mainLoop->callLaterThreadSafe(0, new ExitLoopFunctor());
}

#endif

int start_application()
{
#ifdef Q_OS_UNIX
    mainLoop = QPointer<EventLoopCoroutine>(currentLoop().get());
    mainCoroutine = BaseCoroutine::current();
    auto old_handler = signal(SIGINT, handle_sigint);
    currentLoop().get()->yield();
    signal(SIGINT, old_handler);
#else
    currentLoop().get()->yield();
#endif
    return currentLoop().get()->exitCode();
}

QTNETWORKNG_NAMESPACE_END

#include "eventloop.moc"
