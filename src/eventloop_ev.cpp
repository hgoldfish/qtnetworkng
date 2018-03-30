#include <ev.h>
#include <QtCore/QMap>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QQueue>
#include <QtCore/QPointer>
#include <QtCore/QDebug>
#include <stddef.h>
#include "../include/eventloop.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct EvWatcher
{
    virtual ~EvWatcher();
};


EvWatcher::~EvWatcher() {}


struct IoWatcher: public EvWatcher{
    IoWatcher(EventLoopCoroutine::EventType event, qintptr fd);
    virtual ~IoWatcher();

    struct ev_io e;
    Functor *callback;
};


static void ev_io_callback(struct ev_loop *loop, ev_io *w, int revents)
{
    Q_UNUSED(loop)
    Q_UNUSED(revents)
    IoWatcher *watcher = reinterpret_cast<IoWatcher*>(reinterpret_cast<char*>(w) - offsetof(IoWatcher, e));
    (*watcher->callback)();
}


IoWatcher::IoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
{
    int flags = 0;
    if(event & EventLoopCoroutine::EventType::Read)
        flags |= EV_READ;
    if(event & EventLoopCoroutine::EventType::Write)
        flags |= EV_WRITE;
    ev_io_init(&e, ev_io_callback, fd, flags);
}


IoWatcher::~IoWatcher()
{
    delete callback;
}


struct TimerWatcher: public EvWatcher
{
    TimerWatcher(int msecs, bool repeat);
    virtual ~TimerWatcher();

    ev_timer e;
    Functor *callback;
};


static void ev_timer_callback(struct ev_loop *loop, ev_timer *w, int revents)
{
    Q_UNUSED(loop)
    Q_UNUSED(revents)
    TimerWatcher *watcher = reinterpret_cast<TimerWatcher*>(reinterpret_cast<char*>(w) - offsetof(TimerWatcher, e));
    if(!w->repeat) { // ev_timer_again?
        ev_timer_stop(loop, w);
    }
    (*watcher->callback)();
    // should i remove the wathcer?
}


TimerWatcher::TimerWatcher(int msecs, bool repeat)
{
    float secs = msecs / 1000.0;
    if(repeat) {
        ev_timer_init(&e, ev_timer_callback, 0, secs);
    } else {
        ev_timer_init(&e, ev_timer_callback, secs, 0);
    }
}

TimerWatcher::~TimerWatcher()
{
    delete callback;
}


class EventLoopCoroutinePrivateEv: public EventLoopCoroutinePrivate
{
public:
    EventLoopCoroutinePrivateEv(EventLoopCoroutine* parent);
    virtual ~EventLoopCoroutinePrivateEv();
public:
    virtual void run() override;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) override;
    virtual void startWatcher(int watcherId) override;
    virtual void stopWatcher(int watcherId) override;
    virtual void removeWatcher(int watcherId) override;
    virtual void triggerIoWatchers(qintptr fd) override;
    virtual int callLater(int msecs, Functor *callback) override;
    virtual int callRepeat(int msecs, Functor *callback) override;
    virtual void cancelCall(int callbackId) override;
    virtual void callLaterThreadSafe(int msecs, Functor *callback) override;
    virtual int exitCode() override;
    virtual void runUntil(BaseCoroutine *coroutine) override;
    void doCallLater();
private:
    static void ev_async_callback(struct ev_loop *loop, ev_async *w, int revents);
private:
    struct ev_loop *loop;
    QMap<int, EvWatcher*> watchers;
    int nextWatcherId;
    QMutex mqMutex;
    QQueue<QPair<int, Functor*>> callLaterQueue;
    ev_async asyncContext;
    QAtomicInteger<bool> exitingFlag;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
    friend struct TriggerIoWatchersFunctor;
};

EventLoopCoroutinePrivateEv::EventLoopCoroutinePrivateEv(EventLoopCoroutine *parent)
    :EventLoopCoroutinePrivate(parent), loop(0), nextWatcherId(1)
{
    int flags = EVFLAG_NOENV | EVFLAG_FORKCHECK;
    loop = ev_loop_new(flags);
    ev_async_init(&asyncContext, ev_async_callback);
    ev_async_start(loop, &asyncContext);
}


EventLoopCoroutinePrivateEv::~EventLoopCoroutinePrivateEv()
{
    ev_break(loop);
    QMapIterator<int, EvWatcher*> itor(watchers);
    while(itor.hasNext())
    {
        itor.next();
        delete itor.value();
    }
}

void EventLoopCoroutinePrivateEv::run()
{
    volatile struct ev_loop *localLoop = loop;
    try{
        ev_run((struct ev_loop *)localLoop, 0);
        ev_loop_destroy((struct ev_loop *)localLoop);
    } catch(...) {
        qFatal("libev eventloop got exception.");
    }
}


int EventLoopCoroutinePrivateEv::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *w = new IoWatcher(event, fd);
    w->callback = callback;
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::startWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        ev_io_start(loop, &w->e);
    }
}


void EventLoopCoroutinePrivateEv::stopWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        ev_io_stop(loop, &w->e);
    }
}


void EventLoopCoroutinePrivateEv::removeWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if(w) {
        ev_io_stop(loop, &w->e);
        delete w;
    }
}

struct TriggerIoWatchersFunctor: public Functor
{
    TriggerIoWatchersFunctor(int watcherId, EventLoopCoroutinePrivateEv *eventloop)
        :watcherId(watcherId), eventloop(eventloop) {}
    int watcherId;
    EventLoopCoroutinePrivateEv *eventloop;
    virtual void operator()() override
    {
        IoWatcher *w = dynamic_cast<IoWatcher*>(eventloop->watchers.value(watcherId));
        if(w) {
            (*w->callback)();
        }
    }
};


void EventLoopCoroutinePrivateEv::triggerIoWatchers(qintptr fd)
{
    for(QMap<int, EvWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *w = dynamic_cast<IoWatcher*>(itor.value());
        if(w && w->e.fd == fd) {
            ev_io_stop(loop, &w->e);
            callLater(0, new TriggerIoWatchersFunctor(itor.key(), this));
        }
    }
}


int EventLoopCoroutinePrivateEv::callLater(int msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, false);
    w->callback = callback;
    ev_timer_start(loop, &w->e);
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::ev_async_callback(struct ev_loop *loop, ev_async *w, int revents)
{
    Q_UNUSED(loop);
    Q_UNUSED(revents);
    char *baseaddr = reinterpret_cast<char*>(w) - offsetof(EventLoopCoroutinePrivateEv, asyncContext);
    EventLoopCoroutinePrivateEv *p = reinterpret_cast<EventLoopCoroutinePrivateEv*>(baseaddr); // TODO is p still alive?
    p->doCallLater();
}


void EventLoopCoroutinePrivateEv::doCallLater()
{
    QMutexLocker locker(&mqMutex);
    while(!callLaterQueue.isEmpty()) {
        QPair<int, Functor*> item = callLaterQueue.dequeue();
        callLater(item.first, item.second);
    }
}


void EventLoopCoroutinePrivateEv::callLaterThreadSafe(int msecs, Functor *callback)
{
    QMutexLocker locker(&mqMutex);
    callLaterQueue.enqueue(qMakePair(msecs, callback));
    if(!ev_async_pending(&asyncContext)) {
        ev_async_send(loop, &asyncContext);
    }
}


int EventLoopCoroutinePrivateEv::callRepeat(int msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, true);
    w->callback = callback;
    ev_timer_start(loop, &w->e);
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::cancelCall(int callbackId)
{
    TimerWatcher *w = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if(w) {
        ev_timer_stop(loop, &w->e);
        delete w;
    }
}

int EventLoopCoroutinePrivateEv::exitCode()
{
    return 0;
}


void EventLoopCoroutinePrivateEv::runUntil(BaseCoroutine *coroutine)
{
    QPointer<BaseCoroutine> loopCoroutine = BaseCoroutine::current();
    std::function<BaseCoroutine*(BaseCoroutine*)> exitOneDepth = [this, loopCoroutine] (BaseCoroutine *arg) -> BaseCoroutine * {
        ev_break(loop, EVBREAK_ONE);
        if(!loopCoroutine.isNull()) {
            loopCoroutine->yield();
        }
        return arg;
    };
    coroutine->finished.addCallback(exitOneDepth);
    ev_run(loop);
}

EventLoopCoroutine::EventLoopCoroutine()
    :BaseCoroutine(BaseCoroutine::current()), d_ptr(new EventLoopCoroutinePrivateEv(this))
{

}

QTNETWORKNG_NAMESPACE_END
