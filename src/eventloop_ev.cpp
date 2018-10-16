#include <QtCore/qmap.h>
#include <QtCore/qmutex.h>
#include <QtCore/qqueue.h>
#include <QtCore/qpointer.h>
#include <QtCore/qdebug.h>
#include <stddef.h>
#include "ev/ev.h"
#include "../include/private/eventloop_p.h"


QTNETWORKNG_NAMESPACE_BEGIN

namespace {

struct EvWatcher
{
    virtual ~EvWatcher();
};

struct IoWatcher: public EvWatcher{
    IoWatcher(EventLoopCoroutine::EventType event, qintptr fd);
    virtual ~IoWatcher();

    struct ev_io w;
    Functor *callback;
};

struct TimerWatcher: public EvWatcher
{
    TimerWatcher(int msecs, bool repeat);
    virtual ~TimerWatcher();

    ev_timer w;
    Functor *callback;
};

EvWatcher::~EvWatcher() {}

static void ev_io_callback(struct ev_loop *loop, ev_io *w, int revents)
{
    Q_UNUSED(loop)
    Q_UNUSED(revents)
    IoWatcher *watcher = static_cast<IoWatcher*>(w->data);
    (*watcher->callback)();
}

IoWatcher::IoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
{
    int flags = 0;
    if(event & EventLoopCoroutine::EventType::Read)
        flags |= EV_READ;
    if(event & EventLoopCoroutine::EventType::Write)
        flags |= EV_WRITE;
    ev_io_init(&w, ev_io_callback, fd, flags);
    w.data = this;
}

IoWatcher::~IoWatcher()
{
    delete callback;
}

static void ev_timer_callback(struct ev_loop *loop, ev_timer *w, int revents)
{
    Q_UNUSED(loop)
    Q_UNUSED(revents)
    // TimerWatcher *watcher = reinterpret_cast<TimerWatcher*>(reinterpret_cast<char*>(w) - offsetof(TimerWatcher, e));
    TimerWatcher *watcher = static_cast<TimerWatcher*>(w->data);
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
        ev_timer_init(&w, ev_timer_callback, 0, secs);
    } else {
        ev_timer_init(&w, ev_timer_callback, secs, 0);
    }
    w.data = this;
}

TimerWatcher::~TimerWatcher()
{
    delete callback;
}

}  // anonymous namespace


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
    virtual bool runUntil(BaseCoroutine *coroutine) override;
    virtual void yield() override;
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
    QPointer<BaseCoroutine> loopCoroutine;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
    friend struct TriggerIoWatchersFunctor;
};

EventLoopCoroutinePrivateEv::EventLoopCoroutinePrivateEv(EventLoopCoroutine *parent)
    :EventLoopCoroutinePrivate(parent), loop(0), nextWatcherId(1)
{
    int flags = EVFLAG_NOENV | EVFLAG_FORKCHECK;
    loop = ev_loop_new(flags);
    ev_async_init(&asyncContext, ev_async_callback);
    asyncContext.data = this;
    ev_async_start(loop, &asyncContext);
}


EventLoopCoroutinePrivateEv::~EventLoopCoroutinePrivateEv()
{
    ev_break(loop);
    ev_loop_destroy(loop); // FIXME run() function may not exit, but this situation is rare.
    QMapIterator<int, EvWatcher*> itor(watchers);
    while(itor.hasNext())
    {
        itor.next();
        delete itor.value();
    }
}

void EventLoopCoroutinePrivateEv::run()
{
    try{
        ev_run(loop, 0);
    } catch(...) {
        qFatal("libev eventloop got exception.");
    }
}


int EventLoopCoroutinePrivateEv::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *watcher = new IoWatcher(event, fd);
    watcher->callback = callback;
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::startWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(watcher) {
        ev_io_start(loop, &watcher->w);
    }
}


void EventLoopCoroutinePrivateEv::stopWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(watcher) {
        ev_io_stop(loop, &watcher->w);
    }
}


void EventLoopCoroutinePrivateEv::removeWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if(watcher) {
        ev_io_stop(loop, &watcher->w);
        delete watcher;
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
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(eventloop->watchers.value(watcherId));
        if(watcher) {
            (*watcher->callback)();
        }
    }
};


void EventLoopCoroutinePrivateEv::triggerIoWatchers(qintptr fd)
{
    for(QMap<int, EvWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(itor.value());
        if(watcher && watcher->w.fd == fd) {
            ev_io_stop(loop, &watcher->w);
            callLater(0, new TriggerIoWatchersFunctor(itor.key(), this));
        }
    }
}


int EventLoopCoroutinePrivateEv::callLater(int msecs, Functor *callback)
{
    TimerWatcher *watcher = new TimerWatcher(msecs, false);
    watcher->callback = callback;
    ev_timer_start(loop, &watcher->w);
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::ev_async_callback(struct ev_loop *loop, ev_async *w, int revents)
{
    Q_UNUSED(loop);
    Q_UNUSED(revents);
    //char *baseaddr = reinterpret_cast<char*>(w) - offsetof(EventLoopCoroutinePrivateEv, asyncContext);
    //EventLoopCoroutinePrivateEv *p = reinterpret_cast<EventLoopCoroutinePrivateEv*>(baseaddr); // TODO is p still alive?
    EventLoopCoroutinePrivateEv *p = static_cast<EventLoopCoroutinePrivateEv*>(w->data);
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
    TimerWatcher *watcher = new TimerWatcher(msecs, true);
    watcher->callback = callback;
    ev_timer_start(loop, &watcher->w);
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EventLoopCoroutinePrivateEv::cancelCall(int callbackId)
{
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if(watcher) {
        ev_timer_stop(loop, &watcher->w);
        delete watcher;
    }
}

int EventLoopCoroutinePrivateEv::exitCode()
{
    return 0;
}


bool EventLoopCoroutinePrivateEv::runUntil(BaseCoroutine *coroutine)
{
    if(!loopCoroutine.isNull()) {
        QPointer<BaseCoroutine> current = BaseCoroutine::current();
        std::function<BaseCoroutine*(BaseCoroutine*)> here = [current] (BaseCoroutine *arg) -> BaseCoroutine *  {
            if(!current.isNull()) {
                current->yield();
            }
            return arg;
        };
        coroutine->finished.addCallback(here);
        loopCoroutine->yield();
    } else {
        loopCoroutine = BaseCoroutine::current();
        std::function<BaseCoroutine*(BaseCoroutine*)> exitOneDepth = [this] (BaseCoroutine *arg) -> BaseCoroutine * {
            ev_break(loop, EVBREAK_ONE);
            if(!loopCoroutine.isNull()) {
                loopCoroutine->yield();
            }
            return arg;
        };
        coroutine->finished.addCallback(exitOneDepth);
        ev_run(loop);
        loopCoroutine.clear();
    }
    return true;
}

void EventLoopCoroutinePrivateEv::yield()
{
    Q_Q(EventLoopCoroutine);
    if(!loopCoroutine.isNull()) {
        loopCoroutine->yield();
    } else {
       q->BaseCoroutine::yield();
    }
}

EvEventLoopCoroutine::EvEventLoopCoroutine()
    :EventLoopCoroutine(new EventLoopCoroutinePrivateEv(this))
{

}

QTNETWORKNG_NAMESPACE_END
