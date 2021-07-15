#include <QtCore/qmap.h>
#include <QtCore/qmutex.h>
#include <QtCore/qqueue.h>
#include <QtCore/qpointer.h>
#include <QtCore/qdebug.h>
#include <stddef.h>
#include "ev/ev.h"
#include "../include/private/eventloop_p.h"


QTNETWORKNG_NAMESPACE_BEGIN


class EvEventLoopCoroutinePrivate;

extern "C" void qtng__ev_io_callback(struct ev_loop *, ev_io *w, int);
extern "C" void qtng__ev_timer_callback(struct ev_loop *, ev_timer *w, int);
extern "C" void qtng__ev_async_callback(struct ev_loop *loop, ev_async *w, int revents);
extern "C" void qtng__ev_prepare_callback(struct ev_loop *loop, ev_prepare *w, int);


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
    TimerWatcher(quint32 msecs, bool repeat);
    virtual ~TimerWatcher();

    ev_timer w;
    Functor *callback;
    EvEventLoopCoroutinePrivate *parent;
    int watcherId;
};


EvWatcher::~EvWatcher() {}


IoWatcher::IoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
{
    int flags = 0;
    if(event & EventLoopCoroutine::EventType::Read)
        flags |= EV_READ;
    if(event & EventLoopCoroutine::EventType::Write)
        flags |= EV_WRITE;
    ev_io_init(&w, qtng__ev_io_callback, fd, flags);
}


IoWatcher::~IoWatcher()
{
    delete callback;
}


TimerWatcher::TimerWatcher(quint32 msecs, bool repeat)
//    :parent(nullptr), watcherId(0) // value set by caller.
{
    float secs = static_cast<float>(msecs) / 1000.0f;
    if (repeat) {
        ev_timer_init(&w, qtng__ev_timer_callback, secs, secs);
    } else {
        ev_timer_init(&w, qtng__ev_timer_callback, secs, 0);
    }
}


TimerWatcher::~TimerWatcher()
{
    delete callback;
}


class EvEventLoopCoroutinePrivate: public EventLoopCoroutinePrivate
{
public:
    EvEventLoopCoroutinePrivate(EventLoopCoroutine* parent);
    virtual ~EvEventLoopCoroutinePrivate() override;
public:
    virtual void run() override;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) override;
    virtual void startWatcher(int watcherId) override;
    virtual void stopWatcher(int watcherId) override;
    virtual void removeWatcher(int watcherId) override;
    virtual void triggerIoWatchers(qintptr fd) override;
    virtual int callLater(quint32 msecs, Functor *callback) override;
    virtual int callRepeat(quint32 msecs, Functor *callback) override;
    virtual void callLaterThreadSafe(quint32 msecs, Functor *callback) override;
    virtual void cancelCall(int callbackId) override;
    virtual int exitCode() override;
    virtual bool runUntil(BaseCoroutine *coroutine) override;
    virtual void yield() override;
    void doCallLater();
public:
    struct ev_loop *loop;
    QMap<int, EvWatcher*> watchers;
    QList<EvWatcher *> uselessWatchers;
    QMutex mqMutex;
    QQueue<QPair<quint32, Functor*>> callLaterQueue;
    ev_async asyncContext;
    ev_prepare prepareContext;
    QPointer<BaseCoroutine> loopCoroutine;
    int nextWatcherId;
    QAtomicInteger<bool> exitingFlag;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
};


EvEventLoopCoroutinePrivate::EvEventLoopCoroutinePrivate(EventLoopCoroutine *parent)
    : EventLoopCoroutinePrivate(parent), loop(nullptr), nextWatcherId(1)
{
    unsigned int flags = EVFLAG_NOENV;
    loop = ev_loop_new(flags);
    ev_async_init(&asyncContext, qtng__ev_async_callback);
    asyncContext.data = this;
    ev_async_start(loop, &asyncContext);
    ev_prepare_init(&prepareContext, qtng__ev_prepare_callback);
    prepareContext.data = this;
    ev_prepare_start(loop, &prepareContext);
}


EvEventLoopCoroutinePrivate::~EvEventLoopCoroutinePrivate()
{
    mqMutex.lock();
    while (!callLaterQueue.isEmpty()) {
        QPair<quint32, Functor*> item = callLaterQueue.dequeue();
        delete item.second;
    }
    mqMutex.unlock();
    ev_prepare_stop(loop, &prepareContext);
    ev_async_stop(loop, &asyncContext);
    ev_break(loop, EVBREAK_ONE);
    ev_loop_destroy(loop); // FIXME run() function may not exit, but this situation is rare.
    QMapIterator<int, EvWatcher*> itor(watchers);
    while (itor.hasNext()) {
        itor.next();
        delete itor.value();
    }
    for (EvWatcher *watcher: uselessWatchers) {
        delete watcher;
    }
}

extern "C" void qtng__ev_io_callback(struct ev_loop *, ev_io *w, int)
{
    IoWatcher *watcher = static_cast<IoWatcher*>(w->data);
    if (Q_LIKELY(watcher)) {
        (*watcher->callback)();
    }
}


extern "C" void qtng__ev_timer_callback(struct ev_loop *loop, ev_timer *w, int)
{
    // TimerWatcher *watcher = reinterpret_cast<TimerWatcher*>(reinterpret_cast<char*>(w) - offsetof(TimerWatcher, e));
    TimerWatcher *watcher = static_cast<TimerWatcher*>(w->data);
    if (!watcher) {
        return;
    }
    EvEventLoopCoroutinePrivate *parent = watcher->parent;
    if(qFuzzyIsNull(w->repeat)) { // singleshot
        ev_timer_stop(loop, w);
        parent->watchers.remove(watcher->watcherId);
    }
    (*watcher->callback)();
    if (qFuzzyIsNull(w->repeat)) {
        delete watcher;
    }
}


extern "C" void qtng__ev_async_callback(struct ev_loop *, ev_async *w, int)
{
    //char *baseaddr = reinterpret_cast<char*>(w) - offsetof(EvEventLoopCoroutinePrivate, asyncContext);
    //EvEventLoopCoroutinePrivate *p = reinterpret_cast<EvEventLoopCoroutinePrivate*>(baseaddr); // TODO is p still alive?
    EvEventLoopCoroutinePrivate *p = static_cast<EvEventLoopCoroutinePrivate*>(w->data);
    p->doCallLater();
}


extern "C" void qtng__ev_prepare_callback(struct ev_loop *, ev_prepare *w, int)
{
    EvEventLoopCoroutinePrivate *p = static_cast<EvEventLoopCoroutinePrivate*>(w->data);
    while (!p->uselessWatchers.isEmpty()) {
        EvWatcher *watcher = p->uselessWatchers.takeFirst();
        delete watcher;
    }
}


void EvEventLoopCoroutinePrivate::run()
{
    try {
        ev_run(loop, 0);
    } catch(...) {
        qWarning("libev eventloop got exception.");
    }
}


int EvEventLoopCoroutinePrivate::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *watcher = new IoWatcher(event, fd);
    watcher->callback = callback;
    watcher->w.data = watcher;
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EvEventLoopCoroutinePrivate::startWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (watcher) {
        ev_io_start(loop, &watcher->w);
    }
}


void EvEventLoopCoroutinePrivate::stopWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (watcher) {
        ev_io_stop(loop, &watcher->w);
    }
}


void EvEventLoopCoroutinePrivate::removeWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if (watcher) {
        ev_io_stop(loop, &watcher->w);
        watcher->w.data = nullptr;
        uselessWatchers.append(watcher);
    }
}


struct TriggerIoWatchersFunctor: public Functor
{
    TriggerIoWatchersFunctor(int watcherId, EvEventLoopCoroutinePrivate *eventloop)
        :eventloop(eventloop), watcherId(watcherId) {}
    EvEventLoopCoroutinePrivate *eventloop;
    int watcherId;
    virtual void operator()() override
    {
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(eventloop->watchers.value(watcherId));
        if (watcher) {
            (*watcher->callback)();
        }
    }
};


void EvEventLoopCoroutinePrivate::triggerIoWatchers(qintptr fd)
{
    for (QMap<int, EvWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(itor.value());
        if (watcher && watcher->w.fd == fd) {
            ev_io_stop(loop, &watcher->w);
            callLater(0, new TriggerIoWatchersFunctor(itor.key(), this));
        }
    }
}


int EvEventLoopCoroutinePrivate::callLater(quint32 msecs, Functor *callback)
{
    TimerWatcher *watcher = new TimerWatcher(msecs, false);
    watcher->callback = callback;
    watcher->parent = this;
    watcher->watcherId = nextWatcherId;
    watcher->w.data = watcher;
    ev_timer_start(loop, &watcher->w);
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EvEventLoopCoroutinePrivate::doCallLater()
{
    QMutexLocker locker(&mqMutex);
    while (!callLaterQueue.isEmpty()) {
        QPair<quint32, Functor*> item = callLaterQueue.dequeue();
        callLater(item.first, item.second);
    }
}


void EvEventLoopCoroutinePrivate::callLaterThreadSafe(quint32 msecs, Functor *callback)
{
    QMutexLocker locker(&mqMutex);
    callLaterQueue.enqueue(qMakePair(msecs, callback));
    if (!ev_async_pending(&asyncContext)) {
        ev_async_send(loop, &asyncContext);
    }
}


int EvEventLoopCoroutinePrivate::callRepeat(quint32 msecs, Functor *callback)
{
    TimerWatcher *watcher = new TimerWatcher(msecs, true);
    watcher->callback = callback;
    watcher->parent = this;
    watcher->watcherId = 0;
    ev_timer_start(loop, &watcher->w);
    watchers.insert(nextWatcherId, watcher);
    return nextWatcherId++;
}


void EvEventLoopCoroutinePrivate::cancelCall(int callbackId)
{
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if (watcher) {
        ev_timer_stop(loop, &watcher->w);
        watcher->w.data = nullptr;
        uselessWatchers.append(watcher);
    }
}


int EvEventLoopCoroutinePrivate::exitCode()
{
    return 0;
}


bool EvEventLoopCoroutinePrivate::runUntil(BaseCoroutine *coroutine)
{
    QPointer<BaseCoroutine> current = BaseCoroutine::current();
    if (!loopCoroutine.isNull() && loopCoroutine != current) {
        Deferred<BaseCoroutine*>::Callback here = [current] (BaseCoroutine *) {
            if (!current.isNull()) {
                current->yield();
            }
        };
        coroutine->finished.addCallback(here);
        loopCoroutine->yield();
    } else {
        QPointer<BaseCoroutine> old = loopCoroutine;
        loopCoroutine = current;
        Deferred<BaseCoroutine*>::Callback exitOneDepth = [this] (BaseCoroutine *) {
            ev_break(loop, EVBREAK_ONE);
            if (!loopCoroutine.isNull()) {
                loopCoroutine->yield();
            }
        };
        coroutine->finished.addCallback(exitOneDepth);
        ev_run(loop, 0);
        loopCoroutine = old;
    }
    return true;
}


void EvEventLoopCoroutinePrivate::yield()
{
    Q_Q(EventLoopCoroutine);
    if (!loopCoroutine.isNull()) {
        loopCoroutine->yield();
    } else {
       q->BaseCoroutine::yield();
    }
}


EvEventLoopCoroutine::EvEventLoopCoroutine()
    :EventLoopCoroutine(new EvEventLoopCoroutinePrivate(this))
{

}

QTNETWORKNG_NAMESPACE_END
