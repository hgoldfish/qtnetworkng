#include <QtCore/qmap.h>
#include <QtCore/qeventloop.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qthread.h>
#include <QtCore/qsocketnotifier.h>
#include <QtCore/qdebug.h>
#include <QtCore/qtimer.h>
#include <QtCore/qpointer.h>
#include <QtCore/qcoreevent.h>

#include "../include/eventloop.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct QtWatcher
{
    virtual ~QtWatcher();
};

QtWatcher::~QtWatcher() {}

struct IoWatcher: public QtWatcher
{
    IoWatcher(qintptr fd, EventLoopCoroutine::EventType event, Functor *callback);
    virtual ~IoWatcher();

    EventLoopCoroutine::EventType event;
    QSocketNotifier read;
    QSocketNotifier write;
    Functor *callback;
    qintptr fd;
};

IoWatcher::IoWatcher(qintptr fd, EventLoopCoroutine::EventType event, Functor *callback)
    :event(event), read(fd, QSocketNotifier::Read), write(fd, QSocketNotifier::Write), callback(callback), fd(fd)
{
    read.setEnabled(false);
    write.setEnabled(false);
}

IoWatcher::~IoWatcher()
{
    delete callback;
}

struct TimerWatcher: public QtWatcher
{
    TimerWatcher(int interval, bool singleshot, Functor *callback);
    virtual ~TimerWatcher();

    int timerId;
    int interval;
    bool singleshot;
    Functor *callback;
};

TimerWatcher::TimerWatcher(int interval, bool singleshot, Functor *callback)
    :interval(interval), singleshot(singleshot), callback(callback)
{
}

TimerWatcher::~TimerWatcher()
{
    if(callback) {
        delete callback;
    }
}

class EventLoopCoroutinePrivateQt: public QObject, EventLoopCoroutinePrivate
{
    Q_OBJECT
public:
    EventLoopCoroutinePrivateQt(EventLoopCoroutine* q);
    virtual ~EventLoopCoroutinePrivateQt();
public:
    virtual void run() override;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) override;
    virtual void startWatcher(int watcherId) override;
    virtual void stopWatcher(int watcherId) override;
    virtual void removeWatcher(int watcherId) override;
    virtual void triggerIoWatchers(qintptr fd) override;
    virtual int callLater(int msecs, Functor *callback) override;
    virtual void callLaterThreadSafe(int msecs, Functor *callback) override;
    virtual int callRepeat(int msecs, Functor *callback) override;
    virtual void cancelCall(int callbackId) override;
    virtual int exitCode() override;
    virtual bool runUntil(BaseCoroutine *coroutine) override;
    virtual void yield() override;
private slots:
    void callLaterThreadSafeStub(int msecs, void* callback)
    {
        callLater(msecs, reinterpret_cast<Functor*>(callback));
    }
protected:
    virtual void timerEvent(QTimerEvent *event) override;
private slots:
    void handleIoEvent(int socket);
private:
    QMap<int, QtWatcher*> watchers;
    QMap<int, int> timers;
    int nextWatcherId;
    int qtExitCode;
    QPointer<BaseCoroutine> loopCoroutine;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
    friend struct TriggerIoWatchersArgumentsFunctor;

    static EventLoopCoroutinePrivateQt *getPrivateHelper(EventLoopCoroutine *coroutine)
    {
        EventLoopCoroutinePrivate *d = EventLoopCoroutinePrivate::getPrivateHelper(coroutine);
        return static_cast<EventLoopCoroutinePrivateQt*>(d);
    }

    friend int startQtLoop();
};

EventLoopCoroutinePrivateQt::EventLoopCoroutinePrivateQt(EventLoopCoroutine *q)
    :EventLoopCoroutinePrivate(q), nextWatcherId(1)
{
    setObjectName("EventLoopCoroutinePrivateQt");
}

EventLoopCoroutinePrivateQt::~EventLoopCoroutinePrivateQt()
{
    foreach(QtWatcher *watcher, watchers) {
        delete watcher;
    }
}

void EventLoopCoroutinePrivateQt::run()
{
    QPointer<EventLoopCoroutinePrivateQt> self(this);

    QEventLoop localLoop;
    int result = localLoop.exec();

    if(!self.isNull()) {
        self->qtExitCode = result;
    }
}

void EventLoopCoroutinePrivateQt::handleIoEvent(int socket)
{
    Q_UNUSED(socket)

    QSocketNotifier *n = dynamic_cast<QSocketNotifier*>(sender());
    if(!n) {
        qDebug() << "can not retrieve sender() while handling qt io event.";
        return;
    }

    IoWatcher *w = 0;
    if(n->type() == QSocketNotifier::Read) {
        w = reinterpret_cast<IoWatcher*>(reinterpret_cast<char*>(n) - offsetof(IoWatcher, read));
    } else if (n->type() == QSocketNotifier::Write) {
        w = reinterpret_cast<IoWatcher*>(reinterpret_cast<char*>(n) - offsetof(IoWatcher, write));
    } else {
        qDebug() << "unknown QSocketNotifier type.";
        return;
    }

    (*w->callback)();
}

int EventLoopCoroutinePrivateQt::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *w = new IoWatcher(fd, event, callback);

    connect(&w->read, SIGNAL(activated(int)), SLOT(handleIoEvent(int)), Qt::DirectConnection);
    connect(&w->write, SIGNAL(activated(int)), SLOT(handleIoEvent(int)), Qt::DirectConnection);
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::startWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        if(w->event & EventLoopCoroutine::Read) {
            w->read.setEnabled(true);
        }
        if(w->event & EventLoopCoroutine::Write) {
            w->write.setEnabled(true);
        }
    }
}

void EventLoopCoroutinePrivateQt::stopWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        w->read.setEnabled(false);
        w->write.setEnabled(false);
    }
}

void EventLoopCoroutinePrivateQt::removeWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if(w) {
        w->read.setEnabled(false);
        w->write.setEnabled(false);
        delete w;
    }
}

struct TriggerIoWatchersArgumentsFunctor: public Functor
{
    TriggerIoWatchersArgumentsFunctor(int watcherId, EventLoopCoroutinePrivateQt *eventloop)
        :watcherId(watcherId), eventloop(eventloop) {}
    int watcherId;
    QPointer<EventLoopCoroutinePrivateQt> eventloop;
    virtual void operator() () override
    {
        if(eventloop.isNull()) {
            qWarning("triggerIoWatchers() is called without eventloop.");
            return;
        }
        IoWatcher *w = dynamic_cast<IoWatcher*>(eventloop->watchers.value(watcherId));
        if(w) {
            (*w->callback)();
        }
    }
};


void EventLoopCoroutinePrivateQt::triggerIoWatchers(qintptr fd)
{
    for(QMap<int, QtWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *w = dynamic_cast<IoWatcher*>(itor.value());
        if(w && w->fd == fd) {
            w->read.setEnabled(false);
            w->write.setEnabled(false);
            callLater(0, new TriggerIoWatchersArgumentsFunctor(itor.key(), this));
        }
    }
}

void EventLoopCoroutinePrivateQt::timerEvent(QTimerEvent *event)
{
    if(!timers.contains(event->timerId())) {
        return;
    }

    int watcherId = timers.value(event->timerId());
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.value(watcherId));

    if(!watcher) {
        return;
    }

    bool singleshot = watcher->singleshot;
    (*watcher->callback)();
    if(singleshot) {
        // watcher may be deleted!
        if(watchers.contains(watcherId)) {
            watchers.remove(watcherId);
            timers.remove(event->timerId());
            killTimer(event->timerId());
            delete watcher;
        }
    } else {
        //watcher->timerId = startTimer(watcher->interval);
    }
}


int EventLoopCoroutinePrivateQt::callLater(int msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, true, callback);
    w->timerId = startTimer(msecs, Qt::CoarseTimer);
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::callLaterThreadSafe(int msecs, Functor *callback)
{
    QMetaObject::invokeMethod(this, "callLaterThreadSafeStub", Qt::QueuedConnection, Q_ARG(int, msecs), Q_ARG(void*, callback));
}

int EventLoopCoroutinePrivateQt::callRepeat(int msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, false, callback);
    w->timerId = startTimer(msecs);
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::cancelCall(int callbackId)
{
    TimerWatcher *w = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if(w) {
        timers.remove(w->timerId);
        killTimer(w->timerId);
        delete w;
    }
}

int EventLoopCoroutinePrivateQt::exitCode()
{
    return qtExitCode;
}


bool EventLoopCoroutinePrivateQt::runUntil(BaseCoroutine *coroutine)
{
    if(!loopCoroutine.isNull()) {
        QPointer<BaseCoroutine> current = BaseCoroutine::current();
        std::function<BaseCoroutine*(BaseCoroutine*)> return_here = [current] (BaseCoroutine *arg) -> BaseCoroutine * {
            if(!current.isNull()) {
                current->yield();
            }
            return arg;
        };
        coroutine->finished.addCallback(return_here);
        loopCoroutine->yield();
    } else {
        loopCoroutine = BaseCoroutine::current();
        QSharedPointer<QEventLoop> sub(new QEventLoop());
        std::function<BaseCoroutine*(BaseCoroutine*)> shutdown = [this, sub] (BaseCoroutine *arg) -> BaseCoroutine * {
            sub->exit();
            if(!loopCoroutine.isNull()) {
                loopCoroutine->yield();
            }
            return arg;
        };
        coroutine->finished.addCallback(shutdown);
        sub->exec();
        loopCoroutine.clear();
    }
    return true;
}

void EventLoopCoroutinePrivateQt::yield()
{
    Q_Q(EventLoopCoroutine);
    if(!loopCoroutine.isNull()) {
        loopCoroutine->yield();
    } else {
        q->BaseCoroutine::yield();
    }
}

EventLoopCoroutine::EventLoopCoroutine()
    :BaseCoroutine(BaseCoroutine::current()), d_ptr(new EventLoopCoroutinePrivateQt(this))
{

}


int startQtLoop()
{
    EventLoopCoroutine *coroutine = EventLoopCoroutine::get();
    EventLoopCoroutinePrivateQt *priv = EventLoopCoroutinePrivateQt::getPrivateHelper(coroutine);
    Q_ASSERT(priv);
    Q_ASSERT(priv->loopCoroutine.isNull());
    priv->loopCoroutine = BaseCoroutine::current();
    int result = QCoreApplication::instance()->exec();
    priv->loopCoroutine.clear();
    return result;
}

QTNETWORKNG_NAMESPACE_END

#include "eventloop_qt.moc"
