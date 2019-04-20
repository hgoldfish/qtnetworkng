#include <QtCore/qmap.h>
#include <QtCore/qeventloop.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qthread.h>
#include <QtCore/qsocketnotifier.h>
#include <QtCore/qdebug.h>
#include <QtCore/qtimer.h>
#include <QtCore/qpointer.h>
#include <QtCore/qcoreevent.h>

#include "../include/private/eventloop_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

namespace {

struct QtWatcher
{
    virtual ~QtWatcher();
};

struct IoWatcher: public QtWatcher
{
    IoWatcher(qintptr fd, EventLoopCoroutine::EventType event, Functor *callback);
    virtual ~IoWatcher();

    QSharedPointer<QSocketNotifier> notifier;
    Functor *callback;
    qintptr fd;
    EventLoopCoroutine::EventType event;
};

struct TimerWatcher: public QtWatcher
{
    TimerWatcher(quint32 interval, bool singleshot, Functor *callback);
    virtual ~TimerWatcher();

    Functor *callback;
    int timerId;
    quint32 interval;
    bool singleshot;
};

QtWatcher::~QtWatcher() {}

IoWatcher::IoWatcher(qintptr fd, EventLoopCoroutine::EventType event, Functor *callback)
    :callback(callback), fd(fd), event(event)
{
}

IoWatcher::~IoWatcher()
{
    delete callback;
}

TimerWatcher::TimerWatcher(quint32 interval, bool singleshot, Functor *callback)
    :callback(callback), interval(interval), singleshot(singleshot)
{
}

TimerWatcher::~TimerWatcher()
{
    if(callback) {
        delete callback;
    }
}

}  // anonymous namespace

class EventLoopCoroutinePrivateQtHelper;
class EventLoopCoroutinePrivateQt: public EventLoopCoroutinePrivate
{
public:
    EventLoopCoroutinePrivateQt(EventLoopCoroutine* q);
    virtual ~EventLoopCoroutinePrivateQt() override;
public:
    virtual void run() override;
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback) override;
    virtual void startWatcher(int watcherId) override;
    virtual void stopWatcher(int watcherId) override;
    virtual void removeWatcher(int watcherId) override;
    virtual void triggerIoWatchers(qintptr fd) override;
    virtual int callLater(quint32 msecs, Functor *callback) override;
    virtual void callLaterThreadSafe(quint32 msecs, Functor *callback) override;
    virtual int callRepeat(quint32 msecs, Functor *callback) override;
    virtual void cancelCall(int callbackId) override;
    virtual int exitCode() override;
    virtual bool runUntil(BaseCoroutine *coroutine) override;
    virtual void yield() override;
public:
    void timerEvent(QTimerEvent *event);
    void handleIoEvent(int socket, QSocketNotifier *n);
private:
    QMap<int, QtWatcher*> watchers;
    QMap<int, int> timers;
    int nextWatcherId;
    int qtExitCode;
    QPointer<BaseCoroutine> loopCoroutine;
    EventLoopCoroutinePrivateQtHelper *helper;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)

    friend struct TriggerIoWatchersArgumentsFunctor;

    static EventLoopCoroutinePrivateQt *getPrivateHelper(EventLoopCoroutine *coroutine)
    {
        EventLoopCoroutinePrivate *d = EventLoopCoroutinePrivate::getPrivateHelper(coroutine);
        return static_cast<EventLoopCoroutinePrivateQt*>(d);
    }

    friend int startQtLoop();
};


class EventLoopCoroutinePrivateQtHelper: public QObject
{
    Q_OBJECT
public:
    EventLoopCoroutinePrivateQtHelper(EventLoopCoroutinePrivateQt *parent)
        :parent(parent) {}
public slots:
    virtual void timerEvent(QTimerEvent *event) override
    {
        parent->timerEvent(event);
    }

    void callLaterThreadSafeStub(quint32 msecs, void* callback)
    {
        parent->callLater(msecs, static_cast<Functor*>(callback));
    }

    void handleIoEvent(int socket)
    {
        QSocketNotifier *n = dynamic_cast<QSocketNotifier*>(sender());
        parent->handleIoEvent(socket, n);
    }
private:
    EventLoopCoroutinePrivateQt * const parent;
};


EventLoopCoroutinePrivateQt::EventLoopCoroutinePrivateQt(EventLoopCoroutine *q)
    :EventLoopCoroutinePrivate(q), nextWatcherId(1), helper(new EventLoopCoroutinePrivateQtHelper(this))
{
}

EventLoopCoroutinePrivateQt::~EventLoopCoroutinePrivateQt()
{
    for (QtWatcher *watcher: watchers) {
        delete watcher;
    }
    delete helper;
}

void EventLoopCoroutinePrivateQt::run()
{
    QEventLoop localLoop;
    int result = localLoop.exec();
    this->qtExitCode = result;
}

void EventLoopCoroutinePrivateQt::handleIoEvent(int socket, QSocketNotifier *n)
{
    Q_UNUSED(socket)

    if(!n) {
        qDebug() << "can not retrieve sender() while handling qt io event.";
        return;
    }

    IoWatcher *w = static_cast<IoWatcher*>(n->property("parent").value<void*>());
    (*w->callback)();
}

int EventLoopCoroutinePrivateQt::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *w = new IoWatcher(fd, event, callback);
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::startWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        if(w->event & EventLoopCoroutine::Read) {
            if (w->notifier.isNull()) {
                w->notifier.reset(new QSocketNotifier(w->fd, QSocketNotifier::Read));
                w->notifier->setProperty("parent", QVariant::fromValue(static_cast<void*>(w)));
                QObject::connect(w->notifier.data(), SIGNAL(activated(int)), this->helper, SLOT(handleIoEvent(int)), Qt::DirectConnection);
            }
            w->notifier->setEnabled(true);
        } else if(w->event & EventLoopCoroutine::Write) {
            if (w->notifier.isNull()) {
                w->notifier.reset(new QSocketNotifier(w->fd, QSocketNotifier::Write));
                w->notifier->setProperty("parent", QVariant::fromValue(static_cast<void*>(w)));
                QObject::connect(w->notifier.data(), SIGNAL(activated(int)), this->helper, SLOT(handleIoEvent(int)), Qt::DirectConnection);
            }
            w->notifier->setEnabled(true);
        }
    }
}

void EventLoopCoroutinePrivateQt::stopWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w && !w->notifier.isNull()) {
        w->notifier->setEnabled(false);
    }
}

void EventLoopCoroutinePrivateQt::removeWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if(w) {
        delete w;
    }
}

struct TriggerIoWatchersArgumentsFunctor: public Functor
{
    TriggerIoWatchersArgumentsFunctor(int watcherId, EventLoopCoroutine *eventloop)
        :eventloop(eventloop), watcherId(watcherId) {}
    virtual ~TriggerIoWatchersArgumentsFunctor() override;
    QPointer<EventLoopCoroutine> eventloop;
    int watcherId;
    virtual void operator() () override;
};

TriggerIoWatchersArgumentsFunctor::~TriggerIoWatchersArgumentsFunctor() {}

void TriggerIoWatchersArgumentsFunctor::operator()()
{
    if(eventloop.isNull()) {
        qWarning("triggerIoWatchers() is called without eventloop.");
        return;
    }
    EventLoopCoroutinePrivateQt *d = EventLoopCoroutinePrivateQt::getPrivateHelper(eventloop.data());
    IoWatcher *w = dynamic_cast<IoWatcher*>(d->watchers.value(watcherId));
    if(w) {
        (*w->callback)();
    }
}


void EventLoopCoroutinePrivateQt::triggerIoWatchers(qintptr fd)
{
    Q_Q(EventLoopCoroutine);
    for (QMap<int, QtWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *w = dynamic_cast<IoWatcher*>(itor.value());
        if(w && w->fd == fd) {
            if (!w->notifier.isNull()) {
                w->notifier->setEnabled(false);
            }
            callLater(0, new TriggerIoWatchersArgumentsFunctor(itor.key(), q));
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
            helper->killTimer(event->timerId());
            delete watcher;
        }
    } else {
        //watcher->timerId = startTimer(watcher->interval);
    }
}


int EventLoopCoroutinePrivateQt::callLater(quint32 msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, true, callback);
    w->timerId = helper->startTimer(static_cast<int>(msecs), Qt::PreciseTimer);
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::callLaterThreadSafe(quint32 msecs, Functor *callback)
{
    QMetaObject::invokeMethod(this->helper, "callLaterThreadSafeStub", Qt::QueuedConnection, Q_ARG(quint32, msecs), Q_ARG(void*, callback));
}

int EventLoopCoroutinePrivateQt::callRepeat(quint32 msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, false, callback);
    w->timerId = helper->startTimer(static_cast<int>(msecs));
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::cancelCall(int callbackId)
{
    TimerWatcher *w = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if(w) {
        timers.remove(w->timerId);
        helper->killTimer(w->timerId);
        delete w;
    }
}

int EventLoopCoroutinePrivateQt::exitCode()
{
    return qtExitCode;
}


bool EventLoopCoroutinePrivateQt::runUntil(BaseCoroutine *coroutine)
{
    QPointer<BaseCoroutine> current = BaseCoroutine::current();
    if(!loopCoroutine.isNull() && loopCoroutine != current ) {
        Deferred<BaseCoroutine*>::Callback return_here = [current] (BaseCoroutine *) {
            if(!current.isNull()) {
                current->yield();
            }
        };
        coroutine->finished.addCallback(return_here);
        loopCoroutine->yield();
    } else {
        QPointer<BaseCoroutine> old = loopCoroutine;
        loopCoroutine = current;
        QSharedPointer<QEventLoop> sub(new QEventLoop());
        Deferred<BaseCoroutine*>::Callback shutdown = [this, sub] (BaseCoroutine *) {
            sub->exit();
            if(!loopCoroutine.isNull()) {
                loopCoroutine->yield();
            }
        };
        coroutine->finished.addCallback(shutdown);
        sub->exec();
        loopCoroutine = old;
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

QtEventLoopCoroutine::QtEventLoopCoroutine()
    :EventLoopCoroutine(new EventLoopCoroutinePrivateQt(this))
{
}


int startQtLoop()
{
    if (!QCoreApplication::instance()) {
        qWarning("Qt eventloop require QCoreApplication.");
        return -1;
    }

    QSharedPointer<EventLoopCoroutine> eventLoop = currentLoop()->get();
    QtEventLoopCoroutine *qtEventLoop = nullptr;
    if (!eventLoop.isNull()) {
        qtEventLoop = dynamic_cast<QtEventLoopCoroutine*>(eventLoop.data());
        if (!qtEventLoop) {
            qDebug() << "current eventloop is not Qt.";
            return -1;
        }
    } else {
        qtEventLoop = new QtEventLoopCoroutine();
        currentLoop()->set(QSharedPointer<EventLoopCoroutine>(qtEventLoop));
    }

    EventLoopCoroutinePrivateQt *priv = EventLoopCoroutinePrivateQt::getPrivateHelper(qtEventLoop);

    priv->loopCoroutine = BaseCoroutine::current();
    int result = QCoreApplication::instance()->exec();
    priv->loopCoroutine.clear();
    return result;
}

QTNETWORKNG_NAMESPACE_END

#include "eventloop_qt.moc"
