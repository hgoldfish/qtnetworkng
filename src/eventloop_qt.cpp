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

    QSharedPointer<QSocketNotifier> readNotifier;
    QSharedPointer<QSocketNotifier> writeNotifier;
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
    if (callback) {
        delete callback;
    }
}

}  // anonymous namespace


class EventLoopCoroutinePrivateQtHelper;
class QtEventLoopCoroutinePrivate: public EventLoopCoroutinePrivate
{
public:
    QtEventLoopCoroutinePrivate(EventLoopCoroutine* q);
    virtual ~QtEventLoopCoroutinePrivate() override;
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
    virtual bool yield() override;
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

    static QtEventLoopCoroutinePrivate *getPrivateHelper(EventLoopCoroutine *coroutine)
    {
        EventLoopCoroutinePrivate *d = EventLoopCoroutinePrivate::getPrivateHelper(coroutine);
        return static_cast<QtEventLoopCoroutinePrivate*>(d);
    }

    friend int startQtLoop();
};


class EventLoopCoroutinePrivateQtHelper: public QObject
{
    Q_OBJECT
public:
    EventLoopCoroutinePrivateQtHelper(QtEventLoopCoroutinePrivate *parent)
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
    QtEventLoopCoroutinePrivate * const parent;
};


QtEventLoopCoroutinePrivate::QtEventLoopCoroutinePrivate(EventLoopCoroutine *q)
    :EventLoopCoroutinePrivate(q), nextWatcherId(1), helper(new EventLoopCoroutinePrivateQtHelper(this))
{
}


QtEventLoopCoroutinePrivate::~QtEventLoopCoroutinePrivate()
{
    for (QtWatcher *watcher: watchers) {
        delete watcher;
    }
    delete helper;
}


void QtEventLoopCoroutinePrivate::run()
{
    QEventLoop localLoop;
    int result = localLoop.exec();
    this->qtExitCode = result;
}


void QtEventLoopCoroutinePrivate::handleIoEvent(int socket, QSocketNotifier *n)
{
    Q_UNUSED(socket)

    if (!n) {
        qDebug() << "can not retrieve sender() while handling qt io event.";
        return;
    }

    IoWatcher *w = static_cast<IoWatcher*>(n->property("parent").value<void*>());
    (*w->callback)();
}


int QtEventLoopCoroutinePrivate::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *w = new IoWatcher(fd, event, callback);
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}


void QtEventLoopCoroutinePrivate::startWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (w) {
        if (w->event & EventLoopCoroutine::Read) {
            if (w->readNotifier.isNull()) {
                w->readNotifier.reset(new QSocketNotifier(w->fd, QSocketNotifier::Read));
                w->readNotifier->setProperty("parent", QVariant::fromValue(static_cast<void*>(w)));
                QObject::connect(w->readNotifier.data(), SIGNAL(activated(int)), this->helper, SLOT(handleIoEvent(int)), Qt::DirectConnection);
            }
            w->readNotifier->setEnabled(true);
        }
        if (w->event & EventLoopCoroutine::Write) {
            if (w->writeNotifier.isNull()) {
                w->writeNotifier.reset(new QSocketNotifier(w->fd, QSocketNotifier::Write));
                w->writeNotifier->setProperty("parent", QVariant::fromValue(static_cast<void*>(w)));
                QObject::connect(w->writeNotifier.data(), SIGNAL(activated(int)), this->helper, SLOT(handleIoEvent(int)), Qt::DirectConnection);
            }
            w->writeNotifier->setEnabled(true);
        }
    }
}


void QtEventLoopCoroutinePrivate::stopWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (w && !w->readNotifier.isNull()) {
        w->readNotifier->setEnabled(false);
    }
    if (w && !w->writeNotifier.isNull()) {
        w->writeNotifier->setEnabled(false);
    }
}


void QtEventLoopCoroutinePrivate::removeWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if (w) {
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
    if (eventloop.isNull()) {
        qWarning("triggerIoWatchers() is called without eventloop.");
        return;
    }
    QtEventLoopCoroutinePrivate *d = QtEventLoopCoroutinePrivate::getPrivateHelper(eventloop.data());
    IoWatcher *w = dynamic_cast<IoWatcher*>(d->watchers.value(watcherId));
    if (w) {
        (*w->callback)();
    }
}


void QtEventLoopCoroutinePrivate::triggerIoWatchers(qintptr fd)
{
    Q_Q(EventLoopCoroutine);
    for (QMap<int, QtWatcher*>::const_iterator itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        IoWatcher *w = dynamic_cast<IoWatcher*>(itor.value());
        if (w && w->fd == fd) {
            if (!w->readNotifier.isNull()) {
                w->readNotifier->setEnabled(false);
            }
            if (!w->writeNotifier.isNull()) {
                w->writeNotifier->setEnabled(false);
            }
            callLater(0, new TriggerIoWatchersArgumentsFunctor(itor.key(), q));
        }
    }
}

void QtEventLoopCoroutinePrivate::timerEvent(QTimerEvent *event)
{
    if (!timers.contains(event->timerId())) {
        return;
    }

    int watcherId = timers.value(event->timerId());
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.value(watcherId));

    if (!watcher) {
        return;
    }

    bool singleshot = watcher->singleshot;
    if (singleshot && watchers.contains(watcherId)) {
        watchers.remove(watcherId);
        timers.remove(event->timerId());
        helper->killTimer(event->timerId());
    }
    (*watcher->callback)();
    if (singleshot) {
        // watcher may be deleted!
        delete watcher;
    } else {
        //watcher->timerId = startTimer(watcher->interval);
    }
}


int QtEventLoopCoroutinePrivate::callLater(quint32 msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, true, callback);
    w->timerId = helper->startTimer(static_cast<int>(msecs), Qt::PreciseTimer);
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}


void QtEventLoopCoroutinePrivate::callLaterThreadSafe(quint32 msecs, Functor *callback)
{
    QMetaObject::invokeMethod(this->helper, "callLaterThreadSafeStub", Qt::QueuedConnection, Q_ARG(quint32, msecs), Q_ARG(void*, callback));
}


int QtEventLoopCoroutinePrivate::callRepeat(quint32 msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, false, callback);
    w->timerId = helper->startTimer(static_cast<int>(msecs));
    watchers.insert(nextWatcherId, w);
    timers.insert(w->timerId, nextWatcherId);
    return nextWatcherId++;
}


void QtEventLoopCoroutinePrivate::cancelCall(int callbackId)
{
    TimerWatcher *w = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if (w) {
        timers.remove(w->timerId);
        helper->killTimer(w->timerId);
        delete w;
    }
}


int QtEventLoopCoroutinePrivate::exitCode()
{
    return qtExitCode;
}


bool QtEventLoopCoroutinePrivate::runUntil(BaseCoroutine *coroutine)
{
    QPointer<BaseCoroutine> current = BaseCoroutine::current();
    if (!loopCoroutine.isNull() && loopCoroutine != current ) {
        Deferred<BaseCoroutine*>::Callback return_here = [current] (BaseCoroutine *) {
            if (!current.isNull()) {
                current->yield();
            }
        };
        coroutine->finished.addCallback(return_here);
        loopCoroutine->yield();
    } else {
        QPointer<BaseCoroutine> old = loopCoroutine;
        loopCoroutine = current;
        QSharedPointer<QEventLoop> sub(new QEventLoop());
        QPointer<BaseCoroutine> t = loopCoroutine;
        Deferred<BaseCoroutine*>::Callback shutdown = [t, sub] (BaseCoroutine *) {
            sub->exit();
            if (!t.isNull()) {
                t->yield();
            }
        };
        coroutine->finished.addCallback(shutdown);
        sub->exec();
        loopCoroutine = old;
    }
    return true;
}


bool QtEventLoopCoroutinePrivate::yield()
{
    Q_Q(EventLoopCoroutine);
    if (!loopCoroutine.isNull()) {
        return loopCoroutine->yield();
    } else {
        return q->BaseCoroutine::yield();
    }
}


QtEventLoopCoroutine::QtEventLoopCoroutine()
    :EventLoopCoroutine(new QtEventLoopCoroutinePrivate(this))
{
}


int startQtLoop()
{
    if (!QCoreApplication::instance()) {
        qFatal("Qt eventloop require QCoreApplication.");
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

    QtEventLoopCoroutinePrivate *priv = QtEventLoopCoroutinePrivate::getPrivateHelper(qtEventLoop);

    priv->loopCoroutine = BaseCoroutine::current();
    int result = QCoreApplication::instance()->exec();
    QCoreApplication::instance()->processEvents();
    priv->loopCoroutine.clear();
    return result;
}


QTNETWORKNG_NAMESPACE_END

#include "eventloop_qt.moc"
