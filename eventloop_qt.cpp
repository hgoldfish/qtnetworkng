#include <QMap>
#include <QEventLoop>
#include <QThread>
#include <QCoreApplication>
#include <QSocketNotifier>
#include <QDebug>
#include <QTimer>
#include <QPointer>
#include "eventloop.h"

struct QtWatcher
{
    virtual ~QtWatcher();
};

QtWatcher::~QtWatcher() {}

struct IoWatcher: public QtWatcher
{
    IoWatcher(qintptr fd, EventLoopCoroutine::EventType event);
    virtual ~IoWatcher();

    EventLoopCoroutine::EventType event;
    QSocketNotifier read;
    QSocketNotifier write;
    Functor *callback;
};

IoWatcher::IoWatcher(qintptr fd, EventLoopCoroutine::EventType event)
    :event(event), read(fd, QSocketNotifier::Read), write(fd, QSocketNotifier::Write)
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
    virtual void run();
    virtual int createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback);
    virtual void startWatcher(int watcherId);
    virtual void stopWatcher(int watcherId);
    virtual void removeWatcher(int watcherId);
    virtual int callLater(int msecs, Functor *callback);
    virtual void callLaterThreadSafe(int msecs, Functor *callback);
    virtual int callRepeat(int msecs, Functor *callback);
    virtual void cancelCall(int callbackId);
    virtual int exitCode();
private slots:
    void callLaterThreadSafeStub(int msecs, void* callback)
    {
        callLater(msecs, reinterpret_cast<Functor*>(callback));
    }
protected:
    virtual void timerEvent(QTimerEvent *event);
private slots:
    void handleIoEvent(int socket);
private:
    QEventLoop *loop;
    QMap<int, QtWatcher*> watchers;
    int nextWatcherId;
    int qtExitCode;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
};

EventLoopCoroutinePrivateQt::EventLoopCoroutinePrivateQt(EventLoopCoroutine *q)
    :EventLoopCoroutinePrivate(q), nextWatcherId(1)
{
    QCoreApplication *app = QCoreApplication::instance();
    if(QThread::currentThread() == app->thread()) {
        loop = 0;
    } else {
        loop = new QEventLoop();
    }
}

EventLoopCoroutinePrivateQt::~EventLoopCoroutinePrivateQt()
{
    QMapIterator<int, QtWatcher*> itor(watchers);
    while(itor.hasNext()) {
        itor.next();
        delete itor.value();
    }
    if(loop) {
        loop->quit(); // XXX ::run() may be in other coroutine;
    }
}

void EventLoopCoroutinePrivateQt::run()
{
    QCoreApplication *app = QCoreApplication::instance();
    if(QThread::currentThread() == app->thread()) {
        qtExitCode = app->exec();
    } else {
        volatile QEventLoop *localLoop = loop;
        qtExitCode = ((QEventLoop*)localLoop)->exec();
        delete localLoop;
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
    IoWatcher *w = new IoWatcher(fd, event);

    connect(&w->read, SIGNAL(activated(int)), SLOT(handleIoEvent(int)));
    connect(&w->write, SIGNAL(activated(int)), SLOT(handleIoEvent(int)));
    w->callback = callback;
    watchers.insert(nextWatcherId, w);
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::startWatcher(int watcherId)
{
    IoWatcher *w = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if(w) {
        if(w->event & EventLoopCoroutine::Read)
            w->read.setEnabled(true);
        if(w->event & EventLoopCoroutine::Write)
            w->write.setEnabled(true);
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
        delete w;
    }
}

void EventLoopCoroutinePrivateQt::timerEvent(QTimerEvent *event)
{
    for(auto itor = watchers.constBegin(); itor != watchers.constEnd(); ++itor) {
        int watcherId = itor.key();
        TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(itor.value());
        if(!watcher)
            continue;
        if(watcher->timerId != event->timerId())
            continue;
        (*watcher->callback)();
        if(watcher->singleshot) {
            // watcher may be deleted!
            QtWatcher *w = watchers.value(watcherId);
            if(w) {
                watchers.remove(watcherId);
                delete w;
            }
        } else {
            watcher->timerId = startTimer(watcher->interval);
        }
        break;
    }
}


int EventLoopCoroutinePrivateQt::callLater(int msecs, Functor *callback)
{
    TimerWatcher *w = new TimerWatcher(msecs, true, callback);
    w->timerId = startTimer(msecs, Qt::VeryCoarseTimer);
    watchers.insert(nextWatcherId, w);
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
    return nextWatcherId++;
}

void EventLoopCoroutinePrivateQt::cancelCall(int callbackId)
{
    TimerWatcher *w = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if(w) {
        killTimer(w->timerId);
        delete w;
    }
}

int EventLoopCoroutinePrivateQt::exitCode()
{
    return qtExitCode;
}

EventLoopCoroutine::EventLoopCoroutine()
    :QBaseCoroutine(QBaseCoroutine::current()), d_ptr(new EventLoopCoroutinePrivateQt(this))
{

}

#include "eventloop_qt.moc"
