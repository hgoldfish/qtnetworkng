#include <QtCore/qmap.h>
#include <QtCore/qmutex.h>
#include <QtCore/qqueue.h>
#include <QtCore/qpointer.h>
#include <QtCore/qdebug.h>
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
#include <QtCore/qelapsedtimer.h>
#else
#include <QtCore/qdatetime.h>
#endif
#include <stddef.h>
#include <windows.h>
#include "../include/private/eventloop_p.h"


QTNETWORKNG_NAMESPACE_BEGIN


class WinEventLoopCoroutinePrivate;


struct WinWatcher
{
    int id;
    WinWatcher();
    virtual ~WinWatcher();
};


struct IoWatcher: public WinWatcher{
    IoWatcher(EventLoopCoroutine::EventType event, qintptr fd);
    virtual ~IoWatcher();

    EventLoopCoroutine::EventType event;
    qintptr fd;
    Functor *callback;
};


struct TimerWatcher: public WinWatcher
{
    TimerWatcher(quint32 interval, bool repeat, Functor *callback);
    virtual ~TimerWatcher();

    quint64 at;
    quint32 interval;
    Functor *callback;
    quint32 repeat;
    quint32 inUse;
};


WinWatcher::WinWatcher()
    : id(0) {}

WinWatcher::~WinWatcher() {}


IoWatcher::IoWatcher(EventLoopCoroutine::EventType event, qintptr fd)
    : event(event), fd(fd), callback(nullptr)
{
}


IoWatcher::~IoWatcher()
{
    if (callback) {
        delete callback;
    }
}


TimerWatcher::TimerWatcher(quint32 interval, bool repeat, Functor *callback)
    : at(0), interval(interval), callback(callback), repeat(repeat), inUse(false)
{
}


TimerWatcher::~TimerWatcher()
{
    delete callback;
}


class WinEventLoopCoroutinePrivate: public EventLoopCoroutinePrivate
{
public:
    WinEventLoopCoroutinePrivate(EventLoopCoroutine* parent);
    virtual ~WinEventLoopCoroutinePrivate() override;
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
    void updateIoMask(qintptr fd);
    void stopWatcher(IoWatcher *watcher);
    void sendTimerEvent(TimerWatcher *watcher);
    void sendIoEvent(qintptr fd, EventLoopCoroutine::EventType event);
    void createInternalWindow();
    void updateTimeStamp();
    void processTimers();
    int addTimer(TimerWatcher *watcher);
    HWND internalHwnd;
private:
    QMap<int, WinWatcher*> watchers;
    QMap<qintptr, QSet<IoWatcher *> > activeSockets;
    QList<TimerWatcher *> activeTimers;
    QMutex mqMutex;
    QQueue<TimerWatcher *> callLaterQueue;
    QPointer<BaseCoroutine> loopCoroutine;
    QSharedPointer<QAtomicInt> interrupted;
    quint64 currentTimeStamp;
    int nextWatcherId;
    int padding;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    QElapsedTimer timer;
#endif
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
    friend struct TriggerIoWatchersFunctor;
};



WinEventLoopCoroutinePrivate::WinEventLoopCoroutinePrivate(EventLoopCoroutine *parent)
    : EventLoopCoroutinePrivate(parent)
    , internalHwnd(nullptr)
    , interrupted(new QAtomicInt(false))
    , nextWatcherId(1)
{
    createInternalWindow();
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    timer.start();
#endif
    updateTimeStamp();
}


enum {
    WM_QTNG_SOCKETNOTIFIER = WM_USER,
    WM_QTNG_DO_CALL_LATER = WM_USER + 1,
    WM_QTNG_WAKEUP = WM_USER + 2,
};


WinEventLoopCoroutinePrivate::~WinEventLoopCoroutinePrivate()
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    interrupted->storeRelaxed(true);
#else
    interrupted->storeRelease(true);
#endif
    if (internalHwnd) {
        for (qintptr fd: activeSockets.keys()) {
            WSAAsyncSelect(static_cast<SOCKET>(fd), internalHwnd, 0, 0);
        }
        activeSockets.clear();
        activeTimers.clear();

        QMapIterator<int, WinWatcher*> watchersItor(watchers);
        while (watchersItor.hasNext()) {
            delete watchersItor.next().value();
        }
        DestroyWindow(internalHwnd);
        PostQuitMessage(0);
    }
}


void WinEventLoopCoroutinePrivate::run()
{
    // if WinEventLoopCoroutinePrivate is destructed, run() should exit peacefully.
    QSharedPointer<QAtomicInt> interrupted = this->interrupted;
    DWORD nCount = 0;
    HANDLE *pHandles = nullptr;
    do {
        updateTimeStamp();
        processTimers();
        updateTimeStamp();
        MSG msg;
        bool haveMessage = PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE);
        if (!haveMessage) {
            quint64 waittime = INFINITE;
            if (!activeTimers.isEmpty()) {
                waittime = activeTimers.first()->at - currentTimeStamp;
            }
            DWORD waitRet = MsgWaitForMultipleObjectsEx(nCount, pHandles, static_cast<quint32>(waittime), QS_ALLINPUT, MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);
            Q_UNUSED(waitRet);
            haveMessage = PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE);
            if (!haveMessage) {
                continue;
            }
        }
        if (msg.message == WM_QUIT) {
            return;
        } else if (msg.message == WM_QTNG_WAKEUP) {
            continue;
        } else {
            TranslateMessage(&msg);
            interrupted->storeRelease(false);
            updateTimeStamp();
            DispatchMessage(&msg);
        }
    } while (!interrupted->loadAcquire());
}


int WinEventLoopCoroutinePrivate::createWatcher(EventLoopCoroutine::EventType event, qintptr fd, Functor *callback)
{
    IoWatcher *watcher = new IoWatcher(event, fd);
    watcher->callback = callback;
    int id = nextWatcherId++;
    watcher->id = id;
    watchers.insert(id, watcher);
    return id;
}


void WinEventLoopCoroutinePrivate::startWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (watcher) {
        // i don't like activeSockets[fd]
        if (activeSockets.contains(watcher->fd)) {
            if (!activeSockets[watcher->fd].contains(watcher)) {
                activeSockets[watcher->fd].insert(watcher);
            }
        } else {
            QSet<IoWatcher *> allWatchers;
            allWatchers.insert(watcher);
            activeSockets.insert(watcher->fd, allWatchers);
        }
        updateIoMask(watcher->fd);
    }
}


void WinEventLoopCoroutinePrivate::stopWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (watcher) {
        stopWatcher(watcher);
    }
}

void WinEventLoopCoroutinePrivate::stopWatcher(IoWatcher *watcher)
{
    // i don't like activeSockets[fd]
    bool found = false;
    if (activeSockets.contains(watcher->fd)) {
        found = activeSockets[watcher->fd].remove(watcher);
        if (activeSockets[watcher->fd].isEmpty()) {
            activeSockets.remove(watcher->fd);
        }
    }
    if (found) {
        updateIoMask(watcher->fd);
    }
}


void WinEventLoopCoroutinePrivate::removeWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.take(watcherId));
    if (watcher) {
        stopWatcher(watcher);
        delete watcher;
    }
}


struct TriggerIoWatchersFunctor: public Functor
{
    TriggerIoWatchersFunctor(int watcherId, WinEventLoopCoroutinePrivate *eventloop)
        :eventloop(eventloop), watcherId(watcherId) {}
    virtual ~TriggerIoWatchersFunctor() override;
    WinEventLoopCoroutinePrivate *eventloop;
    int watcherId;
    virtual void operator()() override
    {
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(eventloop->watchers.take(watcherId));
        if (watcher) {
            (*watcher->callback)();
            delete watcher;
        }
    }
};


TriggerIoWatchersFunctor::~TriggerIoWatchersFunctor() {}


void WinEventLoopCoroutinePrivate::triggerIoWatchers(qintptr fd)
{
    for (IoWatcher *watcher: activeSockets.value(fd)) {
        callLater(0, new TriggerIoWatchersFunctor(watcher->id, this));
    }
    activeSockets.remove(fd);
}


int WinEventLoopCoroutinePrivate::addTimer(TimerWatcher *watcher)
{
    int timerId = watcher->id;
    if (!timerId) {
        timerId = nextWatcherId++;
        watcher->id = timerId;
        watchers.insert(timerId, watcher);
    }
    watcher->at = currentTimeStamp + watcher->interval;
    if (activeTimers.isEmpty()) {
        activeTimers.append(watcher);
        PostMessageW(internalHwnd, WM_QTNG_WAKEUP, 0, 0);
    } else {
        bool inserted = false;
        for (int i = 0; i < activeTimers.size() ; ++i) {
            if (activeTimers.at(i)->at > watcher->at) {
                activeTimers.insert(i, watcher);
                inserted = true;
                break;
            }
        }
        if (!inserted) {
            activeTimers.append(watcher);
        }
    }
    return timerId;
}


int WinEventLoopCoroutinePrivate::callLater(quint32 msecs, Functor *callback)
{
    TimerWatcher *watcher = new TimerWatcher(msecs, false, callback);
    return addTimer(watcher);
}


void WinEventLoopCoroutinePrivate::doCallLater()
{
    QMutexLocker locker(&mqMutex);
    while (!callLaterQueue.isEmpty()) {
        TimerWatcher *watcher = callLaterQueue.dequeue();
        addTimer(watcher);
    }
}

void WinEventLoopCoroutinePrivate::callLaterThreadSafe(quint32 msecs, Functor *callback)
{
    QMutexLocker locker(&mqMutex);
    TimerWatcher *watcher = new TimerWatcher(msecs, false, callback);
    callLaterQueue.enqueue(watcher);
    PostMessage(internalHwnd, WM_QTNG_DO_CALL_LATER, 0, 0);
}


int WinEventLoopCoroutinePrivate::callRepeat(quint32 msecs, Functor *callback)
{
    Q_ASSERT(msecs > 0);
    TimerWatcher *watcher = new TimerWatcher(msecs, true, callback);
    return addTimer(watcher);
}


void WinEventLoopCoroutinePrivate::cancelCall(int callbackId)
{
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if (watcher) {
        activeTimers.removeAll(watcher);
        if (watcher->inUse) {
            watcher->id = 0;
        } else {
            delete watcher;
        }
    }
}

int WinEventLoopCoroutinePrivate::exitCode()
{
    return 0;
}


bool WinEventLoopCoroutinePrivate::runUntil(BaseCoroutine *coroutine)
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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
            this->interrupted->storeRelaxed(true);
#else
            this->interrupted->store(true);
#endif
            if (!loopCoroutine.isNull()) {
                loopCoroutine->yield();
            }
        };
        coroutine->finished.addCallback(exitOneDepth);
        run();
        loopCoroutine = old;
    }
    return true;
}


void WinEventLoopCoroutinePrivate::yield()
{
    Q_Q(EventLoopCoroutine);
    if (!loopCoroutine.isNull()) {
        loopCoroutine->yield();
    } else {
       q->BaseCoroutine::yield();
    }
}


WinEventLoopCoroutine::WinEventLoopCoroutine()
    :EventLoopCoroutine(new WinEventLoopCoroutinePrivate(this))
{

}

// here comes windows implemention.

// Provide class name and atom for the message window used by
// QEventDispatcherWin32Private via Q_GLOBAL_STATIC shared between threads.
struct QWindowsMessageWindowClassContext
{
    QWindowsMessageWindowClassContext();
    ~QWindowsMessageWindowClassContext();

    ATOM atom;
    wchar_t *className;
};


LRESULT QT_WIN_CALLBACK evl_win_internal_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_NCCREATE)
        return true;

#ifdef GWLP_USERDATA
    WinEventLoopCoroutinePrivate *d = reinterpret_cast<WinEventLoopCoroutinePrivate *>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
#else
    WinEventLoopCoroutinePrivate *d = reinterpret_cast<WinEventLoopCoroutinePrivate *>(GetWindowLong(hwnd, GWL_USERDATA));
#endif
    switch (message) {
    case WM_QTNG_SOCKETNOTIFIER: {
        // socket notifier message
        int event = WSAGETSELECTEVENT(lp);
        qintptr fd = static_cast<qintptr>(wp);
        if (event == FD_READ || event == FD_ACCEPT) {
            d->sendIoEvent(fd, EventLoopCoroutine::Read);
        } else if (event == FD_WRITE || event == FD_CONNECT) {
            d->sendIoEvent(fd, EventLoopCoroutine::Write);
        } else if (event == FD_CLOSE) {
            d->sendIoEvent(fd, EventLoopCoroutine::ReadWrite);
        } else {
            qDebug() << "unknown select event!";
        }
    }
        break;
    case WM_QTNG_DO_CALL_LATER:
        // TODO remove all WM_QTNG_DO_CALL_LATER messages.
        d->doCallLater();
        break;
    }
    return DefWindowProc(hwnd, message, wp, lp);
}

QWindowsMessageWindowClassContext::QWindowsMessageWindowClassContext()
    : atom(0), className(nullptr)
{
    // make sure that multiple Qt's can coexist in the same process
    const QString qClassName = QStringLiteral("WinEventLoopCoroutine_Internal_Widget")
        + QString::number(quintptr(evl_win_internal_proc));
    className = new wchar_t[qClassName.size() + 1];
    qClassName.toWCharArray(className);
    className[qClassName.size()] = 0;

    WNDCLASSW wc;
    wc.style = 0;
    wc.lpfnWndProc = evl_win_internal_proc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hIcon = nullptr;
    wc.hCursor = nullptr;
    wc.hbrBackground = nullptr;
    wc.lpszMenuName = nullptr;
    wc.lpszClassName = className;
    atom = RegisterClassW(&wc);
    if (!atom) {
        qErrnoWarning("WinEventLoopCoroutine_Internal_Widget RegisterClass() failed");
        delete [] className;
        className = nullptr;
    }
}

QWindowsMessageWindowClassContext::~QWindowsMessageWindowClassContext()
{
    if (className) {
        UnregisterClassW(className, GetModuleHandle(nullptr));
        delete [] className;
    }
}

Q_GLOBAL_STATIC(QWindowsMessageWindowClassContext, qWindowsMessageWindowClassContext)


void WinEventLoopCoroutinePrivate::createInternalWindow()
{
    if (internalHwnd) {
        return;
    }

    QWindowsMessageWindowClassContext *ctx = qWindowsMessageWindowClassContext();
    if (!ctx->atom) {
        return;
    }

    internalHwnd = CreateWindowW(ctx->className,    // classname
                                ctx->className,    // window name
                                0,                 // style
                                0, 0, 0, 0,        // geometry
                                HWND_MESSAGE,            // parent
                                nullptr,                 // menu handle
                                GetModuleHandle(nullptr),     // application
                                nullptr);                // windows creation data.

    if (!internalHwnd) {
        qErrnoWarning("CreateWindow() for QEventDispatcherWin32 internal window failed");
        return;
    }

#ifdef GWLP_USERDATA
    SetWindowLongPtr(internalHwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
#else
    SetWindowLong(internalHwnd, GWL_USERDATA, reinterpret_cast<LONG>(this));
#endif
}


void WinEventLoopCoroutinePrivate::sendTimerEvent(TimerWatcher *watcher)
{
    if (!watcher->repeat) {
        watchers.remove(watcher->id);
        watcher->id = 0;
    } else {
        addTimer(watcher);
    }
    watcher->inUse = true;
    (*watcher->callback)();
    Q_ASSERT(watcher->inUse);
    if (watcher->id == 0) {
        delete watcher;
    } else {
        watcher->inUse = false;
    }
}


void WinEventLoopCoroutinePrivate::sendIoEvent(qintptr fd, EventLoopCoroutine::EventType event)
{
    if (event == EventLoopCoroutine::ReadWrite) {  // closed
        WSAAsyncSelect(static_cast<SOCKET>(fd), internalHwnd, 0, 0);
        // assume that no new socket is started. so we just clear activeSockets[fd]
        for (IoWatcher *watcher: activeSockets.value(fd)) {
            int id = watcher->id;
            (*watcher->callback)();
            if (watchers.remove(id)) {
                delete watcher;
            }
        }
        activeSockets.remove(fd);
        QMutableMapIterator<int, WinWatcher*> itor(watchers);
        while (itor.hasNext()) {
            IoWatcher *watcher = dynamic_cast<IoWatcher *>(itor.next().value());
            if (Q_UNLIKELY(watcher && watcher->fd == fd)) {
                itor.remove();
                delete watcher;
            }
        }
    } else {
        for (IoWatcher *watcher: activeSockets.value(fd)) {
            if (((event & EventLoopCoroutine::Read) && (watcher->event & EventLoopCoroutine::Read)) ||
                ((event & EventLoopCoroutine::Write) && (watcher->event & EventLoopCoroutine::Write))) {
                // can be removed while process it. but ignored new watchers.
                // after callback, remove from active sockets list,
                // but not from watchers, because someone may restart it later.
                if (activeSockets.value(fd).contains(watcher)) {
                    activeSockets[fd].remove(watcher);
                    (*watcher->callback)();
                }
            }
        }
        if (activeSockets.value(fd).isEmpty()) {
            activeSockets.remove(fd);
            WSAAsyncSelect(static_cast<SOCKET>(fd), internalHwnd, 0, 0);
        } else {
            updateIoMask(fd);
        }
    }
}


void WinEventLoopCoroutinePrivate::updateIoMask(qintptr fd)
{
    const QSet<IoWatcher *> &watchers = activeSockets.value(fd);
    long event = 0;
    for (IoWatcher *watcher: watchers) {
        if (watcher->event & EventLoopCoroutine::Read) {
            event |= FD_READ | FD_ACCEPT | FD_CLOSE ;
        } else if (watcher->event & EventLoopCoroutine::Write) {
            event |= FD_WRITE | FD_CONNECT | FD_CLOSE;
        }
    }
    int result = WSAAsyncSelect(static_cast<SOCKET>(fd), internalHwnd, (event ? WM_QTNG_SOCKETNOTIFIER : 0), event);
    if (result && event) {
        qDebug() << result << WSAGetLastError();
    }
}


void WinEventLoopCoroutinePrivate::processTimers()
{
    while (!activeTimers.isEmpty() && !interrupted->loadAcquire()) {
//        for (int i = 1; i < activeTimers.size(); ++i) {
//            if (activeTimers.at(i -1)->at > activeTimers.at(i)->at) {
//                qDebug() << "invalid timer queue!";
//            }
//        }
        TimerWatcher *watcher = activeTimers.first();
        if (watcher->at <= currentTimeStamp) {
            activeTimers.takeFirst();
            sendTimerEvent(watcher);
        } else {
            break;
        }
    }
}


void WinEventLoopCoroutinePrivate::updateTimeStamp()
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 7, 0))
    currentTimeStamp = static_cast<quint64>(timer.elapsed());
#elif _WIN32_WINNT >= 0x0600
    currentTimeStamp = GetTickCount64();
#else
    currentTimeStamp = static_cast<quint64>(GetTickCount());
#endif
}


QTNETWORKNG_NAMESPACE_END


