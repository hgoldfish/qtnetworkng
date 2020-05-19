#include <QtCore/qmap.h>
#include <QtCore/qmutex.h>
#include <QtCore/qqueue.h>
#include <QtCore/qpointer.h>
#include <QtCore/qdebug.h>
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

    quint32 interval;
    bool repeat;
    bool inUse;
    Functor *callback;
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
    : interval(interval), repeat(repeat), inUse(false), callback(callback)
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
    void stopWatcher(IoWatcher *watcher);
    void sendTimerEvent(int callbackId);
    void sendIoEvent(qintptr fd, EventLoopCoroutine::EventType event, bool doClose);
    void updateIoMask(qintptr fd);
    void createInternalWindow();
    HWND internalHwnd;
private:
    QMap<int, WinWatcher*> watchers;
    QMap<qintptr, QList<IoWatcher *> > activeSockets;
    QMutex mqMutex;
    QQueue<TimerWatcher *> callLaterQueue;
    QPointer<BaseCoroutine> loopCoroutine;
    int nextWatcherId;
    QAtomicInt interrupted;
    Q_DECLARE_PUBLIC(EventLoopCoroutine)
    friend struct TriggerIoWatchersFunctor;
};



WinEventLoopCoroutinePrivate::WinEventLoopCoroutinePrivate(EventLoopCoroutine *parent)
    : EventLoopCoroutinePrivate(parent)
    , internalHwnd(nullptr)
    , nextWatcherId(1)
    , interrupted(false)
{
    createInternalWindow();
}

enum {
    WM_QTNG_SOCKETNOTIFIER = WM_USER,
    WM_QTNG_DO_CALL_LATER = WM_USER + 1,
};

WinEventLoopCoroutinePrivate::~WinEventLoopCoroutinePrivate()
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    interrupted.storeRelaxed(true);
#else
    interrupted.store(true);
#endif
    if (internalHwnd) {
        QMapIterator<qintptr, QList<IoWatcher*> > activeSocketsItor(activeSockets);
        while (activeSocketsItor.hasNext()) {
            activeSocketsItor.next();
            WSAAsyncSelect(static_cast<SOCKET>(activeSocketsItor.key()), internalHwnd, 0, 0);
        }
        activeSockets.clear();

        QMapIterator<int, WinWatcher*> watchersItor(watchers);
        while (watchersItor.hasNext()) {
            watchersItor.next();
            WinWatcher *watcher = watchersItor.value();
            if (dynamic_cast<TimerWatcher *>(watcher)) {
                KillTimer(internalHwnd, static_cast<UINT_PTR>(watchersItor.key()));
            }
            delete watcher;
        }
        DestroyWindow(internalHwnd);
        PostQuitMessage(0);
    }
}


void WinEventLoopCoroutinePrivate::run()
{
    DWORD nCount = 0;
    HANDLE *pHandles = nullptr;
    do {
        MSG msg;

        bool haveMessage = PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE);
        if (!haveMessage) {
            DWORD waitRet = MsgWaitForMultipleObjectsEx(nCount, pHandles, INFINITE, QS_ALLINPUT, MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);
            Q_UNUSED(waitRet);
            haveMessage = PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE);
        }
        if (!haveMessage) {
            break;
        }

        if (msg.message == WM_QUIT) {
            return;
        } else {
            TranslateMessage(&msg);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
            interrupted.storeRelease(false);
            DispatchMessage(&msg);
        }
    } while (!interrupted.loadAcquire());
#else
            interrupted.store(false);
            DispatchMessage(&msg);
        }
    } while (!interrupted.load());
#endif
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


//static bool isValid(qintptr fd)
//{
//    int error = 0;
//    int len = sizeof (error);
//    int result = getsockopt(static_cast<SOCKET>(fd), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len);
//    return result == 0 && error == 0;
//}


void WinEventLoopCoroutinePrivate::updateIoMask(qintptr fd)
{
    const QList<IoWatcher *> &allWatchers = activeSockets.value(fd);
    long event = 0;
    for (IoWatcher *watcher: allWatchers) {
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


void WinEventLoopCoroutinePrivate::startWatcher(int watcherId)
{
    IoWatcher *watcher = dynamic_cast<IoWatcher*>(watchers.value(watcherId));
    if (watcher) {
        // i don't like activeSockets[fd]
        if (activeSockets.contains(watcher->fd)) {
            if (!activeSockets[watcher->fd].contains(watcher)) {
                activeSockets[watcher->fd].append(watcher);
            }
        } else {
            QList<IoWatcher *> allWatchers;
            allWatchers.append(watcher);
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
        found = activeSockets[watcher->fd].removeAll(watcher) > 0;
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
        IoWatcher *watcher = dynamic_cast<IoWatcher*>(eventloop->watchers.value(watcherId));
        if (watcher) {
            (*watcher->callback)();
        }
    }
};


TriggerIoWatchersFunctor::~TriggerIoWatchersFunctor() {}


void WinEventLoopCoroutinePrivate::triggerIoWatchers(qintptr fd)
{
    for (IoWatcher *watcher: activeSockets.value(fd)) {
        callLater(0, new TriggerIoWatchersFunctor(watcher->id, this));
    }
}


int WinEventLoopCoroutinePrivate::callLater(quint32 msecs, Functor *callback)
{
    TimerWatcher *watcher = new TimerWatcher(msecs, false, callback);
    int timerId = nextWatcherId++;
    watcher->id = timerId;
    watchers.insert(timerId, watcher);
    SetTimer(internalHwnd, static_cast<UINT_PTR>(timerId), msecs, nullptr);
    return timerId;
}


void WinEventLoopCoroutinePrivate::doCallLater()
{
    QMutexLocker locker(&mqMutex);
    while (!callLaterQueue.isEmpty()) {
        TimerWatcher *watcher = callLaterQueue.dequeue();
        int timerId = nextWatcherId++;
        watcher->id = timerId;
        watchers.insert(timerId, watcher);
        SetTimer(internalHwnd, static_cast<UINT_PTR>(timerId), watcher->interval, nullptr);
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
    TimerWatcher *watcher = new TimerWatcher(msecs, true, callback);
    int timerId = nextWatcherId++;
    watcher->id = timerId;
    watchers.insert(timerId, watcher);
    SetTimer(internalHwnd, static_cast<UINT_PTR>(timerId), msecs, nullptr);
    return timerId;
}


void WinEventLoopCoroutinePrivate::cancelCall(int callbackId)
{
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.take(callbackId));
    if (watcher) {
        KillTimer(internalHwnd, static_cast<UINT_PTR>(callbackId));
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
            this->interrupted.storeRelaxed(true);
#else
            this->interrupted.store(true);
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
            d->sendIoEvent(fd, EventLoopCoroutine::Read, false);
        } else if (event == FD_WRITE || event == FD_CONNECT) {
            d->sendIoEvent(fd, EventLoopCoroutine::Write, false);
        } else if (event == FD_CLOSE) {
            WSAAsyncSelect(static_cast<SOCKET>(wp), hwnd, 0, 0);
            d->sendIoEvent(fd, EventLoopCoroutine::ReadWrite, true);
        } else {
            qDebug() << "unknown select event!";
        }
        return 0;
    }
    case WM_QTNG_DO_CALL_LATER:
        // TODO remove all WM_QTNG_DO_CALL_LATER messages.
        d->doCallLater();
        return 0;
    case WM_TIMER:
        d->sendTimerEvent(static_cast<int>(wp));
        return 0;
    default:
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
        qErrnoWarning("%ls RegisterClass() failed", qUtf16Printable(qClassName));
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

void WinEventLoopCoroutinePrivate::sendTimerEvent(int callbackId)
{
    TimerWatcher *watcher = dynamic_cast<TimerWatcher*>(watchers.value(callbackId));
    if (watcher) {
        watcher->inUse = true;
        (*watcher->callback)();
        if (watcher->id == 0) {
            delete watcher;
        } else if (watcher->repeat) {
            watcher->inUse = false;
            SetTimer(internalHwnd, static_cast<UINT_PTR>(callbackId), watcher->interval, nullptr);
        } else {
            watchers.remove(callbackId);
            KillTimer(internalHwnd, static_cast<UINT_PTR>(callbackId));
            delete watcher;
        }
    }
}


void WinEventLoopCoroutinePrivate::sendIoEvent(qintptr fd, EventLoopCoroutine::EventType event, bool doClose)
{
    QList<IoWatcher *> allWatchers = activeSockets.value(fd);
    if (doClose) {
        activeSockets.remove(fd);
        QMutableMapIterator<int, WinWatcher*> itor(watchers);
        while (itor.hasNext()) {
            IoWatcher *watcher = dynamic_cast<IoWatcher *>(itor.next().value());
            if (watcher && watcher->fd == fd) {
                itor.remove();
            }
        }
    }
    for (IoWatcher *watcher: allWatchers) {
        if (((event & EventLoopCoroutine::Read) && (watcher->event & EventLoopCoroutine::Read)) ||
            ((event & EventLoopCoroutine::Write) && (watcher->event & EventLoopCoroutine::Write))) {
            (*watcher->callback)();
        }
    }
}


QTNETWORKNG_NAMESPACE_END


