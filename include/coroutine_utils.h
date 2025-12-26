#ifndef QTNG_COROUTINE_UTILS_H
#define QTNG_COROUTINE_UTILS_H
#include <functional>
#include <QtCore/qobject.h>
#include <QtCore/qvariant.h>
#include <QtCore/qthread.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qset.h>
#include <QtCore/qmutex.h>
#include <QtCore/qwaitcondition.h>
#include "locks.h"
#include "private/eventloop_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

template<typename T>
T callInEventLoop(std::function<T()> func)
{
    Q_ASSERT(static_cast<BaseCoroutine *>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event());

    std::function<void()> wrapper = [result, done, func]() mutable {
        *result = func();
        done->set();
    };

    int callbackId = EventLoopCoroutine::get()->callLater(0, new LambdaFunctor(wrapper));
    try {
        done->tryWait();
        EventLoopCoroutine::get()->cancelCall(callbackId);
    } catch (...) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
        throw;
    }
    return *result;
}

inline void callInEventLoop(std::function<void()> func, quint32 msecs = 0)
{
    Q_ASSERT(static_cast<BaseCoroutine *>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<Event> done(new Event());

    std::function<void()> wrapper = [done, func]() {
        func();
        done->set();
    };

    int callbackId = EventLoopCoroutine::get()->callLater(msecs, new LambdaFunctor(wrapper));
    try {
        done->tryWait();
        EventLoopCoroutine::get()->cancelCall(callbackId);
    } catch (...) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
        throw;
    }
}

inline void callInEventLoopAsync(std::function<void()> func, quint32 msecs = 0)
{
    //    Q_ASSERT(static_cast<QBaseCoroutine*>(EventLoopCoroutine::get()) != QBaseCoroutine::current());
    EventLoopCoroutine::get()->callLater(msecs, new LambdaFunctor(func));
}

template<typename EventLoop>
void runLocalLoop(EventLoop *loop)
{
    callInEventLoop([loop]() { loop->exec(); });
}

struct QAwaitHelper0 : public QObject
{
    void call() { event.set(); }
    Event event;
};

template<typename Func1>
void qAwait(const typename QtPrivate::FunctionPointer<Func1>::Object *obj, Func1 signal)
{
    QAwaitHelper0 helper;
    const QMetaObject::Connection connection =
            QObject::connect(obj, signal, &helper, &QAwaitHelper0::call, Qt::DirectConnection);
    try {
        helper.event.tryWait();
        QObject::disconnect(connection);
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}

template<typename ARG1, typename... ARGS>
struct QAwaitHelper1 : QObject
{
    QAwaitHelper1(QSharedPointer<ValueEvent<ARG1>> event)
        : event(event)
    {
    }
    void call(ARG1 arg1, ARGS...) { event->send(arg1); }
    QSharedPointer<ValueEvent<ARG1>> event;
};

template<typename Obj, typename ARG1>
ARG1 qAwait(const Obj *obj, const typename QtPrivate::FunctionPointer<void (Obj::*)(ARG1 arg1)>::Function signal)
{
    QSharedPointer<ValueEvent<ARG1>> event(new ValueEvent<ARG1>());
    QAwaitHelper1<ARG1> helper(event);
    const QMetaObject::Connection connection =
            QObject::connect(obj, signal, &helper, &QAwaitHelper1<ARG1>::call, Qt::DirectConnection);
    try {
        ARG1 result = event->tryWait();
        QObject::disconnect(connection);
        return result;
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}

template<typename... ARGS>
struct QAwaitHelper : QObject
{
    QAwaitHelper(QSharedPointer<ValueEvent<std::tuple<ARGS...>>> event)
        : event(event)
    {
    }
    void call(ARGS... args) { event->send(std::tuple<ARGS...>(args...)); }
    QSharedPointer<ValueEvent<std::tuple<ARGS...>>> event;
};

template<typename Obj, typename ARG1, typename ARG2, typename... ARGS>
std::tuple<ARG1, ARG2, ARGS...>
qAwait(const Obj *obj, const typename QtPrivate::FunctionPointer<void (Obj::*)(ARG1, ARG2, ARGS...)>::Function signal)
{
    QSharedPointer<ValueEvent<std::tuple<ARG1, ARG2, ARGS...>>> event(
            new ValueEvent<std::tuple<ARG1, ARG2, ARGS...>>());
    QAwaitHelper<ARG1, ARG2, ARGS...> helper(event);
    const QMetaObject::Connection connection =
            QObject::connect(obj, signal, &helper, &QAwaitHelper<ARG1, ARG2, ARGS...>::call, Qt::DirectConnection);
    try {
        std::tuple<ARG1, ARG2, ARGS...> result = event->tryWait();
        QObject::disconnect(connection);
        return result;
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}

// XXX DO NOT DELETE ANYTHING IN CHILD THREADS.
class DeferCallThread : public QThread
{
public:
    DeferCallThread(std::function<void()> makeResult, QSharedPointer<Event> done, EventLoopCoroutine *eventloop);
    virtual void run() override;
private:
    std::function<void()> makeResult;
    QSharedPointer<Event> done;
    QPointer<EventLoopCoroutine> eventloop;
};

inline QSharedPointer<Event> spawnInThread(const std::function<void()> &func)
{
    QSharedPointer<Event> done = QSharedPointer<Event>::create();
    DeferCallThread *thread = new DeferCallThread(func, done, EventLoopCoroutine::get());
    thread->start();
    return done;
}

template<typename T>
T callInThread(std::function<T()> func)
{
    QSharedPointer<T> result = QSharedPointer<T>::create();
    std::function<void()> makeResult = [result, func]() mutable { *result = func(); };
    spawnInThread(makeResult)->tryWait();
    return *result;
}

template<typename T, typename ARG1>
T callInThread(std::function<T(ARG1)> func, ARG1 arg1)
{
    return callInThread<T>([func, arg1]() -> T { return func(arg1); });
}

template<typename T, typename ARG1, typename ARG2>
T callInThread(std::function<T(ARG1, ARG2)> func, ARG1 arg1, ARG2 arg2)
{
    return callInThread<T>([func, arg1, arg2]() -> T { return func(arg1, arg2); });
}

template<typename T, typename ARG1, typename ARG2, typename ARG3>
T callInThread(std::function<T(ARG1, ARG2, ARG3)> func, ARG1 arg1, ARG2 arg2, ARG3 arg3)
{
    return callInThread<T>([func, arg1, arg2, arg3]() -> T { return func(arg1, arg2, arg3); });
}

template<typename T, typename ARG1, typename ARG2, typename ARG3, typename ARG4>
T callInThread(std::function<T(ARG1, ARG2, ARG3)> func, ARG1 arg1, ARG2 arg2, ARG3 arg3, ARG4 arg4)
{
    return callInThread<T>([func, arg1, arg2, arg3, arg4]() -> T { return func(arg1, arg2, arg3, arg4); });
}

inline void callInThread(const std::function<void()> &func)
{
    spawnInThread(func)->tryWait();
}

class CoroutineThreadPrivate;
class CoroutineThread : public QThread
{
public:
    explicit CoroutineThread(quint32 capacity = UINT_MAX);
    virtual ~CoroutineThread() override;
    virtual void run() override;
public:
    void apply(const std::function<void()> &f);
private:
    CoroutineThreadPrivate * const dd_ptr;
    Q_DECLARE_PRIVATE_D(dd_ptr, CoroutineThread)
};

bool waitThread(QThread *thread);
bool waitProcess(class QProcess *process);

inline QSharedPointer<Deferred<QSharedPointer<Coroutine>>> waitForAny()
{
    return QSharedPointer<Deferred<QSharedPointer<Coroutine>>>::create();
}

template<typename... CS>
QSharedPointer<Deferred<QSharedPointer<Coroutine>>> waitForAny(QSharedPointer<Coroutine> c1, CS... cs)
{
    QSharedPointer<Deferred<QSharedPointer<Coroutine>>> df = waitForAny(cs...);
    QWeakPointer<Coroutine> c1w = c1.toWeakRef();
    int callbackId = c1->finished.addCallback([c1w, df](BaseCoroutine *) {
        Q_ASSERT(!c1w.isNull());
        df->callback(c1w.toStrongRef());
    });

    df->addCallback([c1w, callbackId](QSharedPointer<Coroutine>) {
        if (!c1w.isNull()) {
            c1w.toStrongRef()->finished.remove(callbackId);
        }
    });
    return df;
}

template<typename... CS>
QSharedPointer<Coroutine> any(CS... cs)
{
    QSharedPointer<Deferred<QSharedPointer<Coroutine>>> df = waitForAny(cs...);
    QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>> event =
            QSharedPointer<ValueEvent<QSharedPointer<Coroutine>>>::create();
    df->addCallback([event](QSharedPointer<Coroutine> c) { event->send(c); });
    try {
        return event->tryWait();
    } catch (...) {
        df->callback(QSharedPointer<Coroutine>());
        throw;
    }
}

class Coroutine;
class CoroutineGroup : public QObject
{
public:
    CoroutineGroup();
    virtual ~CoroutineGroup();
public:
    bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString());
    bool add(Coroutine *coroutine, const QString &name = QString())
    {
        return add(QSharedPointer<Coroutine>(coroutine), name);
    }
    bool start(Coroutine *coroutine, const QString &name = QString()) { return add(coroutine->start(), name); }
    QSharedPointer<Coroutine> get(const QString &name);
    bool has(const QString &name);
    bool isCurrent(const QString &name);
    bool kill(const QString &name, bool join = true);
    bool killall(bool join = true);
    bool join(const QString &name);
    bool joinall();
    int size() const { return coroutines.size(); }
    bool isEmpty() const { return coroutines.isEmpty(); }
    QSharedPointer<Coroutine> any();

    inline QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func,
                                                   bool replace = false);
    inline QSharedPointer<Coroutine> spawn(const std::function<void()> &func);
    //    inline QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func);
    //    inline QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func,
    //    bool replace = false);

    template<typename T, typename S>
    static QList<T> map(std::function<T(S)> func, const QList<S> &l, int chunk = INT16_MAX)
    {
        CoroutineGroup operations;
        QSharedPointer<QList<T>> result(new QList<T>());
        QSharedPointer<Semaphore> semaphore(new Semaphore(chunk));
        for (int i = 0; i < l.size(); ++i) {
            result->append(T());
            S s = l[i];
            semaphore->tryAcquire();   // ALWAYS return true
            operations.spawn([func, s, result, i, semaphore]{
                try {
                    (*result)[i] = func(s);
                    semaphore->release();
                } catch (...) {
                    semaphore->release();
                    throw;
                }
            });
        }
        operations.joinall();
        return *result;
    }

    template<typename S>
    static void each(std::function<void(S)> func, const QList<S> &l, int chunk = INT16_MAX)
    {
        CoroutineGroup operations;
        QSharedPointer<Semaphore> semaphore(new Semaphore(chunk));
        for (int i = 0; i < l.size(); ++i) {
            semaphore->tryAcquire();   // ALWAYS return true
            S s = l[i];
            operations.spawn([func, s, semaphore] {
                try {
                    func(s);
                    semaphore->release();
                } catch (...) {
                    semaphore->release();
                    throw;
                }
            });
        }
        operations.joinall();
    }

    template<typename T, typename S>
    T apply(std::function<T(S)> func, S s)
    {
        QSharedPointer<T> result(new T);
        QSharedPointer<Coroutine> t = spawn([func, result, s] { (*result) = func(s); });
        t->join();
        return *result;
    }
private:
    void deleteCoroutine(BaseCoroutine *coroutine);
private:
    QSet<QSharedPointer<Coroutine>> coroutines;
};

QSharedPointer<Coroutine> CoroutineGroup::spawnWithName(const QString &name, const std::function<void()> &func,
                                                        bool replace)
{
    QSharedPointer<Coroutine> old = get(name);
    if (!old.isNull()) {
        if (replace) {
            old->kill();
            coroutines.remove(old);
            old->join();
        } else {
            return old;
        }
    }
    QSharedPointer<Coroutine> coroutine(Coroutine::spawn(func));
    add(coroutine, name);
    return coroutine;
}

QSharedPointer<Coroutine> CoroutineGroup::spawn(const std::function<void()> &func)
{
    QSharedPointer<Coroutine> coroutine(Coroutine::spawn(func));
    add(coroutine);
    return coroutine;
}

// QSharedPointer<Coroutine> CoroutineGroup::spawnInThread(const std::function<void ()> &func)
//{
//     QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
//     add(coroutine);
//     return coroutine;
// }

// QSharedPointer<Coroutine> CoroutineGroup::spawnInThreadWithName(const QString &name, const std::function<void()>
// &func, bool replace)
//{
//     QSharedPointer<Coroutine> old = get(name);
//     if (!old.isNull()) {
//         if (replace) {
//             old->kill();
//             coroutines.removeOne(old);
//             old->join();
//         } else {
//             return old;
//         }
//     }
//     QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
//     add(coroutine, name);
//     return coroutine;
// }

namespace detail {
// see
// https://stackoverflow.com/questions/2097811/c-syntax-for-explicit-specialization-of-a-template-function-in-a-template-clas
struct NormalType
{
};
struct VoidType
{
};
template<typename T>
struct ApplyDispatchTag
{
    using Tag = NormalType;
};
template<>
struct ApplyDispatchTag<void>
{
    using Tag = VoidType;
};
}  // namespace detail

class ThreadPool : public QObject
{
public:
    ThreadPool(int threads = 0);
    virtual ~ThreadPool() override;
public:
    template<typename T, typename S>
    QList<T> map(std::function<T(S)> func, const QList<S> &l, int chunk = INT16_MAX);

    template<typename S>
    void each(std::function<void(S)> func, const QList<S> &l, int chunk = INT16_MAX);

    template<typename T, typename Func, typename... ARGS>
    T apply(Func func, ARGS... s);

    template<typename T>
    T call(std::function<T()> func);

    void call(std::function<void()> func);
private:
    template<typename T, typename Func, typename... ARGS>
    T apply_dispatch(Func func, detail::NormalType, ARGS... args);
    template<typename T, typename Func, typename... ARGS>
    T apply_dispatch(Func func, detail::VoidType, ARGS... args);
private:
    QList<QSharedPointer<class ThreadPoolWorkThread>> threads;
    QSharedPointer<Semaphore> semaphore;
};

template<typename T, typename S>
QList<T> ThreadPool::map(std::function<T(S)> func, const QList<S> &l, int chunk/* = INT16_MAX*/)
{
    std::function<T(S)> f = [this, func] (S s) -> T {
        std::function<T()> wrapped = [s, func] () -> T { return func(s); };
        return call(wrapped);
    };
    return CoroutineGroup::map(f, l, chunk);
}

template<typename S>
void ThreadPool::each(std::function<void(S)> func, const QList<S> &l, int chunk/* = INT16_MAX*/)
{
    std::function<void(S)> f = [this, func] (S s) {
        std::function<void()> wrapped = [s, func] { func(s); };
        call(wrapped);
    };
    CoroutineGroup::each(f, l, chunk);
}

template<typename T, typename Func, typename... ARGS>
T ThreadPool::apply(Func func, ARGS... args)
{
    return apply_dispatch<T, Func, ARGS...>(func, typename detail::ApplyDispatchTag<T>::Tag{}, args...);
}

template<typename T, typename Func, typename... ARGS>
T ThreadPool::apply_dispatch(Func func, detail::NormalType, ARGS... args)
{
    QSharedPointer<T> result(new T());
    std::function<void()> wrapped = [func, result, args...] { *result = func(args...); };
    call(wrapped);
    return *result;
}

template<typename T, typename Func, typename... ARGS>
T ThreadPool::apply_dispatch(Func func, detail::VoidType, ARGS... args)
{
    std::function<void()> wrapped = [func, args...] { func(args...); };
    call(wrapped);
}

template<typename T>
T ThreadPool::call(std::function<T()> func)
{
    QSharedPointer<T> result(new T());
    std::function<void()> wrapped = [result, func] { *result = func(); };
    call(wrapped);
    return *result;
}

#if QT_VERSION < QT_VERSION_CHECK(5, 7, 0)

namespace detail {
    class SetEventHelper: public QObject
    {
        Q_OBJECT
    public:
        SetEventHelper(QSharedPointer<Event> event)
            : event(event) {}
    public slots:
        void set() { event->set(); }
    private:
        QSharedPointer<Event> event;
    };
}

#endif


QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_COROUTINE_UTILS_H
