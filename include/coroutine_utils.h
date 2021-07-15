#ifndef QTNG_COROUTINE_UTILS_H
#define QTNG_COROUTINE_UTILS_H
#include <functional>
#include <QtCore/qobject.h>
#include <QtCore/qvariant.h>
#include <QtCore/qthread.h>
#include <QtCore/qsharedpointer.h>
#include <QtCore/qqueue.h>
#include <QtCore/qmutex.h>
#include <QtCore/qwaitcondition.h>
#include "locks.h"
#include "private/eventloop_p.h"


QTNETWORKNG_NAMESPACE_BEGIN


template<typename T>
T callInEventLoop(std::function<T ()> func)
{
    Q_ASSERT(static_cast<BaseCoroutine*>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event());

    auto wrapper = [result, done, func]() mutable
    {
        *result = func();
        done->set();
    };

    int callbackId = EventLoopCoroutine::get()->callLater(0, new LambdaFunctor(wrapper));
    try {
        done->wait();
        EventLoopCoroutine::get()->cancelCall(callbackId);
    } catch(...) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
        throw;
    }
    return *result;
}


inline void callInEventLoop(std::function<void ()> func, quint32 msecs = 0)
{
    Q_ASSERT(static_cast<BaseCoroutine*>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<Event> done(new Event());

    auto wrapper = [done, func]() {
        func();
        done->set();
    };

    int callbackId = EventLoopCoroutine::get()->callLater(msecs, new LambdaFunctor(wrapper));
    try {
        done->wait();
        EventLoopCoroutine::get()->cancelCall(callbackId);
    } catch(...) {
        EventLoopCoroutine::get()->cancelCall(callbackId);
        throw;
    }
}


inline void callInEventLoopAsync(std::function<void ()> func, quint32 msecs = 0)
{
//    Q_ASSERT(static_cast<QBaseCoroutine*>(EventLoopCoroutine::get()) != QBaseCoroutine::current());
    EventLoopCoroutine::get()->callLater(msecs, new LambdaFunctor(func));
}


template<typename EventLoop>
void runLocalLoop(EventLoop *loop)
{
    callInEventLoop([loop]() {
        loop->exec();
    });
}


template <typename Obj>
void qAwait(const Obj *obj,
            const typename QtPrivate::FunctionPointer<void (Obj::*) ()>::Function signal)
{
    QSharedPointer<Event> event(new Event());
    const auto connection = QObject::connect(obj, signal, [event] () {
        event->set();
    }, Qt::DirectConnection);
    try {
        event->wait();
        QObject::disconnect(connection);
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}


template <typename ARG1, typename... ARGS>
struct QAwaitHelper1: QObject
{
    QAwaitHelper1(QSharedPointer<ValueEvent<ARG1>> event)
        : event(event) {}
    void call(ARG1 arg1, ARGS...) { event->send(arg1); }
    QSharedPointer<ValueEvent<ARG1>> event;
};


template <typename Obj, typename ARG1>
ARG1 qAwait(const Obj *obj,
            const typename QtPrivate::FunctionPointer<void (Obj::*) (ARG1 arg1)>::Function signal)
{
    QSharedPointer<ValueEvent<ARG1>> event(new ValueEvent<ARG1>());
    QAwaitHelper1<ARG1> helper(event);
    const auto connection = QObject::connect(obj, signal, &helper, &QAwaitHelper1<ARG1>::call, Qt::DirectConnection);
    try {
        return event->wait();
        QObject::disconnect(connection);
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}


template <typename... ARGS>
struct QAwaitHelper: QObject
{
    QAwaitHelper(QSharedPointer<ValueEvent<std::tuple<ARGS...>>> event)
        : event(event) {}
    void call(ARGS ... args) { event->send(std::tuple<ARGS...>(args...)); }
    QSharedPointer<ValueEvent<std::tuple<ARGS...>>> event;
};


template <typename Obj, typename ARG1, typename ARG2, typename... ARGS>
std::tuple<ARG1, ARGS...> qAwait(const Obj *obj,
            const typename QtPrivate::FunctionPointer<void (Obj::*) (ARG1, ARG2, ARGS...)>::Function signal)
{
    QSharedPointer<ValueEvent<std::tuple<ARG1, ARG2, ARGS...>>> event(new ValueEvent<std::tuple<ARG1, ARG2, ARGS...>>());
    QAwaitHelper<ARG1, ARG2, ARGS...> helper(event);
    const auto connection = QObject::connect(obj, signal, &helper, &QAwaitHelper<ARG1, ARG2, ARGS...>::call, Qt::DirectConnection);
    try {
        return event->wait();
        QObject::disconnect(connection);
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}


// XXX DO NOT DELETE ANYTHING IN CHILD THREADS.
class DeferCallThread: public QThread
{
public:
    DeferCallThread(std::function<void()> makeResult, QSharedPointer<Event> done, EventLoopCoroutine *eventloop);
    virtual void run() override;
private:
    std::function<void()> makeResult;
    QSharedPointer<Event> done;
    QPointer<EventLoopCoroutine> eventloop;
};


template<typename T>
T callInThread(std::function<T()> func)
{
    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event());
    std::function<void()> makeResult = [result, func]() mutable
    {
        *result = func();
    };

    DeferCallThread *thread = new DeferCallThread(makeResult, done, EventLoopCoroutine::get());
    thread->start();
    done->wait();
    return *result;
}


template<typename T, typename ARG1>
T callInThread(std::function<T(ARG1)> func, ARG1 arg1)
{
    return callInThread<T>([func, arg1] () -> T {
        return func(arg1);
    });
}


template<typename T, typename ARG1, typename ARG2>
T callInThread(std::function<T(ARG1, ARG2)> func, ARG1 arg1, ARG2 arg2)
{
    return callInThread<T>([func, arg1, arg2] () -> T {
        return func(arg1, arg2);
    });
}



template<typename T, typename ARG1, typename ARG2, typename ARG3>
T callInThread(std::function<T(ARG1, ARG2, ARG3)> func, ARG1 arg1, ARG2 arg2, ARG3 arg3)
{
    return callInThread<T>([func, arg1, arg2, arg3] () -> T {
        return func(arg1, arg2, arg3);
    });
}



inline void callInThread(const std::function<void ()> &func)
{
    QSharedPointer<Event> done(new Event());
    DeferCallThread *thread = new DeferCallThread(func, done, EventLoopCoroutine::get());
    thread->start();
    done->wait();
    //thread.wait();
}


class NewThreadCoroutine: public Coroutine
{
public:
    NewThreadCoroutine(const std::function<void ()> &func)
        :func(func) {}
    std::function<void ()> func;
    virtual void run() override;
};


inline Coroutine *spawnInThread(const std::function<void ()> &func)
{
    Coroutine *coroutine = new NewThreadCoroutine(func);
    coroutine->start();
    return coroutine;
}


class Coroutine;

class CoroutineGroup: public QObject
{
public:
    CoroutineGroup();
    virtual ~CoroutineGroup();
public:
    bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString());
    bool add(Coroutine *coroutine, const QString &name = QString()) {return add(QSharedPointer<Coroutine>(coroutine), name);}
    bool start(Coroutine *coroutine, const QString &name = QString()) { return add(coroutine->start(), name); }
    QSharedPointer<Coroutine> get(const QString &name);
    bool has(const QString &name);
    bool kill(const QString &name, bool join = true);
    bool killall(bool join = true);
    bool joinall();
    int size() const { return coroutines.size(); }
    bool isEmpty() const { return coroutines.isEmpty(); }

    inline QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func, bool replace = false);
    inline QSharedPointer<Coroutine> spawn(const std::function<void()> &func);
    inline QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func);
    inline QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool replace = false);

    template <typename T, typename S>
    static QList<T> map(std::function<T(S)> func, const QList<S> &l, int chunk = INT16_MAX)
    {
        CoroutineGroup operations;
        QSharedPointer<QList<T>> result(new QList<T>());
        QSharedPointer<Semaphore> semaphore(new Semaphore(chunk));
        for (int i = 0; i < l.size(); ++i) {
            result->append(T());
            S s = l[i];
            semaphore->acquire();   // ALWAYS return true
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

    template <typename S>
    static void each(std::function<void(S)> func, const QList<S> &l, int chunk = INT16_MAX) {
        CoroutineGroup operations;
        QSharedPointer<Semaphore> semaphore(new Semaphore(chunk));
        for (int i = 0; i < l.size(); ++i) {
            semaphore->acquire();   // ALWAYS return true
            S s = l[i];
            operations.spawn([func, s, semaphore] {
                try {
                    func(s);
                    semaphore->release();
                }  catch (...) {
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
        QSharedPointer<Coroutine> t = spawn([func, result, s] {
            (*result) = func(s);
        });
        t->join();
        return *result;
    }

private:
    void deleteCoroutine(BaseCoroutine *coroutine);
private:
    QList<QSharedPointer<Coroutine>> coroutines;
};


QSharedPointer<Coroutine> CoroutineGroup::spawnWithName(const QString &name, const std::function<void ()> &func, bool replace)
{
    QSharedPointer<Coroutine> old = get(name);
    if (!old.isNull()) {
        if (replace) {
            old->kill();
            coroutines.removeOne(old);
            old->join();
        } else {
            return old;
        }
    }
    QSharedPointer<Coroutine> coroutine(Coroutine::spawn(func));
    add(coroutine, name);
    return coroutine;
}


QSharedPointer<Coroutine> CoroutineGroup::spawn(const std::function<void ()> &func)
{
    QSharedPointer<Coroutine> coroutine(Coroutine::spawn(func));
    add(coroutine);
    return coroutine;
}


QSharedPointer<Coroutine> CoroutineGroup::spawnInThread(const std::function<void ()> &func)
{
    QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
    add(coroutine);
    return coroutine;
}


QSharedPointer<Coroutine> CoroutineGroup::spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool replace)
{
    QSharedPointer<Coroutine> old = get(name);
    if (!old.isNull()) {
        if (replace) {
            old->kill();
            coroutines.removeOne(old);
            old->join();
        } else {
            return old;
        }
    }
    QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
    add(coroutine, name);
    return coroutine;
}


class ThreadPool: public QObject
{
public:
    ThreadPool(int threads = 0);
    virtual ~ThreadPool() override;
public:
    template<typename T, typename S>
    QList<T> map(std::function<T(S)> func, const QList<S> &l);

    template<typename S>
    void each(std::function<void(S)> func, const QList<S> &l);

    template<typename T, typename S>
    T apply(std::function<T(S)> func, S s);

    template<typename S>
    void apply(std::function<void(S)> func, S s);

    template<typename T>
    T call(std::function<T()> func);

    inline void call(std::function<void()> func);
private:
    // for map()
    template<typename T, typename S>
    std::function<T(S)> makeResult(std::function<T(S)> func);

    // for each()
    template<typename S>
    std::function<void(S)> makeResult(std::function<void(S)> func);

    QList<QSharedPointer<class ThreadPoolWorkThread>> threads;
    QSharedPointer<Semaphore> semaphore;
};


template<typename T, typename S>
QList<T> ThreadPool::map(std::function<T(S)> func, const QList<S> &l)
{
    std::function<T(S)> f = [this, func] (const S &s) -> T { return this->apply<T, S>(s); } ;
    return CoroutineGroup::map(f, l);
}


template<typename S>
void ThreadPool::each(std::function<void(S)> func, const QList<S> &l)
{
    std::function<void(S)> f = [this, func] (const S &s) -> void { this->apply<S>(s); } ;
    CoroutineGroup::each(f, l);
}


template<typename T, typename S>
T ThreadPool::apply(std::function<T(S)> func, S s)
{
    QSharedPointer<T> result(new T());
    std::function<void()> wrapped = [func, s, result] {
        *result = func(s);
    };
    call(wrapped);
    return *result;
}


template<typename S>
void ThreadPool::apply(std::function<void(S)> func, S s)
{
    std::function<void()> wrapped = [func, s] {
        func(s);
    };
    call(wrapped);
}


template<typename T>
T ThreadPool::call(std::function<T()> func)
{
    QSharedPointer<T> result(new T());
    std::function<void()> wrapped = [result, func] {
        *result = func();
    };
    call(wrapped);
    return *result;
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_UTILS_H
