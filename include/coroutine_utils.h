#ifndef QTNG_COROUTINE_UTILS_H
#define QTNG_COROUTINE_UTILS_H
#include <functional>
#include <QtCore/qobject.h>
#include <QtCore/qvariant.h>
#include <QtCore/qthread.h>
#include <QtCore/qsharedpointer.h>
#include "locks.h"
#include "eventloop_p.h"


QTNETWORKNG_NAMESPACE_BEGIN

struct LambdaFunctor: public Functor
{
    LambdaFunctor(const std::function<void()> &callback)
        :callback(callback) {}
    virtual void operator ()();
    std::function<void()> callback;
};


template<typename T>
T callInEventLoop(std::function<T ()> func)
{
    Q_ASSERT(static_cast<BaseCoroutine*>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event());

    auto wrapper = [result, done, func]() mutable
    {
        result.reset(func());
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


inline void callInEventLoop(std::function<void ()> func)
{
    Q_ASSERT(static_cast<BaseCoroutine*>(EventLoopCoroutine::get()) != BaseCoroutine::current());

    QSharedPointer<Event> done(new Event());

    auto wrapper = [done, func]() {
        func();
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
}


inline void callInEventLoopAsync(std::function<void ()> func)
{
//    Q_ASSERT(static_cast<QBaseCoroutine*>(EventLoopCoroutine::get()) != QBaseCoroutine::current());
    EventLoopCoroutine::get()->callLater(0, new LambdaFunctor(func));
}


template<typename EventLoop>
void runLocalLoop(EventLoop *loop)
{
    callInEventLoop([loop]() {
        loop->exec();
    });
}


template <typename Func>
void qAwait(const typename QtPrivate::FunctionPointer<Func>::Object *obj, Func signal)
{
    QSharedPointer<Event> event(new Event);
    const auto connection = QObject::connect(obj, signal, [event] {
        event->set();
    });
    try {
        event->wait();
        QObject::disconnect(connection);
    } catch (...) {
        QObject::disconnect(connection);
        throw;
    }
}


class DeferCallThread: public QThread
{
public:
    DeferCallThread(const std::function<void()> &func, LambdaFunctor *yieldCoroutine, EventLoopCoroutine *eventloop);
    virtual void run();
private:
    std::function<void()> func;
    LambdaFunctor *yieldCoroutine;
    QPointer<EventLoopCoroutine> eventloop;
};


template<typename T>
T callInThread(std::function<T()> func)
{
    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event);
    
    LambdaFunctor *yieldCoroutine = new LambdaFunctor([done] { done->set(); });
    QPointer<EventLoopCoroutine> eventloop = EventLoopCoroutine::get();

    std::function<void()> makeResult = [result, func]() mutable
    {
        *result = func();
    };

    DeferCallThread *thread = new DeferCallThread(makeResult, yieldCoroutine, eventloop);
    thread->start();
    done->wait();
    return *result;
}


inline void callInThread(const std::function<void ()> &func)
{
    QSharedPointer<Event> done(new Event);
    LambdaFunctor *yieldCoroutine = new LambdaFunctor([done] { done->set(); });
    QPointer<EventLoopCoroutine> eventloop = EventLoopCoroutine::get();
    DeferCallThread *thread = new DeferCallThread(func, yieldCoroutine, eventloop);
    thread->start();
    done->wait();
    //thread.wait();
}


struct NewThreadCoroutine:public Coroutine
{
    NewThreadCoroutine(const std::function<void ()> &func)
        :func(func) {}
    std::function<void ()> func;
    void run()
    {
        callInThread(func);
    }
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
    static QList<T> map(std::function<T(S)> func, const QList<S> &l)
    {
        CoroutineGroup operations;
        QSharedPointer<QList<T>> result(new QList<T>());
        for(int i = 0; i < l.size(); ++i) {
            result->append(T());
            S s = l[i];
            operations.spawn([func, s, result, i]{
                (*result)[i] = func(s);
            });
        }
        operations.joinall();
        return *result;
    }

    template <typename S>
    static void each(std::function<void(S)> func, const QList<S> &l) {
        CoroutineGroup operations;
        for(int i = 0; i < l.size(); ++i) {
            S s = l[i];
            operations.add(Coroutine::spawn([func, s] {
                func(s);
            }));
        }
        operations.joinall();
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
        if (!old->isRunning()) {
            coroutines.removeOne(old);
        } else {
            if (replace) {
                old->kill();
                coroutines.removeOne(old);
            } else {
                return old;
            }
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
        if (!old->isRunning()) {
            coroutines.removeOne(old);
        } else {
            if (replace) {
                old->kill();
                coroutines.removeOne(old);
            } else {
                return old;
            }
        }
    }
    QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
    add(coroutine, name);
    return coroutine;
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_UTILS_H
