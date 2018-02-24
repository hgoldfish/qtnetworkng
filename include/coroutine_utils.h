#ifndef QTNG_COROUTINE_UTILS_H
#define QTNG_COROUTINE_UTILS_H
#include <functional>
#include <QtCore/QObject>
#include <QtCore/QVariant>
#include <QtCore/QThread>
#include <QtCore/QSharedPointer>
#include "locks.h"
#include "eventloop.h"


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


class DeferCallThread: public QThread
{
    Q_OBJECT
public:
    DeferCallThread(const std::function<void()> &func, YieldCurrentFunctor *yieldCoroutine, QPointer<EventLoopCoroutine> eventloop);
    virtual void run();
private:
    std::function<void()> func;
    YieldCurrentFunctor *yieldCoroutine;
    QPointer<EventLoopCoroutine> eventloop;
};


template<typename T>
T callInThread(std::function<T()> func)
{
    QSharedPointer<T> result(new T());
    YieldCurrentFunctor *yieldCoroutine = new YieldCurrentFunctor();
    QPointer<EventLoopCoroutine> eventloop = EventLoopCoroutine::get();

    std::function<void()> makeResult = [result, func]() mutable
    {
        *result = func();
    };

    DeferCallThread *thread = new DeferCallThread(makeResult, yieldCoroutine, eventloop);
    thread->start();
    eventloop->yield();
    return *result;
}


inline void callInThread(const std::function<void ()> &func)
{
    YieldCurrentFunctor *yieldCoroutine = new YieldCurrentFunctor();
    QPointer<EventLoopCoroutine> eventloop = EventLoopCoroutine::get();
    DeferCallThread *thread = new DeferCallThread(func, yieldCoroutine, eventloop);
    thread->start();
    eventloop->yield();
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
    Q_OBJECT
public:
    CoroutineGroup();
    virtual ~CoroutineGroup();
public:
    bool add(QSharedPointer<Coroutine> coroutine, const QString &name = QString());
    bool add(Coroutine *coroutine, const QString &name = QString()) {return add(QSharedPointer<Coroutine>(coroutine), name);}
    bool start(Coroutine *coroutine, const QString &name = QString()) { return add(coroutine->start(), name); }
    QSharedPointer<Coroutine> get(const QString &name);
    bool kill(const QString &name);
    bool killall(bool join = true, bool skipMyself = false);
    bool joinall();
    int size() { return coroutines.size(); }

    inline QSharedPointer<Coroutine> spawnWithName(const QString &name, const std::function<void()> &func, bool one = true);
    inline QSharedPointer<Coroutine> spawn(const std::function<void()> &func);
    inline QSharedPointer<Coroutine> spawnInThread(const std::function<void()> &func);
    inline QSharedPointer<Coroutine> spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool one = true);

    template <typename T, typename S>
    QList<T> map(std::function<T(S)> func, const QList<S> &l)
    {
        QList<QSharedPointer<Coroutine>> coroutines;
        QSharedPointer<QList<T>> result(new QList<T>());
        for(int i = 0; i < l.size(); ++i) {
            result->append(T());
            S s = l[i];
            coroutines.append(Coroutine::spawn([func, s, result, i]{
                (*result)[i] = func(s);
            }));
        }
        for(int i = 0; i < coroutines.size(); ++i) {
            coroutines[i]->join();
        }
        return *result;
    }

    template <typename S>
    void each(std::function<void(S)> func, const QList<S> &l) {
        QList<QSharedPointer<Coroutine>> coroutines;
        for(int i = 0; i < l.size(); ++i) {
            S s = l[i];
            coroutines.append(Coroutine::spawn([func, s] {
                func(s);
            }));
        }
        for(int i = 0; i < coroutines.size(); ++i) {
            coroutines[i]->join();
        }
    }

private slots:
    void deleteCoroutine();
private:
    QList<QSharedPointer<Coroutine>> coroutines;
};


QSharedPointer<Coroutine> CoroutineGroup::spawnWithName(const QString &name, const std::function<void ()> &func, bool one)
{
    QSharedPointer<Coroutine> old = get(name);
    if(one && !old.isNull()) {
        if(old->isActive())
            return old;
        kill(name);
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


QSharedPointer<Coroutine> CoroutineGroup::spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool one)
{
    QSharedPointer<Coroutine> old = get(name);
    if(one && !old.isNull()) {
        if(old->isActive())
            return old;
        kill(name);
    }
    QSharedPointer<Coroutine> coroutine(QTNETWORKNG_NAMESPACE::spawnInThread(func));
    add(coroutine, name);
    return coroutine;
}


QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_UTILS_H
