#ifndef COROUTINE_UTILS_H
#define COROUTINE_UTILS_H
#include <QObject>
#include <QVariant>
#include <QThread>
#include <functional>
#include <QSharedPointer>
#include "locks.h"
#include "eventloop.h"

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
    Q_ASSERT(static_cast<QBaseCoroutine*>(EventLoopCoroutine::get()) != QBaseCoroutine::current());

    QSharedPointer<T> result(new T());
    QSharedPointer<Event> done(new Event());

    auto wrapper = [result, done, func]() mutable
    {
        result.reset(func());
        done->set();
    };

    int callbackId = EventLoopCoroutine::get()->callLater(0, new LambdaFunctor(wrapper));
    try
    {
        done->wait();
        EventLoopCoroutine::get()->cancelCall(callbackId);
    }
    catch(...)
    {
        EventLoopCoroutine::get()->cancelCall(callbackId);
        throw;
    }
    return *result;
}


inline void callInEventLoop(std::function<void ()> func)
{
    Q_ASSERT(static_cast<QBaseCoroutine*>(EventLoopCoroutine::get()) != QBaseCoroutine::current());

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
    DeferCallThread(const std::function<void()> &func, const std::function<void()> &callback);
    virtual void run();
private:
    std::function<void()> func;
    std::function<void()> callback;
};


template<typename T>
T callInThread(std::function<T()> func)
{

    QSharedPointer<T> result(new T());
    YieldCurrentFunctor *functor = new YieldCurrentFunctor();
    QPointer<EventLoopCoroutine> eventloop = EventLoopCoroutine::get();

    auto makeResult = [result, func]() mutable
    {
        *result = func();
    };
    auto callback = [eventloop, functor]()
    {
        if(!eventloop.isNull())
        {
            eventloop->callLaterThreadSafe(0, functor);
        }
    };
    DeferCallThread thread(makeResult, callback);
    thread.start();
    eventloop->yield();
    thread.wait();
    return *result;
}


inline void callInThread(const std::function<void ()> &func)
{
    QSharedPointer<Event> done(new Event());
    auto callback = [done]()
    {
        if(done.isNull())
            return;
        done->set();
    };
    DeferCallThread thread(func, callback);
    thread.start();
    done->wait();
}


struct NewThreadCoroutine:public QCoroutine
{
    NewThreadCoroutine(const std::function<void ()> &func)
        :func(func) {}
    std::function<void ()> func;
    void run()
    {
        callInThread(func);
    }
};


inline QCoroutine *spawnInThread(const std::function<void ()> &func)
{
    QCoroutine *coroutine = new NewThreadCoroutine(func);
    coroutine->start();
    return coroutine;
}


class QCoroutine;

class CoroutineGroup: public QObject
{
    Q_OBJECT
public:
    CoroutineGroup();
    virtual ~CoroutineGroup();
public:
    bool add(QCoroutine *coroutine, const QString &name = QString());
    QCoroutine *get(const QString &name);
    bool kill(const QString &name);
    bool killall(bool join = true);
    bool joinall();

    inline void spawnWithName(const QString &name, const std::function<void()> &func, bool one = true);
    inline void spawn(const std::function<void()> &func);
    inline void spawnInThread(const std::function<void()> &func);
    inline void spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool one = true);
private slots:
    void deleteCoroutine();
private:
    QList<QCoroutine*> coroutines;
};


void CoroutineGroup::spawnWithName(const QString &name, const std::function<void ()> &func, bool one)
{
    if(one && get(name) != 0) {
        if(get(name)->isActive())
            return;
        kill(name);
    }
    QCoroutine *coroutine = QCoroutine::spawn(func);
    add(coroutine, name);
}


void CoroutineGroup::spawn(const std::function<void ()> &func)
{
    QCoroutine *coroutine = QCoroutine::spawn(func);
    add(coroutine);
}


void CoroutineGroup::spawnInThread(const std::function<void ()> &func)
{
    QCoroutine *coroutine = ::spawnInThread(func);
    add(coroutine);
}


void CoroutineGroup::spawnInThreadWithName(const QString &name, const std::function<void()> &func, bool one)
{
    if(one && get(name) != 0){
        return;
    }
    QCoroutine *coroutine = ::spawnInThread(func);
    add(coroutine, name);
}


#endif // COROUTINE_UTILS_H
