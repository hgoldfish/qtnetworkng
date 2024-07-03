#ifndef QTNG_COROUTINE_H
#define QTNG_COROUTINE_H

#include <QtCore/qobject.h>
#include <QtCore/qstring.h>
#include "config.h"
#include "deferred.h"

#ifndef DEFAULT_COROUTINE_STACK_SIZE
#ifdef Q_OS_ANDROID
#define DEFAULT_COROUTINE_STACK_SIZE 1024 * 64
#else
#define DEFAULT_COROUTINE_STACK_SIZE 1024 * 256
#endif
#endif

QTNETWORKNG_NAMESPACE_BEGIN

class CoroutineException
{
public:
    explicit CoroutineException();
    CoroutineException(CoroutineException &);
    virtual ~CoroutineException();
    virtual void raise();
    virtual QString what() const;
    virtual CoroutineException *clone() const;
};

class CoroutineExitException : public CoroutineException
{
public:
    explicit CoroutineExitException();
    virtual void raise() override;
    virtual QString what() const override;
    virtual CoroutineException *clone() const override;
};

class CoroutineInterruptedException : public CoroutineException
{
public:
    explicit CoroutineInterruptedException();
    virtual void raise() override;
    virtual QString what() const override;
    virtual CoroutineException *clone() const override;
};

class BaseCoroutinePrivate;
class BaseCoroutine : public QObject
{
    Q_DISABLE_COPY(BaseCoroutine)
public:
    enum State {
        Initialized,
        Started,
        Stopped,
        Joined,
    };
    explicit BaseCoroutine(BaseCoroutine *previous, size_t stackSize = DEFAULT_COROUTINE_STACK_SIZE);
    virtual ~BaseCoroutine();

    virtual void run();

    State state() const;
    bool isRunning() const;
    bool isFinished() const;

    bool raise(CoroutineException *exception);
    bool yield();
    quintptr id() const;

    BaseCoroutine *previous() const;
    void setPrevious(BaseCoroutine *previous);

    static BaseCoroutine *current();
public:
    Deferred<BaseCoroutine *> started;
    Deferred<BaseCoroutine *> finished;
protected:
    void setState(BaseCoroutine::State state);
    virtual void cleanup();
private:
    BaseCoroutinePrivate * const dd_ptr;
    friend BaseCoroutine *createMainCoroutine();
    Q_DECLARE_PRIVATE_D(dd_ptr, BaseCoroutine)
};

template<typename T>
class Iterator
{
public:
    Iterator(std::function<void(Iterator &itor)> func);
    ~Iterator();
    bool next(T &result);
    void yield(const T &t);
public:
    BaseCoroutine *caller;
    BaseCoroutine *callee;
    T result;
};

namespace internal {
template<typename T>
class IteratorCoroutine : public BaseCoroutine
{
public:
    IteratorCoroutine(Iterator<T> &itor, std::function<void(Iterator<T> &)> func)
        : BaseCoroutine(BaseCoroutine::current())
        , itor(itor)
        , func(func)
    {
    }

    virtual void run() override { func(itor); }

    Iterator<T> &itor;
    std::function<void(Iterator<T> &itor)> func;
};
}  // namespace internal

template<typename T>
Iterator<T>::Iterator(std::function<void(Iterator &itor)> func)
    : caller(BaseCoroutine::current())
    , callee(new internal::IteratorCoroutine<T>(*this, func))
{
}

template<typename T>
Iterator<T>::~Iterator()
{
    if (callee->isRunning()) {
        callee->raise(new CoroutineExitException());
    }
    delete callee;
}

template<typename T>
bool Iterator<T>::next(T &result)
{
    if (callee->isFinished()) {
        result = T();
        return true;
    } else if (callee->state() == BaseCoroutine::Initialized) {
        callee->yield();
    } else {
        Q_ASSERT(callee->isRunning());
    }
    callee->yield();
    result = this->result;
    return callee->isFinished();
}

template<typename T>
void Iterator<T>::yield(const T &t)
{
    result = t;
    caller->yield();
}

QTNETWORKNG_NAMESPACE_END

class QDebug;
QDebug &operator<<(QDebug &out, const QTNETWORKNG_NAMESPACE::BaseCoroutine &coroutine);

#endif  // QTNG_COROUTINE_H
