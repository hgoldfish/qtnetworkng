#ifndef QTNG_COROUTINE_P_H
#define QTNG_COROUTINE_P_H

#include <QtCore/qthreadstorage.h>
#include "../coroutine.h"

QTNETWORKNG_NAMESPACE_BEGIN

// this class is not used by other code, but just a stub figure out how to write a new coroutine implementation.
class BaseCoroutinePrivate;
class BaseCoroutinePrivatePlatformCommon
{
public:
    BaseCoroutinePrivatePlatformCommon(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize);
    virtual ~BaseCoroutinePrivatePlatformCommon();
    bool raise(CoroutineException *exception = 0);
    bool yield();
protected:
    BaseCoroutine * const q_ptr;
    BaseCoroutine * const previous;
    size_t stackSize;
    void *stack;
    enum BaseCoroutine::State state;
    bool bad;
    CoroutineException *exception;
    Q_DECLARE_PUBLIC(BaseCoroutine)
};


BaseCoroutine* createMainCoroutine();

// 开始声明 CurrentCoroutineStorage

class CurrentCoroutineStorage
{
public:
    BaseCoroutine *get();
    void set(BaseCoroutine *coroutine);
    void clean();
private:
    struct CurrentCoroutine
    {
        BaseCoroutine *value;
    };
    QThreadStorage<CurrentCoroutine> storage;
};

CurrentCoroutineStorage &currentCoroutine();

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_P_H

