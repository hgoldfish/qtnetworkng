#ifndef QTNG_COROUTINE_P_H
#define QTNG_COROUTINE_P_H

#include <QtCore/QThreadStorage>
#include "coroutine.h"

// this file is not used by other code, but just a stub figure out how to write a new coroutine implementation.

QTNETWORKNG_NAMESPACE_BEGIN

class QBaseCoroutinePrivate;
class QBaseCoroutinePrivatePlatformCommon
{
public:
    QBaseCoroutinePrivatePlatformCommon(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize);
    virtual ~QBaseCoroutinePrivatePlatformCommon();
    bool raise(QCoroutineException *exception = 0);
    bool yield();
protected:
    QBaseCoroutine * const q_ptr;
    QBaseCoroutine * const previous;
    size_t stackSize;
    void *stack;
    enum QBaseCoroutine::State state;
    bool bad;
    QCoroutineException *exception;
    Q_DECLARE_PUBLIC(QBaseCoroutine)
};


QBaseCoroutine* createMainCoroutine();

// 开始声明 CurrentCoroutineStorage

class CurrentCoroutineStorage
{
public:
    QBaseCoroutine *get();
    void set(QBaseCoroutine *coroutine);
    void clean();
private:
    struct CurrentCoroutine
    {
        QBaseCoroutine *value;
    };
    QThreadStorage<CurrentCoroutine> storage;
};

CurrentCoroutineStorage &currentCoroutine();

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_P_H

