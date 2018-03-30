#include <stdlib.h>
#include <errno.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <QtCore/QDebug>
#include <QtCore/QList>
#include "../include/coroutine_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

// 开始定义 CoroutinePrivate

class BaseCoroutinePrivate
{
public:
    BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize);
    ~BaseCoroutinePrivate();
    bool initContext();
    bool raise(CoroutineException *exception = 0);
    bool yield();
private:
    BaseCoroutine * const q_ptr;
    BaseCoroutine * const previous;
    size_t stackSize;
    void *stack;
    enum BaseCoroutine::State state;
    bool bad;
    CoroutineException *exception;
    ucontext_t *context;
    Q_DECLARE_PUBLIC(BaseCoroutine)
private:
    static void run_stub(BaseCoroutinePrivate *coroutine);
    friend BaseCoroutine* createMainCoroutine();
};


// 开始实现 CoroutinePrivate
void BaseCoroutinePrivate::run_stub(BaseCoroutinePrivate *coroutine)
{
    coroutine->state = BaseCoroutine::Started;
    emit coroutine->q_ptr->started();
    try
    {
        coroutine->q_ptr->run();
        coroutine->state = BaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(const CoroutineExitException &e)
    {
        coroutine->state = BaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(const CoroutineException &e)
    {
        qDebug() << "got coroutine exception:" << e.what();
        coroutine->state = BaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(...)
    {
        qWarning() << "coroutine throw a unhandled exception.";
        coroutine->state = BaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
//        throw; // cause undefined behaviors
    }
    swapcontext(coroutine->context, coroutine->previous->d_ptr->context);
}


BaseCoroutinePrivate::BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), stack(0), state(BaseCoroutine::Initialized),
      bad(false), exception(0), context(0)
{
    if(stackSize) {
//        stack = operator new(stackSize);
        stack = mmap(NULL, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
        if(!stack) {
            qFatal("Coroutine can not malloc new memroy.");
            bad = true;
            return;
        }
    } else {
        stack = 0;
    }
}


BaseCoroutinePrivate::~BaseCoroutinePrivate()
{
    Q_Q(BaseCoroutine);
    if(state == BaseCoroutine::Started) {
        qWarning() << "do not delete running QBaseCoroutine: %1";
    }
    if(stack) {
//        operator delete(stack);
        munmap(stack, stackSize);
    }

    if(currentCoroutine().get() == q)
    {
        //TODO 在当前 coroutine 里面把自己给干掉了怎么办？
        qWarning("do not delete one self.");
    }
    if(context)
        delete context;
    if(exception)
        delete exception;
}


bool BaseCoroutinePrivate::yield()
{
    Q_Q(BaseCoroutine);

    if(bad || (state != BaseCoroutine::Initialized && state != BaseCoroutine::Started))
        return false;

    if(!initContext())
        return false;

    BaseCoroutine *old = currentCoroutine().get();
    if(!old || old == q)
        return false;

    currentCoroutine().set(q);

    if(swapcontext(old->d_func()->context, this->context) < 0) {
        qDebug() << "swapcontext() return error: " << errno;
        return false;
    }
    if(currentCoroutine().get() != old) { // when coroutine finished, swapcontext auto yield to the previous.
        currentCoroutine().set(old);
    }
    CoroutineException *e = old->d_ptr->exception;
    if(e) {
        old->d_func()->exception = 0;
        if(!dynamic_cast<CoroutineExitException*>(e)) {
            qDebug() << "got exception:" << e->what() << old;
        }
        e->raise();
    }
    return true;
}

bool BaseCoroutinePrivate::initContext()
{
    if(context)
        return true;

    context = new ucontext_t;
    if(!context) {
        qFatal("Coroutine can not malloc new memroy.");
        bad = true;
        return false;
    }
    if(getcontext(context) < 0) {
        qDebug() <<"getcontext() return error." << errno;
        bad = true;
        return false;
    }
    context->uc_stack.ss_sp = stack;
    context->uc_stack.ss_size = stackSize;
    if(previous) {
        context->uc_link = previous->d_ptr->context;
    } else {
        context->uc_link = 0;
    }
    makecontext(context, (void(*)(void))run_stub, 1, this);
    return true;
}

bool BaseCoroutinePrivate::raise(CoroutineException *exception)
{
    Q_Q(BaseCoroutine);
    if(currentCoroutine().get() == q) {
        qWarning("can not kill oneself.");
        return false;
    }

    if(this->exception) {
        qWarning("coroutine had been killed.");
        return false;
    }

    if(state == BaseCoroutine::Stopped || state == BaseCoroutine::Joined) {
        qWarning("coroutine is stopped.");
        return false;
    }

    if(exception) {
        this->exception = exception;
    } else {
        this->exception = new CoroutineExitException();
    }
    try {
        bool result = yield();
        delete exception;
        return result;
    } catch (...) {
        delete exception;
        throw;
    }
}

BaseCoroutine* createMainCoroutine()
{
    BaseCoroutine *main = new BaseCoroutine(0, 0);
    if(!main)
        return 0;
    BaseCoroutinePrivate *mainPrivate = main->d_ptr;
    mainPrivate->context = new ucontext_t;
    if(!mainPrivate->context) {
        qFatal("Coroutine can not malloc new memroy.");
        delete main;
        return 0;
    }
    if(getcontext(mainPrivate->context) < 0) {
        qDebug() << "getcontext() returns error." << errno;
        delete main;
        return 0;
    }
    mainPrivate->state = BaseCoroutine::Started;
    return main;
}

// 开始实现 QBaseCoroutine
BaseCoroutine::BaseCoroutine(BaseCoroutine * previous, size_t stackSize)
    :d_ptr(new BaseCoroutinePrivate(this, previous, stackSize))
{

}

BaseCoroutine::~BaseCoroutine()
{
    delete d_ptr;
}


BaseCoroutine::State BaseCoroutine::state() const
{
    Q_D(const BaseCoroutine);
    return d->state;
}

void BaseCoroutine::setState(BaseCoroutine::State state)
{
    Q_D(BaseCoroutine);
    d->state = state;
}

bool BaseCoroutine::raise(CoroutineException *exception)
{
    Q_D(BaseCoroutine);
    return d->raise(exception);
}

bool BaseCoroutine::yield()
{
    Q_D(BaseCoroutine);
    return d->yield();
}


QTNETWORKNG_NAMESPACE_END
