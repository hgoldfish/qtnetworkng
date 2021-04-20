#include <stdlib.h>
#include <errno.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <QtCore/qdebug.h>
#include <QtCore/qlist.h>
#include "../include/private/coroutine_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

class BaseCoroutinePrivate
{
public:
    BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize);
    ~BaseCoroutinePrivate();
    bool initContext();
    bool raise(CoroutineException *exception = nullptr);
    bool yield();
private:
    BaseCoroutine * const q_ptr;
    BaseCoroutine * previous;
    size_t stackSize;
    void *stack;
    CoroutineException *exception;
    ucontext_t *context;
    enum BaseCoroutine::State state;
    bool bad;
    Q_DECLARE_PUBLIC(BaseCoroutine)
private:
    static void run_stub(BaseCoroutinePrivate *coroutine);
    void cleanup() { q_ptr->cleanup(); }
    friend BaseCoroutine* createMainCoroutine();
};


void BaseCoroutinePrivate::run_stub(BaseCoroutinePrivate *coroutine)
{
    coroutine->state = BaseCoroutine::Started;
    coroutine->q_ptr->started.callback(coroutine->q_ptr);
    try {
        coroutine->q_ptr->run();
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
    } catch(const CoroutineExitException &) {
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
    } catch(const CoroutineException &) {
//        qDebug() << "got coroutine exception:" << e.what();
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
    } catch(...) {
        qWarning() << "coroutine throw a unhandled exception.";
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
//        throw; // cause undefined behaviors
    }
    coroutine->cleanup();
}


BaseCoroutinePrivate::BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), stack(nullptr),
      exception(nullptr), context(nullptr), state(BaseCoroutine::Initialized), bad(false)
{
    if (stackSize) {
#ifdef MAP_GROWSDOWN
        stack = mmap(nullptr, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
#else
        stack = mmap(nullptr, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        if (!stack) {
            qWarning("Coroutine can not malloc new memroy.");
            bad = true;
        }
    }
}


BaseCoroutinePrivate::~BaseCoroutinePrivate()
{
    Q_Q(BaseCoroutine);
    if (state == BaseCoroutine::Started) {
        qWarning() << "deleting running BaseCoroutine" << this;
    }
    if (stack) {
        munmap(stack, stackSize);
    }

    if (currentCoroutine().get() == q) {
        qWarning("do not delete one self.");
    }
    if (context) {
        delete context;
    }
    if (exception) {
        qWarning("BaseCoroutine->exception should always be kept null.");
        //delete exception;
    }
}


bool BaseCoroutinePrivate::yield()
{
    Q_Q(BaseCoroutine);

    if (bad || (state != BaseCoroutine::Initialized && state != BaseCoroutine::Started)) {
        qWarning("invalid coroutine state.");
        return false;
    }

    if (!initContext())
        return false;

    BaseCoroutine *old = currentCoroutine().get();
    if (!old) {
        qWarning("can not get old coroutine.");
        return false;
    }
    if (old == q) {
        qWarning("yield to myself. did you call blocking functions in eventloop?");
        return false;
    }

    currentCoroutine().set(q);

    if (swapcontext(old->d_func()->context, this->context) < 0) {
        qDebug() << "swapcontext() return error: " << errno;
        return false;
    }
    if (currentCoroutine().get() != old) { // when coroutine finished, swapcontext auto yield to the previous.
        currentCoroutine().set(old);
    }
    CoroutineException *e = old->dd_ptr->exception;
    if (e) {
        old->d_func()->exception = nullptr;
        e->raise();
    }
    return true;
}


bool BaseCoroutinePrivate::initContext()
{
    if (context)
        return true;

    context = new ucontext_t;
    if (!context) {
        qWarning("Coroutine can not malloc new memroy.");
        bad = true;
        return false;
    }
    if (getcontext(context) < 0) {
        qDebug() <<"getcontext() return error." << errno;
        bad = true;
        return false;
    }
    context->uc_stack.ss_sp = stack;
    context->uc_stack.ss_size = stackSize;
    if (previous) {
        context->uc_link = previous->dd_ptr->context;
    } else {
        context->uc_link = nullptr;
    }
    makecontext(context, (void(*)(void))run_stub, 1, this);
    return true;
}


bool BaseCoroutinePrivate::raise(CoroutineException *exception)
{
    Q_Q(BaseCoroutine);
    if (!exception) {
        qWarning("can not kill coroutine with null exception.");
        return false;
    }
    if (currentCoroutine().get() == q) {
        qWarning("can not kill oneself.");
        delete exception;
        return false;
    }

    if (this->exception) {
        qWarning("coroutine had been killed.");
        delete exception;
        return false;
    }

    if (state == BaseCoroutine::Stopped || state == BaseCoroutine::Joined) {
        qWarning("coroutine is stopped.");
        delete exception;
        return false;
    }

    this->exception = exception;
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
    BaseCoroutine *main = new BaseCoroutine(nullptr, 0);
    if (!main)
        return nullptr;
    BaseCoroutinePrivate *mainPrivate = main->dd_ptr;
    mainPrivate->context = new ucontext_t;
    if (!mainPrivate->context) {
        qWarning("Coroutine can not malloc new memroy.");
        delete main;
        return nullptr;
    }
    if (getcontext(mainPrivate->context) < 0) {
        qDebug() << "getcontext() returns error." << errno;
        delete main;
        return nullptr;
    }
    mainPrivate->state = BaseCoroutine::Started;
    return main;
}


BaseCoroutine::BaseCoroutine(BaseCoroutine * previous, size_t stackSize)
    :dd_ptr(new BaseCoroutinePrivate(this, previous, stackSize))
{

}


BaseCoroutine::~BaseCoroutine()
{
    delete dd_ptr;
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


void BaseCoroutine::cleanup()
{
    Q_D(BaseCoroutine);
    if(d->previous) {
        d->previous->yield();
    }
}


BaseCoroutine *BaseCoroutine::previous() const
{
    Q_D(const BaseCoroutine);
    return d->previous;
}


void BaseCoroutine::setPrevious(BaseCoroutine *previous)
{
    Q_D(BaseCoroutine);
    d->previous = previous;
}

QTNETWORKNG_NAMESPACE_END
