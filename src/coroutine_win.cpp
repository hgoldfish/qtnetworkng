#include "../include/private/coroutine_p.h"
#include <windows.h>
#include <winbase.h>
#include <QtCore/qdebug.h>

QTNETWORKNG_NAMESPACE_BEGIN

class BaseCoroutinePrivate
{
public:
    BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize);
    virtual ~BaseCoroutinePrivate();
    bool initContext();
    bool raise(CoroutineException *exception = nullptr);
    bool yield();
    void cleanup() { q_ptr->cleanup(); }
public:
    BaseCoroutine * const q_ptr;
    BaseCoroutine * previous;
    size_t stackSize;
    enum BaseCoroutine::State state;
    CoroutineException *exception;
    LPVOID context;
    bool bad;
    Q_DECLARE_PUBLIC(BaseCoroutine)
};


void CALLBACK run_stub(BaseCoroutinePrivate *coroutine)
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
        qWarning("coroutine throw a unhandled exception.");
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
        //throw; // cause undefined behaviors
    }
    coroutine->cleanup();
}


BaseCoroutinePrivate::BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), state(BaseCoroutine::Initialized), exception(nullptr), context(nullptr),  bad(false)
{

}


BaseCoroutinePrivate::~BaseCoroutinePrivate()
{
    Q_Q(BaseCoroutine);
    if (currentCoroutine().get() == q) {
        qWarning("do not delete one self.");
    }
    if (context) {
        if(Q_UNLIKELY(stackSize == 0)) {
            ConvertFiberToThread();
        } else {
            DeleteFiber(context);
        }
    }
    if (exception) {
        qWarning("BaseCoroutine::exception should always be kept null.");
        // XXX we do not own the exception!
        // delete exception;
    }
}


bool BaseCoroutinePrivate::initContext()
{
    if (context) {
        return true;
    }

    context = CreateFiberEx(1024 * 4, stackSize, 0, (PFIBER_START_ROUTINE)run_stub, this);
    if (!context) {
        DWORD error = GetLastError();
        qWarning() << QString::fromLatin1("can not create fiber: error is %1").arg(error);
        bad = true;
        return false;
    } else {
        bad = false;
    }
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


bool BaseCoroutinePrivate::yield()
{
    Q_Q(BaseCoroutine);

    if (bad || (state != BaseCoroutine::Initialized && state != BaseCoroutine::Started)) {
        qWarning("invalid coroutine state.");
        return false;
    }

    if (!initContext()) {
        return false;
    }

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
    SwitchToFiber(context);
    if (currentCoroutine().get() != old) { // when coroutine finished, swapcontext auto yield to the previous.
        currentCoroutine().set(old);
    }
    CoroutineException *e = old->d_func()->exception;
    if (e) {
        old->d_func()->exception = nullptr;
        e->raise();
    }
    return true;
}


BaseCoroutine* createMainCoroutine()
{
    BaseCoroutine *main = new BaseCoroutine(nullptr, 0);
    if (!main) {
        return nullptr;
    }
    main->setObjectName(QString::fromLatin1("main"));
    BaseCoroutinePrivate *mainPrivate = main->d_func();
#if ( _WIN32_WINNT > 0x0600)
        if (IsThreadAFiber()) {
            mainPrivate->context = GetCurrentFiber();
        } else {
            mainPrivate->context = ConvertThreadToFiberEx(nullptr, 0);
        }
#else
        mainPrivate->context = ConvertThreadToFiber(nullptr);
        if (Q_UNLIKELY(nullptr== mainPrivate->context)) {
            DWORD err = GetLastError();
            if (err == ERROR_ALREADY_FIBER) {
                mainPrivate->context = GetCurrentFiber();
            }
            if (reinterpret_cast<LPVOID>(0x1E00) == mainPrivate->context) {
                mainPrivate->context = nullptr;
            }
        }
#endif
    if (!mainPrivate->context) {
        DWORD error = GetLastError();
        qWarning("Coroutine can not malloc new memroy: error is %d", error);
        delete main;
        return nullptr;
    }
    mainPrivate->state = BaseCoroutine::Started;
    return main;
}


// here comes the public class.
BaseCoroutine::BaseCoroutine(BaseCoroutine *previous, size_t stackSize)
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


void BaseCoroutine::setState(BaseCoroutine::State state)
{
    Q_D(BaseCoroutine);
    d->state = state;
}


void BaseCoroutine::cleanup()
{
    Q_D(BaseCoroutine);
    if (d->previous) {
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
