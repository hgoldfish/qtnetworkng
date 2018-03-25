#include "../include/coroutine_p.h"
#include <windows.h>
#include <winbase.h>

QTNETWORKNG_NAMESPACE_BEGIN

class BaseCoroutinePrivate
{
public:
    BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize);
    virtual ~BaseCoroutinePrivate();
    bool initContext();
    bool raise(CoroutineException *exception = 0);
    bool yield();
private:
    BaseCoroutine * const q_ptr;
    BaseCoroutine * const previous;
    size_t stackSize;
    enum BaseCoroutine::State state;
    bool bad;
    CoroutineException *exception;
    LPVOID context;
    Q_DECLARE_PUBLIC(QBaseCoroutine)
private:
    static void CALLBACK run_stub(BaseCoroutinePrivate *coroutine);
    friend BaseCoroutine* createMainCoroutine();
};

void CALLBACK BaseCoroutinePrivate::run_stub(BaseCoroutinePrivate *coroutine)
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
        qWarning("coroutine throw a unhandled exception.");
        coroutine->state = BaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
        //throw; // cause undefined behaviors
    }
    SwitchToFiber(coroutine->previous->d_ptr->context);
}


BaseCoroutinePrivate::BaseCoroutinePrivate(BaseCoroutine *q, BaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), state(BaseCoroutine::Initialized), bad(false), exception(0), context(NULL)
{

}

BaseCoroutinePrivate::~BaseCoroutinePrivate()
{
    Q_Q(BaseCoroutine);
    if(currentCoroutine().get() == q)
    {
        //TODO 在当前 coroutine 里面把自己给干掉了怎么办？
        qWarning("do not delete one self.");
    }
    if(context) {
        if(Q_UNLIKELY(stackSize == 0)) {
            ConvertFiberToThread();
        } else {
            DeleteFiber(context);
        }
    }
    if(exception)
        delete exception;
}

bool BaseCoroutinePrivate::initContext()
{
    if(context)
        return true;

    context = CreateFiberEx(1024*4, stackSize, 0, (PFIBER_START_ROUTINE)BaseCoroutinePrivate::run_stub, this);
    if(context == NULL) {
        DWORD error = GetLastError();
        qDebug() << QStringLiteral("can not create fiber: error is %1").arg(error);
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
    if(currentCoroutine().get() == q)
    {
        qWarning("can not kill oneself.");
        return false;
    }

    if(this->exception)
    {
        qWarning("coroutine had been killed.");
        return false;
    }

    if(state == BaseCoroutine::Stopped || state == BaseCoroutine::Joined)
    {
        qWarning("coroutine is stopped.");
        return false;
    }

    if(exception)
        this->exception = exception;
    else
        this->exception = new CoroutineExitException();

    return yield();
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
    //qDebug() << "yield from " << old << "to" << q;
    SwitchToFiber(context);
    if(currentCoroutine().get() != old)  // when coroutine finished, swapcontext auto yield to the previous.
    {
        currentCoroutine().set(old);
    }
    CoroutineException *e = old->d_ptr->exception;
    if(e) {
        old->d_ptr->exception = 0;
        if(!dynamic_cast<CoroutineExitException*>(e)) {
            qDebug() << "got exception:" << e->what() << old;
        }
        e->raise();
    }
    return true;
}

BaseCoroutine* createMainCoroutine()
{
    BaseCoroutine *main = new BaseCoroutine(0, 0);
    if(!main)
        return 0;
    BaseCoroutinePrivate *mainPrivate = main->d_ptr;
#if ( _WIN32_WINNT > 0x0600)
        if ( IsThreadAFiber() ) {
            mainPrivate->context = GetCurrentFiber();
        } else {
            mainPrivate->context = ConvertThreadToFiberEx(NULL, 0);
        }
#else
        mainPrivate->context = ConvertThreadToFiberEx(NULL, 0);
        if(Q_UNLIKELY( NULL == mainPrivate->context) ) {
            DWORD err = GetLastError();
            if(err == ERROR_ALREADY_FIBER) {
                mainPrivate->context = GetCurrentFiber();
            }
            if(reinterpret_cast<LPVOID>(0x1E00) == mainPrivate->context) {
                mainPrivate->context = 0;
            }
        }
#endif
    if(mainPrivate->context == NULL)
    {
        DWORD error = GetLastError();
        qDebug() << QStringLiteral("Coroutine can not malloc new memroy: error is %1").arg(error);
        delete main;
        return 0;
    }
    mainPrivate->state = BaseCoroutine::Started;
    return main;
}


// here comes the public class.
BaseCoroutine::BaseCoroutine(BaseCoroutine *previous, size_t stackSize)
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

QTNETWORKNG_NAMESPACE_END
