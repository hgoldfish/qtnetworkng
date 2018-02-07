#include "../include/coroutine_p.h"
#include <windows.h>
#include <winbase.h>

QTNETWORKNG_NAMESPACE_BEGIN

class QBaseCoroutinePrivate
{
public:
    QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize);
    virtual ~QBaseCoroutinePrivate();
    bool initContext();
    bool raise(QCoroutineException *exception = 0);
    bool yield();
private:
    QBaseCoroutine * const q_ptr;
    QBaseCoroutine * const previous;
    size_t stackSize;
    enum QBaseCoroutine::State state;
    bool bad;
    QCoroutineException *exception;
    LPVOID context;
    Q_DECLARE_PUBLIC(QBaseCoroutine)
private:
    static void CALLBACK run_stub(QBaseCoroutinePrivate *coroutine);
    friend QBaseCoroutine* createMainCoroutine();
};

void CALLBACK QBaseCoroutinePrivate::run_stub(QBaseCoroutinePrivate *coroutine)
{
    coroutine->state = QBaseCoroutine::Started;
    emit coroutine->q_ptr->started();
    try
    {
        coroutine->q_ptr->run();
        coroutine->state = QBaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(const QCoroutineExitException &e)
    {
        coroutine->state = QBaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(const QCoroutineException &e)
    {
        qDebug() << "got coroutine exception:" << e.what();
        coroutine->state = QBaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
    }
    catch(...)
    {
        qWarning("coroutine throw a unhandled exception.");
        coroutine->state = QBaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
        //throw; // cause undefined behaviors
    }
    SwitchToFiber(coroutine->previous->d_ptr->context);
}


QBaseCoroutinePrivate::QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), state(QBaseCoroutine::Initialized), bad(false), exception(0), context(NULL)
{

}

QBaseCoroutinePrivate::~QBaseCoroutinePrivate()
{
    Q_Q(QBaseCoroutine);
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

bool QBaseCoroutinePrivate::initContext()
{
    if(context)
        return true;

    context = CreateFiberEx(1024*4, stackSize, 0, (PFIBER_START_ROUTINE)QBaseCoroutinePrivate::run_stub, this);
    if(context == NULL) {
        DWORD error = GetLastError();
        qDebug() << QString::fromUtf8("can not create fiber: error is %1").arg(error);
        bad = true;
        return false;
    } else {
        bad = false;
    }
    return true;
}

bool QBaseCoroutinePrivate::raise(QCoroutineException *exception)
{
    Q_Q(QBaseCoroutine);
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

    if(state == QBaseCoroutine::Stopped || state == QBaseCoroutine::Joined)
    {
        qWarning("coroutine is stopped.");
        return false;
    }

    if(exception)
        this->exception = exception;
    else
        this->exception = new QCoroutineExitException();

    return yield();
}

bool QBaseCoroutinePrivate::yield()
{
    Q_Q(QBaseCoroutine);

    if(bad || (state != QBaseCoroutine::Initialized && state != QBaseCoroutine::Started))
        return false;

    if(!initContext())
        return false;

    QBaseCoroutine *old = currentCoroutine().get();
    if(!old || old == q)
        return false;

    currentCoroutine().set(q);
    //qDebug() << "yield from " << old << "to" << q;
    SwitchToFiber(context);
    if(currentCoroutine().get() != old)  // when coroutine finished, swapcontext auto yield to the previous.
    {
        currentCoroutine().set(old);
    }
    QCoroutineException *e = old->d_ptr->exception;
    if(e) {
        old->d_ptr->exception = 0;
        if(!dynamic_cast<QCoroutineExitException*>(e)) {
            qDebug() << "got exception:" << e->what() << old;
        }
        e->raise();
    }
    return true;
}

QBaseCoroutine* createMainCoroutine()
{
    QBaseCoroutine *main = new QBaseCoroutine(0, 0);
    if(!main)
        return 0;
    QBaseCoroutinePrivate *mainPrivate = main->d_ptr;
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
        qDebug() << QString::fromUtf8("QCoroutine can not malloc new memroy: error is %1").arg(error);
        delete main;
        return 0;
    }
    mainPrivate->state = QBaseCoroutine::Started;
    return main;
}


// here comes the public class.
QBaseCoroutine::QBaseCoroutine(QBaseCoroutine *previous, size_t stackSize)
    :d_ptr(new QBaseCoroutinePrivate(this, previous, stackSize))
{
}

QBaseCoroutine::~QBaseCoroutine()
{
    delete d_ptr;
}

QBaseCoroutine::State QBaseCoroutine::state() const
{
    Q_D(const QBaseCoroutine);
    return d->state;
}

bool QBaseCoroutine::raise(QCoroutineException *exception)
{
    Q_D(QBaseCoroutine);
    return d->raise(exception);
}

bool QBaseCoroutine::yield()
{
    Q_D(QBaseCoroutine);
    return d->yield();
}

void QBaseCoroutine::setState(QBaseCoroutine::State state)
{
    Q_D(QBaseCoroutine);
    d->state = state;
}

QTNETWORKNG_NAMESPACE_END
