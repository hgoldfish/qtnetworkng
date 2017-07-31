#include <stdlib.h>
#include <errno.h>
#include <QDebug>
#include <ucontext.h>
#include <qlist.h>
#include "coroutine_p.h"

// 开始定义 QCoroutinePrivate

class QBaseCoroutinePrivate;
static void run_stub(QBaseCoroutinePrivate *coroutine);

class QBaseCoroutinePrivate
{
public:
    QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize);
    ~QBaseCoroutinePrivate();
    bool initContext();
    bool kill(QCoroutineException *exception = 0);
    bool yield();
private:
    QBaseCoroutine * const q_ptr;
    QBaseCoroutine * const previous;
    size_t stackSize;
    void *stack;
    enum QBaseCoroutine::State state;
    bool bad;
    QCoroutineException *exception;
    ucontext_t *context;
    Q_DECLARE_PUBLIC(QBaseCoroutine)
private:
    friend void run_stub(QBaseCoroutinePrivate *coroutine);
    friend QBaseCoroutine* createMainCoroutine();
};


// 开始实现 QCoroutinePrivate
static void run_stub(QBaseCoroutinePrivate *coroutine)
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
        throw; // cause undefined behaviors
    }
}


QBaseCoroutinePrivate::QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), stack(0), state(QBaseCoroutine::Initialized),
      bad(false), exception(0), context(0)
{
    if(stackSize)
    {
        stack = operator new(stackSize);
        if(!stack)
        {
            qFatal("QCoroutine can not malloc new memroy.");
            bad = true;
            return;
        }
    }
    else
    {
        stack = 0;
    }
}


QBaseCoroutinePrivate::~QBaseCoroutinePrivate()
{
    Q_Q(QBaseCoroutine);
    if(stack)
        operator delete(stack);

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
    if(swapcontext(old->d_func()->context, this->context) < 0)
    {
        qDebug() << "swapcontext() return error: " << errno;
        return false;
    }
    if(currentCoroutine().get() != old)  // when coroutine finished, swapcontext auto yield to the previous.
    {
        currentCoroutine().set(old);
    }
    QCoroutineException *e = old->d_ptr->exception;
    if(e)
    {
        old->d_func()->exception = 0;
        qDebug() << "got exception:" << e->what() << old;
        e->raise();
    }
    return true;
}

bool QBaseCoroutinePrivate::initContext()
{
    if(context)
        return true;

    context = new ucontext_t;
    if(!context)
    {
        qFatal("QCoroutine can not malloc new memroy.");
        bad = true;
        return false;
    }
    if(getcontext(context) < 0)
    {
        qDebug() <<"getcontext() return error." << errno;
        bad = true;
        return false;
    }
    context->uc_stack.ss_sp = stack;
    context->uc_stack.ss_size = stackSize;
    if(previous)
    {
        context->uc_link = previous->d_ptr->context;
    }
    else
    {
        context->uc_link = 0;
    }
    makecontext(context, (void(*)(void))::run_stub, 1, this);
    return true;
}

bool QBaseCoroutinePrivate::kill(QCoroutineException *exception)
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

QBaseCoroutine* createMainCoroutine()
{
    QBaseCoroutine *main = new QBaseCoroutine(0, 0);
    if(!main)
        return 0;
    QBaseCoroutinePrivate *mainPrivate = main->d_ptr;
    mainPrivate->context = new ucontext_t;
    if(!mainPrivate->context)
    {
        qFatal("QCoroutine can not malloc new memroy.");
        delete main;
        return 0;
    }
    if(getcontext(mainPrivate->context) < 0)
    {
        qDebug() << "getcontext() returns error." << errno;
        delete main;
        return 0;
    }
    mainPrivate->state = QBaseCoroutine::Started;
    return main;
}

// 开始实现 QBaseCoroutine
QBaseCoroutine::QBaseCoroutine(QBaseCoroutine * previous, size_t stackSize)
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

void QBaseCoroutine::setState(QBaseCoroutine::State state)
{
    Q_D(QBaseCoroutine);
    d->state = state;
}

bool QBaseCoroutine::kill(QCoroutineException *exception)
{
    Q_D(QBaseCoroutine);
    return d->kill(exception);
}

bool QBaseCoroutine::yield()
{
    Q_D(QBaseCoroutine);
    return d->yield();
}


