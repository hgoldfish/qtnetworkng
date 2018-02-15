#include <stdlib.h>
#include <setjmp.h>
#include <QtCore/QDebug>
#include <QtCore/QList>
#include "../include/coroutine_p.h"

#ifdef Q_OS_UNIX
# include <sys/mman.h>
#endif

QTNETWORKNG_NAMESPACE_BEGIN

#if (defined(i386) || defined(__i386__) || defined(__i386) \
     || defined(__i486__) || defined(__i586__) || defined(__i686__) \
     || defined(__X86__) || defined(_X86_) || defined(__THW_INTEL__) \
     || defined(__I86__) || defined(__INTEL__) || defined(__IA32__) \
     || defined(_M_IX86) || defined(_I86_)) && defined(Q_OS_WIN)
# define BOOST_CONTEXT_CALLDECL __cdecl
#else
# define BOOST_CONTEXT_CALLDECL
#endif

typedef void* fcontext_t;
extern "C" intptr_t BOOST_CONTEXT_CALLDECL jump_fcontext(fcontext_t *ofc, fcontext_t nfc, intptr_t vp, bool preserve_fpu);
extern "C" fcontext_t BOOST_CONTEXT_CALLDECL make_fcontext(void *sp, std::size_t size, void (* fn)(intptr_t));


// 开始定义 QCoroutinePrivate
extern "C" void run_stub(intptr_t tr);
class QBaseCoroutinePrivate
{
public:
    QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize);
    ~QBaseCoroutinePrivate();
    bool initContext();
    bool raise(QCoroutineException *exception = 0);
    bool yield();
private:
    QBaseCoroutine * const q_ptr;
    QBaseCoroutine * const previous;
    size_t stackSize;
    void *stack;
    enum QBaseCoroutine::State state;
    bool bad;
    QCoroutineException *exception;
    fcontext_t context;
    Q_DECLARE_PUBLIC(QBaseCoroutine)
private:
    static QBaseCoroutinePrivate *getPrivateHelper(QBaseCoroutine *coroutine) { return coroutine->d_ptr; }
    friend void run_stub(intptr_t tr);
    friend QBaseCoroutine* createMainCoroutine();
};


// 开始实现 QCoroutinePrivate
extern "C" void run_stub(intptr_t data)
{
    QBaseCoroutinePrivate *coroutine = reinterpret_cast<QBaseCoroutinePrivate*>(data);
    if(!coroutine) {
        qDebug() << "run_stub got invalid coroutine.";
        return;
    }
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
        qWarning() << "coroutine throw a unhandled exception.";
        coroutine->state = QBaseCoroutine::Stopped;
        emit coroutine->q_ptr->finished();
//        throw; // cause undefined behaviors
    }
    if(coroutine->previous) {
        fcontext_t to = QBaseCoroutinePrivate::getPrivateHelper(coroutine->previous)->context;
        fcontext_t from;
        jump_fcontext(&from, to, 0, false);
    }
}


QBaseCoroutinePrivate::QBaseCoroutinePrivate(QBaseCoroutine *q, QBaseCoroutine *previous, size_t stackSize)
    :q_ptr(q), previous(previous), stackSize(stackSize), stack(0), state(QBaseCoroutine::Initialized),
      bad(false), exception(0), context(0)
{
    if(stackSize) {
#ifdef Q_OS_UNIX
#ifdef MAP_GROWSDOWN
        stack = mmap(NULL, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
#else
        stack = mmap(NULL, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
#else
        stack = operator new(stackSize);
#endif
        if(!stack) {
            qFatal("QCoroutine can not malloc new memroy.");
            bad = true;
            return;
        }
    }
}


QBaseCoroutinePrivate::~QBaseCoroutinePrivate()
{
    Q_Q(QBaseCoroutine);
    if(state == QBaseCoroutine::Started) {
        qWarning() << "do not delete running QBaseCoroutine: %1";
    }
    if(stack) {
#ifdef Q_OS_UNIX
        munmap(stack, stackSize);
#else
        operator delete(stack);
#endif

    }

    if(currentCoroutine().get() == q) {
        //TODO 在当前 coroutine 里面把自己给干掉了怎么办？
        qWarning("do not delete one self.");
    }
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

    intptr_t result = jump_fcontext(&old->d_ptr->context, context, reinterpret_cast<intptr_t>(this), false);
    if(!result && state != QBaseCoroutine::Stopped) {  // last coroutine private.
        qDebug() << "jump_fcontext() return error.";
        return false;
    }
    if(currentCoroutine().get() != old) {  // when coroutine finished, jump_fcontext auto yield to the previous.
        currentCoroutine().set(old);
    }
    QCoroutineException *e = old->d_ptr->exception;
    if(e) {
        old->d_func()->exception = 0;
        if(!dynamic_cast<QCoroutineExitException*>(e)) {
            qDebug() << "got exception:" << e->what() << old;
        }
        try {
            e->raise();
        } catch(...) {
            delete e;
            e = 0;
            throw;
        }
    }
    return true;
}

bool QBaseCoroutinePrivate::initContext()
{
    if(context)
        return true;
    if(!stackSize) {
        qDebug() << "is the main fiber forgot to create context?";
        return true;
    }

    void * stackTop = static_cast<char*>(stack) + stackSize;
    context = make_fcontext(stackTop, stackSize, run_stub);
    if(!context) {
        qFatal("QCoroutine can not malloc new context.");
        bad = true;
        return false;
    }
    return true;
}

bool QBaseCoroutinePrivate::raise(QCoroutineException *exception)
{
    Q_Q(QBaseCoroutine);
    if(currentCoroutine().get() == q) {
        qWarning("can not kill oneself.");
        return false;
    }

    if(this->exception) {
        qWarning("coroutine had been killed.");
        return false;
    }

    if(state == QBaseCoroutine::Stopped || state == QBaseCoroutine::Joined) {
        qWarning("coroutine is stopped.");
        return false;
    }

    if(exception) {
        this->exception = exception;
    } else {
        this->exception = new QCoroutineExitException();
    }
    return yield();
}

QBaseCoroutine* createMainCoroutine()
{
    QBaseCoroutine *main = new QBaseCoroutine(0, 0);
    if(!main)
        return 0;
    QBaseCoroutinePrivate *mainPrivate = main->d_ptr;
    mainPrivate->stack = new char[1024];
    mainPrivate->stackSize = 1024;
    void *stackTop = static_cast<char*>(mainPrivate->stack) + mainPrivate->stackSize;
    mainPrivate->context = make_fcontext(stackTop, mainPrivate->stackSize, 0);
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


QTNETWORKNG_NAMESPACE_END
