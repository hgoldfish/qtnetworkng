#include <stdlib.h>
#include <setjmp.h>
#include <QtCore/qdebug.h>
#include <QtCore/qlist.h>
#include "../include/private/coroutine_p.h"

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


// 开始定义 CoroutinePrivate
extern "C" void run_stub(intptr_t tr);
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
    CoroutineException *exception;
    fcontext_t context;
    size_t stackSize;
    void *stack;
    enum BaseCoroutine::State state;
    bool bad;
    Q_DECLARE_PUBLIC(BaseCoroutine)
private:
    static BaseCoroutinePrivate *getPrivateHelper(BaseCoroutine *coroutine) { return coroutine->dd_ptr; }
    void cleanup() { q_ptr->cleanup(); }
    friend void run_stub(intptr_t tr);
    friend BaseCoroutine* createMainCoroutine();
};


// 开始实现 CoroutinePrivate
extern "C" void run_stub(intptr_t data)
{
    BaseCoroutinePrivate *coroutine = reinterpret_cast<BaseCoroutinePrivate*>(data);
    if(!coroutine) {
        qDebug() << "run_stub got invalid coroutine.";
        return;
    }
    coroutine->state = BaseCoroutine::Started;
    coroutine->q_ptr->started.callback(coroutine->q_ptr);
    try {
        coroutine->q_ptr->run();
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
    } catch(const CoroutineExitException &) {
        coroutine->state = BaseCoroutine::Stopped;
        coroutine->q_ptr->finished.callback(coroutine->q_ptr);
    } catch(const CoroutineException &e) {
        qDebug() << "got coroutine exception:" << e.what();
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
    :q_ptr(q), previous(previous), exception(nullptr), context(nullptr), stackSize(stackSize), stack(nullptr),
      state(BaseCoroutine::Initialized), bad(false)
{
    if(stackSize) {
#ifdef Q_OS_UNIX
#ifdef MAP_GROWSDOWN
        stack = mmap(nullptr, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
#else
        stack = mmap(nullptr, this->stackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
#else
        stack = operator new(stackSize);
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
        if (q->objectName().isEmpty()) {
            qWarning() << "do not delete running BaseCoroutine:" << q;
        } else {
            qWarning() << "do not delete running BaseCoroutine:" << q->objectName();
        }
    }
    if (exception) {
        qWarning("BaseCoroutine->exception should always be kept null.");
        //delete exception;
    }

    if (currentCoroutine().get() == q) {
        qWarning("do not delete one self.");
    }

    if (stack) {
#ifdef Q_OS_UNIX
        munmap(stack, stackSize);
#else
        operator delete(stack);
#endif
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

    intptr_t result = jump_fcontext(&old->d_func()->context, context, reinterpret_cast<intptr_t>(this), false);
    if (!result && state != BaseCoroutine::Stopped) {  // last coroutine private.
        qWarning("jump_fcontext() return error.");
        return false;
    }
    if (currentCoroutine().get() != old) {  // when coroutine finished, jump_fcontext auto yield to the previous.
        currentCoroutine().set(old);
    }
    CoroutineException *e = old->d_func()->exception;
    if (e) {
        old->d_func()->exception = nullptr;
        if (!dynamic_cast<CoroutineExitException*>(e)) {
//            qDebug() << "got exception with no harm:" << e->what() << old;
        }
        e->raise();
    }
    return true;
}


bool BaseCoroutinePrivate::initContext()
{
    if (context) {
        return true;
    }
    if (!stackSize) {
        qDebug("is the main fiber forgot to create context?");
        return true;
    }

    void * stackTop = static_cast<char*>(stack) + stackSize;
    context = make_fcontext(stackTop, stackSize, run_stub);
    if (!context) {
        qWarning("Coroutine can not malloc new context.");
        bad = true;
        return false;
    }
    return true;
}


bool BaseCoroutinePrivate::raise(CoroutineException *exception)
{
    Q_Q(BaseCoroutine);
    if (currentCoroutine().get() == q) {
        qWarning("can not kill oneself.");
        return false;
    }

    if (this->exception) {
        qWarning("coroutine had been killed.");
        return false;
    }

    if (state == BaseCoroutine::Stopped || state == BaseCoroutine::Joined) {
        qWarning("coroutine is stopped.");
        return false;
    }

    if (exception) {
        this->exception = exception;
    } else {
        this->exception = new CoroutineExitException();
    }
    CoroutineException *t = this->exception;  // this->exception will be zeroed in yiled()
    try {
        bool result = yield();
        delete t;
        return result;
    } catch (...) {
        delete t;
        throw;
    }
}


BaseCoroutine* createMainCoroutine()
{
    BaseCoroutine *main = new BaseCoroutine(nullptr, 0);
    if (!main) {
        return nullptr;
    }
    BaseCoroutinePrivate *mainPrivate = main->d_func();
    mainPrivate->stack = new char[1024];
    mainPrivate->stackSize = 1024;
    void *stackTop = static_cast<char*>(mainPrivate->stack) + mainPrivate->stackSize;
    mainPrivate->context = make_fcontext(stackTop, mainPrivate->stackSize, nullptr);
    mainPrivate->state = BaseCoroutine::Started;
    return main;
}


// 开始实现 QBaseCoroutine
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


void BaseCoroutine::cleanup()
{
    Q_D(BaseCoroutine);
    if (d->previous) {
        d->previous->yield();
    }
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
