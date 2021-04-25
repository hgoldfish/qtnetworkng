#ifndef QTNG_EVENTLOOP_H
#define QTNG_EVENTLOOP_H

#include <functional>
#include <QtCore/qthreadstorage.h>
#include <QtCore/qvariant.h>
#include <QtCore/qpointer.h>
#include "coroutine.h"


QTNETWORKNG_NAMESPACE_BEGIN

class CoroutinePrivate;
class Coroutine: public BaseCoroutine
{
    Q_DISABLE_COPY(Coroutine)
public:
    explicit Coroutine(size_t stackSize = DEFAULT_COROUTINE_STACK_SIZE);
    Coroutine(QObject *obj, const char *slot, size_t stackSize = DEFAULT_COROUTINE_STACK_SIZE);
    virtual ~Coroutine() override;
public:
    bool isRunning() const;
    bool isFinished() const;
    Coroutine *start(quint32 msecs = 0);
    void kill(CoroutineException *e = nullptr, quint32 msecs = 0);
    void cancelStart();
    bool join();
    virtual void run() override;
    static Coroutine *current();
    static void msleep(quint32 msecs);
    static void sleep(float secs) { msleep(static_cast<quint32>(secs * 1000)); }
    static Coroutine *spawn(std::function<void()> f);
    static void preferLibev();
protected:
    virtual void cleanup() override;
private:
    CoroutinePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Coroutine)
};


class TimeoutException: public CoroutineException
{
public:
    explicit TimeoutException();
    virtual QString what() const override;
    virtual void raise() override;
    virtual CoroutineException *clone() const override;
};

class Timeout: public QObject
{
public:
    Timeout(float secs);
    Timeout(quint32 msecs, int); // the second parameter is not used.
    ~Timeout();
public:
    void restart();
private:
    quint32 msecs;
    int timeoutId;
};


// useful for qt application.
int startQtLoop();

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_EVENTLOOP_H
