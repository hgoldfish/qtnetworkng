#ifndef QTNG_COROUTINE_H
#define QTNG_COROUTINE_H

#include <QtCore/qobject.h>
#include <QtCore/qstring.h>
#include <QtCore/qdebug.h>
#include "config.h"
#include "deferred.h"


QTNETWORKNG_NAMESPACE_BEGIN

class CoroutineException
{
public:
    explicit CoroutineException() throw();
    virtual ~CoroutineException() throw();
    virtual void raise();
    virtual QString what() const throw();
};

class CoroutineExitException: public CoroutineException
{
public:
    explicit CoroutineExitException();
    virtual void raise();
    virtual QString what() const throw();
};




class BaseCoroutinePrivate;
class BaseCoroutine: public QObject
{
    Q_DISABLE_COPY(BaseCoroutine)
public:
    enum State
    {
        Initialized,
        Started,
        Stopped,
        Joined,
    };
    explicit BaseCoroutine(BaseCoroutine * previous, size_t stackSize = 1024 * 1024 * 8);
    virtual ~BaseCoroutine();

    virtual void run();

    State state() const;
    bool raise(CoroutineException *exception = 0);
    bool yield();
    quintptr id() const;

    BaseCoroutine *previous() const;
    void setPrevious(BaseCoroutine *previous);

    static BaseCoroutine *current();
public:
    Deferred<BaseCoroutine*> started;
    Deferred<BaseCoroutine*> finished;
protected:
    void setState(BaseCoroutine::State state);
    virtual void cleanup();
private:
    BaseCoroutinePrivate * const d_ptr;
    friend BaseCoroutine* createMainCoroutine();
    Q_DECLARE_PRIVATE(BaseCoroutine)
};

inline QDebug &operator <<(QDebug &out, const BaseCoroutine& coroutine)
{
    if(coroutine.objectName().isEmpty()) {
        return out << QString::fromLatin1("BaseCourtine(id=%1)").arg(coroutine.id());
    } else {
        return out << QString::fromLatin1("%1(id=%2)").arg(coroutine.objectName()).arg(coroutine.id());
    }
}

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_COROUTINE_H
