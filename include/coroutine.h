#ifndef COROUTINE_H
#define COROUTINE_H

#include <QObject>
#include <QString>
#include <QDebug>

class QCoroutineException
{
public:
    explicit QCoroutineException() throw();
    virtual ~QCoroutineException() throw();
    virtual void raise();
    virtual QString what() const throw();
};

class QCoroutineExitException: public QCoroutineException
{
public:
    explicit QCoroutineExitException();
    virtual void raise();
    virtual QString what() const throw();
};


class QBaseCoroutinePrivate;
class QBaseCoroutine: public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY(QBaseCoroutine)
public:
    enum State
    {
        Initialized,
        Started,
        Stopped,
        Joined,
    };
    explicit QBaseCoroutine(QBaseCoroutine * previous, size_t stackSize = 1024 * 1024 * 8);
    virtual ~QBaseCoroutine();

    virtual void run();

    State state() const;
    bool kill(QCoroutineException *exception = 0);
    bool yield();
    quintptr id() const;
    static QBaseCoroutine *current();
signals:
    void started();
    void finished();
protected:
    void setState(QBaseCoroutine::State state);
private:
    QBaseCoroutinePrivate * const d_ptr;
    friend QBaseCoroutine* createMainCoroutine();
    Q_DECLARE_PRIVATE(QBaseCoroutine)
};

inline QDebug &operator <<(QDebug &out, const QBaseCoroutine& coroutine)
{
    if(coroutine.objectName().isEmpty())
        return out << QString::fromLatin1("BaseCourtine(id=%1)").arg(coroutine.id());
    else
        return out << QString::fromLatin1("%1(id=%2)").arg(coroutine.objectName(), coroutine.id());
}



#endif // COROUTINE_H
