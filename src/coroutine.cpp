#include "coroutine_p.h"

QCoroutineException::QCoroutineException() throw ()
{
}

QCoroutineException::~QCoroutineException() throw()
{}

void QCoroutineException::raise()
{
    throw *this;
}

QString QCoroutineException::what() const throw()
{
    return QString::fromLatin1("coroutine base exception.");
}

QCoroutineExitException::QCoroutineExitException()
{
}

void QCoroutineExitException::raise()
{
    throw *this;
}

QString QCoroutineExitException::what() const throw()
{
    return QString::fromLatin1("coroutine was asked to quit.");
}

quintptr QBaseCoroutine::id() const
{
    const QBaseCoroutine *p = this;
    return reinterpret_cast<quintptr>(p);
}

void QBaseCoroutine::run()
{

}

CurrentCoroutineStorage &currentCoroutine()
{
    static CurrentCoroutineStorage storage;
    return storage;
}

// 开始实现 QBaseCoroutine::current()
QBaseCoroutine *CurrentCoroutineStorage::get()
{
    if(storage.hasLocalData())
    {
        return storage.localData().value;
    }
    QBaseCoroutine *main = createMainCoroutine();
    storage.localData().value = main;
    return main;
}

void CurrentCoroutineStorage::set(QBaseCoroutine *coroutine)
{
    storage.localData().value = coroutine;
}

void CurrentCoroutineStorage::clean()
{
    if(storage.hasLocalData())
    {
        storage.localData().value = 0;
    }
}

QBaseCoroutine *QBaseCoroutine::current()
{
    return currentCoroutine().get();
}
