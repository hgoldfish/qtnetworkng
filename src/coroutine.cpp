#include "../include/coroutine_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

CoroutineException::CoroutineException() throw ()
{
}

CoroutineException::~CoroutineException() throw()
{}

void CoroutineException::raise()
{
    throw *this;
}

QString CoroutineException::what() const throw()
{
    return QString::fromLatin1("coroutine base exception.");
}

CoroutineExitException::CoroutineExitException()
{
}

void CoroutineExitException::raise()
{
    throw *this;
}

QString CoroutineExitException::what() const throw()
{
    return QString::fromLatin1("coroutine was asked to quit.");
}

quintptr BaseCoroutine::id() const
{
    const BaseCoroutine *p = this;
    return reinterpret_cast<quintptr>(p);
}


void BaseCoroutine::run()
{

}


CurrentCoroutineStorage &currentCoroutine()
{
    static CurrentCoroutineStorage storage;
    return storage;
}

// 开始实现 QBaseCoroutine::current()
BaseCoroutine *CurrentCoroutineStorage::get()
{
    if(storage.hasLocalData())
    {
        return storage.localData().value;
    }
    BaseCoroutine *main = createMainCoroutine();
    main->setObjectName("main_coroutine");
    storage.localData().value = main;
    return main;
}

void CurrentCoroutineStorage::set(BaseCoroutine *coroutine)
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

BaseCoroutine *BaseCoroutine::current()
{
    return currentCoroutine().get();
}


QDebug &operator <<(QDebug &out, const BaseCoroutine& coroutine)
{
    if(coroutine.objectName().isEmpty()) {
        return out << QString::fromLatin1("BaseCourtine(id=%1)").arg(coroutine.id());
    } else {
        return out << QString::fromLatin1("%1(id=%2)").arg(coroutine.objectName()).arg(coroutine.id());
    }
}


QTNETWORKNG_NAMESPACE_END
