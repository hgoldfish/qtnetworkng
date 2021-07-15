#include <QDebug>
#include "../include/private/coroutine_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

CoroutineException::CoroutineException()
{
}


CoroutineException::CoroutineException(CoroutineException &)
{
}


CoroutineException::~CoroutineException()
{}


void CoroutineException::raise()
{
    throw *this;
}


QString CoroutineException::what() const
{
    return QString::fromLatin1("coroutine base exception.");
}


CoroutineException *CoroutineException::clone() const
{
    return new CoroutineException();
}


CoroutineExitException::CoroutineExitException()
{
}


void CoroutineExitException::raise()
{
    throw *this;
}


QString CoroutineExitException::what() const
{
    return QString::fromLatin1("coroutine was asked to quit.");
}


CoroutineException *CoroutineExitException::clone() const
{
    return new CoroutineExitException();
}


CoroutineInterruptedException::CoroutineInterruptedException()
{
}


void CoroutineInterruptedException::raise()
{
    throw *this;
}


QString CoroutineInterruptedException::what() const
{
    return QString::fromLatin1("coroutine was interrupted.");
}


CoroutineException *CoroutineInterruptedException::clone() const
{
    return new CoroutineInterruptedException();
}


quintptr BaseCoroutine::id() const
{
    const BaseCoroutine *p = this;
    return reinterpret_cast<quintptr>(p);
}


bool BaseCoroutine::isRunning() const
{
    return state() == BaseCoroutine::Started;
}


bool BaseCoroutine::isFinished() const
{
    return state() == BaseCoroutine::Stopped || state() == BaseCoroutine::Joined;
}


void BaseCoroutine::run()
{

}


CurrentCoroutineStorage &currentCoroutine()
{
    static CurrentCoroutineStorage storage;
    return storage;
}


BaseCoroutine *CurrentCoroutineStorage::get()
{
    if (storage.hasLocalData()) {
        return storage.localData().value;
    }
    BaseCoroutine *main = createMainCoroutine();
    main->setObjectName(QString::fromLatin1("main_coroutine"));
    storage.localData().value = main;
    return main;
}


void CurrentCoroutineStorage::set(BaseCoroutine *coroutine)
{
    storage.localData().value = coroutine;
}


void CurrentCoroutineStorage::clean()
{
    if (storage.hasLocalData()) {
        storage.localData().value = nullptr;
    }
}


BaseCoroutine *BaseCoroutine::current()
{
    return currentCoroutine().get();
}

QTNETWORKNG_NAMESPACE_END


QDebug &operator <<(QDebug &out, const QTNETWORKNG_NAMESPACE::BaseCoroutine& coroutine)
{
    if (coroutine.objectName().isEmpty()) {
        return out << QString::fromLatin1("BaseCourtine(id=%1)").arg(coroutine.id());
    } else {
        return out << QString::fromLatin1("%1(id=%2)").arg(coroutine.objectName()).arg(coroutine.id());
    }
}

