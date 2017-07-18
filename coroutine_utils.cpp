#include "coroutine_utils.h"
#include "eventloop.h"

void LambdaFunctor::operator ()()
{
    callback();
}

DeferCallThread::DeferCallThread(const std::function<void()> &func, const std::function<void()> &callback)
:func(func), callback(callback)
{
}

void DeferCallThread::run()
{
    func();
    callback();
}


CoroutineGroup::CoroutineGroup()
{

}

CoroutineGroup::~CoroutineGroup()
{
    killall();
}

bool CoroutineGroup::add(QCoroutine *coroutine, const QString &name)
{
    if(!name.isEmpty())
    {
        QListIterator<QCoroutine*> itor(coroutines);
        while(itor.hasNext())
        {
            QCoroutine *oldCoroutine = itor.next();
            if(oldCoroutine->objectName() == name)
            {
                return false;
            }
        }
        coroutine->setObjectName(name);
    }
    coroutines.append(coroutine);
    return true;
}

QCoroutine *CoroutineGroup::get(const QString &name)
{
    QListIterator<QCoroutine*> itor(coroutines);
    while(itor.hasNext())
    {
        QCoroutine *coroutine = itor.next();
        if(coroutine->objectName() == name)
            return coroutine;
    }
    return 0;
}

bool CoroutineGroup::kill(const QString &name)
{
    QMutableListIterator<QCoroutine*> itor(coroutines);
    while(itor.hasNext())
    {
        QCoroutine *coroutine = itor.next();
        if(coroutine->objectName() == name)
        {
            bool success;
            if(coroutine->isActive()) {
                success = coroutine->kill(); // maybe current coroutine.
            } else {
                success = true;
            }
            itor.remove();
            delete coroutine;
            return success;
        }
    }
    return false;
}

bool CoroutineGroup::killall(bool join)
{
    bool hasCoroutines = coroutines.size() > 0;
    Q_FOREACH(QCoroutine *coroutine, coroutines)
    {
        if(coroutine == QCoroutine::current())
        {
            qDebug("will not kill current coroutine while killall() is called.");
            continue;
        }
        if(coroutine->isActive()) {
            coroutine->kill();
        }
    }
    if(join)
    {
        Q_FOREACH(QCoroutine *coroutine, coroutines)
        {
            if(coroutine == QCoroutine::current())
            {
                qDebug("will not join current coroutine while killall() is called.");
                continue;
            }
            if(coroutine->isActive()) {
                coroutine->join();
            }
        }
    }
    Q_FOREACH(QCoroutine *coroutine, coroutines)
    {
        if(coroutine == QCoroutine::current())
        {
            qDebug("will not kill current coroutine while killall() is called.");
            continue;
        }
        delete coroutine;
    }
    coroutines.clear();
    return hasCoroutines;
}

bool CoroutineGroup::joinall()
{
    bool hasCoroutines = coroutines.size() > 0;
    Q_FOREACH(QCoroutine *coroutine, coroutines)
    {
        if(coroutine == QCoroutine::current())
        {
            qDebug("will not join current coroutine while joinall() is called.");
            continue;
        }
        coroutine->join();
    }
    Q_FOREACH(QCoroutine *coroutine, coroutines)
    {
        if(coroutine == QCoroutine::current())
        {
            qDebug("will not kill current coroutine while killall() is called.");
            continue;
        }
        delete coroutine;
    }
    coroutines.clear();
    return hasCoroutines;
}

