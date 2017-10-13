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
    :QObject()
{

}

CoroutineGroup::~CoroutineGroup()
{
    killall();
}

bool CoroutineGroup::add(QCoroutine *coroutine, const QString &name)
{
    if(!name.isEmpty()) {
        QListIterator<QCoroutine*> itor(coroutines);
        while(itor.hasNext()) {
            QCoroutine *oldCoroutine = itor.next();
            if(oldCoroutine->objectName() == name) {
                return false;
            }
        }
        coroutine->setObjectName(name);
    }
    connect(coroutine, SIGNAL(finished()), SLOT(deleteCoroutine()), Qt::DirectConnection);
    coroutines.append(coroutine);
    return true;
}

QCoroutine *CoroutineGroup::get(const QString &name)
{
    QListIterator<QCoroutine*> itor(coroutines);
    while(itor.hasNext()) {
        QCoroutine *coroutine = itor.next();
        if(coroutine->objectName() == name)
            return coroutine;
    }
    return 0;
}

bool CoroutineGroup::kill(const QString &name)
{
    QCoroutine *found = 0;
    for(QList<QCoroutine*>::const_iterator itor = coroutines.constBegin(); itor != coroutines.constEnd(); ++itor) {
        QCoroutine *coroutine = *itor;
        if(coroutine->objectName() == name) {
            found = coroutine;
            if(coroutine->isActive()) {
                coroutine->kill(); // maybe current coroutine.
            }
            break;
        }
    }

    if(found) {
        coroutines.removeAll(found);
    }
    return false;
}

bool CoroutineGroup::killall(bool join)
{
    bool hasCoroutines = !coroutines.isEmpty();
    QList<QCoroutine*> copy = coroutines;

    for(QList<QCoroutine*>::const_iterator itor = copy.constBegin(); itor != copy.constEnd(); ++itor) {
        QCoroutine *coroutine = *itor;
        if(!coroutines.contains(coroutine)) {
            continue;
        }

        if(coroutine == QCoroutine::current()) {
            qWarning("will not kill current coroutine while killall() is called.");
            continue;
        }
        if(coroutine->isActive()) {
            coroutine->kill();
        }
    }

    if(join) {
        copy = coroutines;
        for(QList<QCoroutine*>::const_iterator itor = copy.constBegin(); itor != copy.constEnd(); ++itor) {
            QCoroutine *coroutine = *itor;
            if(!coroutines.contains(coroutine)) {
                continue;
            }
            if(coroutine == QCoroutine::current()) {
                qWarning("will not join current coroutine while killall() is called.");
                continue;
            }
            if(coroutine->isActive()) {
                coroutine->join();
            }
        }
    }

    for(QList<QCoroutine*>::const_iterator itor = coroutines.constBegin(); itor != coroutines.constEnd(); ++itor) {
        QCoroutine *coroutine = *itor;
        if(coroutine == QCoroutine::current()) {
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
    bool hasCoroutines = !coroutines.isEmpty();

    QList<QCoroutine*> copy = coroutines;
    for(QList<QCoroutine*>::const_iterator itor = copy.constBegin(); itor != copy.constEnd(); ++itor) {
        QCoroutine *coroutine = *itor;
        if(!coroutines.contains(coroutine)) {
            continue;
        }
        if(coroutine == QCoroutine::current()) {
            qDebug("will not join current coroutine while joinall() is called.");
            continue;
        }
        coroutine->join();
    }


    for(QList<QCoroutine*>::const_iterator itor = coroutines.constBegin(); itor != coroutines.constEnd(); ++itor) {
        QCoroutine *coroutine = *itor;
        if(!coroutines.contains(coroutine)) {
            continue;
        }
        if(coroutine == QCoroutine::current()) {
            qDebug("will not kill current coroutine while joinall() is called.");
            continue;
        }
        delete coroutine;
    }

    coroutines.clear();
    return hasCoroutines;
}

struct DeleteCoroutineFunctor: public Functor
{
    virtual ~DeleteCoroutineFunctor()
    {
        if(coroutine.isNull()) {
            return;
        }
        delete coroutine.data();
    }

    virtual void operator()()
    {
        if(coroutine.isNull()) {
            return;
        }
        delete coroutine.data();
    }

    QPointer<QBaseCoroutine> coroutine;
};

void CoroutineGroup::deleteCoroutine()
{
    QCoroutine *coroutine = dynamic_cast<QCoroutine*>(sender());
    Q_ASSERT(coroutine != 0);
    coroutines.removeAll(coroutine);

    DeleteCoroutineFunctor *callback = new DeleteCoroutineFunctor();
    callback->coroutine = QPointer<QBaseCoroutine>(coroutine);
    EventLoopCoroutine::get()->callLater(0, callback);
}
