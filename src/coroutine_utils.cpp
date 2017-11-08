#include "../include/coroutine_utils.h"
#include "../include/eventloop.h"

void LambdaFunctor::operator ()()
{
    callback();
}


DeferCallThread::DeferCallThread(const std::function<void()> &func, YieldCurrentFunctor *yieldCoroutine, QPointer<EventLoopCoroutine> eventloop)
:func(func), yieldCoroutine(yieldCoroutine), eventloop(eventloop)
{
}

void DeferCallThread::run()
{
    func();
    if(!eventloop.isNull()) {
        eventloop->callLaterThreadSafe(0, yieldCoroutine);
        eventloop->callLaterThreadSafe(0, new DeleteLaterFunctor<DeferCallThread>(this));
    } else {
        delete yieldCoroutine;
    }
}


CoroutineGroup::CoroutineGroup()
    :QObject()
{

}

CoroutineGroup::~CoroutineGroup()
{
    killall(true);
}

bool CoroutineGroup::add(QSharedPointer<QCoroutine> coroutine, const QString &name)
{
    if(!name.isEmpty()) {
        QListIterator<QSharedPointer<QCoroutine>> itor(coroutines);
        while(itor.hasNext()) {
            QSharedPointer<QCoroutine> oldCoroutine = itor.next();
            if(oldCoroutine->objectName() == name) {
                return false;
            }
        }
        coroutine->setObjectName(name);
    }
    connect(coroutine.data(), SIGNAL(finished()), SLOT(deleteCoroutine()), Qt::DirectConnection);
    coroutines.append(coroutine);
    return true;
}

QSharedPointer<QCoroutine> CoroutineGroup::get(const QString &name)
{
    QListIterator<QSharedPointer<QCoroutine>> itor(coroutines);
    while(itor.hasNext()) {
        QSharedPointer<QCoroutine> coroutine = itor.next();
        if(coroutine->objectName() == name)
            return coroutine;
    }
    return QSharedPointer<QCoroutine>();
}

bool CoroutineGroup::kill(const QString &name)
{
    QSharedPointer<QCoroutine> found;
    for(QList<QSharedPointer<QCoroutine>>::const_iterator itor = coroutines.constBegin(); itor != coroutines.constEnd(); ++itor) {
        QSharedPointer<QCoroutine> coroutine = *itor;
        if(coroutine->objectName() == name) {
            found = coroutine;
            if(coroutine.data() == QBaseCoroutine::current()) {
                qWarning("killing current coroutine?");
            }
            if(coroutine->isActive()) {
                coroutine->kill(); // maybe current coroutine.
            }
            break;
        }
    }

    if(!found.isNull()) {
        coroutines.removeAll(found);
    }
    return false;
}

bool CoroutineGroup::killall(bool join)
{
    bool hasCoroutines = !coroutines.isEmpty();
    QList<QSharedPointer<QCoroutine>> copy = coroutines;
    foreach(const QSharedPointer<QCoroutine> &coroutine, copy) {
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
        foreach(const QSharedPointer<QCoroutine> &coroutine, copy) {
            if(coroutine == QCoroutine::current()) {
                qWarning("will not kill current coroutine while killall() is called.");
                continue;
            }
            if(coroutine->isActive()) {
                coroutine->join();
            }
        }
    }
    coroutines.clear();
    return hasCoroutines;
}

bool CoroutineGroup::joinall()
{
    bool hasCoroutines = !coroutines.isEmpty();
    QList<QSharedPointer<QCoroutine>> copy = coroutines;
    foreach(const QSharedPointer<QCoroutine> &coroutine, copy) {
        if(coroutine == QCoroutine::current()) {
            qDebug("will not kill current coroutine while joinall() is called.");
            continue;
        }
        coroutine->join();
    }
    coroutines.clear();
    return hasCoroutines;
}

struct DeleteCoroutineFunctor: public Functor
{
    virtual void operator()() {}
    QSharedPointer<QBaseCoroutine> coroutine;
};

void CoroutineGroup::deleteCoroutine()
{
    QCoroutine *coroutine = dynamic_cast<QCoroutine*>(sender());
    Q_ASSERT(coroutine != 0);
    for(QList<QSharedPointer<QCoroutine>>::iterator itor = coroutines.begin(); itor != coroutines.end(); ++itor) {
        if(itor->data() == coroutine) {
            DeleteCoroutineFunctor *callback = new DeleteCoroutineFunctor();
            callback->coroutine = *itor;
            EventLoopCoroutine::get()->callLater(0, callback);
            coroutines.erase(itor);
            break;
        }
    }
}
