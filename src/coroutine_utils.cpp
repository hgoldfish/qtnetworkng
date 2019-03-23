#include "../include/coroutine_utils.h"
#include "../include/eventloop.h"

QTNETWORKNG_NAMESPACE_BEGIN

void LambdaFunctor::operator ()()
{
    callback();
}


DeferCallThread::DeferCallThread(const std::function<void()> &func, LambdaFunctor *yieldCoroutine, EventLoopCoroutine *eventloop)
:func(func), yieldCoroutine(yieldCoroutine), eventloop(eventloop)
{
}

void DeferCallThread::run()
{
    func();
    if(!eventloop.isNull()) {
        eventloop->callLaterThreadSafe(0, yieldCoroutine);
        eventloop->callLaterThreadSafe(100, new DeleteLaterFunctor<DeferCallThread>(this));
    } else {
        delete yieldCoroutine;
    }
}

NewThreadCoroutine::~NewThreadCoroutine() {}

CoroutineGroup::CoroutineGroup()
    :QObject()
{

}

CoroutineGroup::~CoroutineGroup()
{
    killall(true);
}

bool CoroutineGroup::add(QSharedPointer<Coroutine> coroutine, const QString &name)
{
    if(!name.isEmpty()) {
        if(!get(name).isNull()) {
            return false;
        }
        coroutine->setObjectName(name);
    }
    QPointer<CoroutineGroup> self(this);
    coroutine->finished.addCallback([self] (BaseCoroutine *coroutine) {
        if (self.isNull()) {
            return;
        }
        self->deleteCoroutine(coroutine);
    });
    coroutines.append(coroutine);
    return true;
}

QSharedPointer<Coroutine> CoroutineGroup::get(const QString &name)
{
    QListIterator<QSharedPointer<Coroutine>> itor(coroutines);
    while(itor.hasNext()) {
        QSharedPointer<Coroutine> coroutine = itor.next();
        if(coroutine->objectName() == name)
            return coroutine;
    }
    return QSharedPointer<Coroutine>();
}

bool CoroutineGroup::kill(const QString &name, bool join)
{
    QSharedPointer<Coroutine> found = get(name);
    if(!found.isNull()) {
        if(found.data() == Coroutine::current()) {
//            qWarning("killing current coroutine?");
        } else {
            found->kill();
            if(join) {
                bool success = found->join();
                coroutines.removeOne(found);
                return success;
            }
            return true;
        }
    }
    return false;
}

bool CoroutineGroup::killall(bool join)
{
    bool done = false;
    QList<QSharedPointer<Coroutine>> copy = coroutines;
    for (QSharedPointer<Coroutine> coroutine: copy) {
        if(coroutine.data() == Coroutine::current()) {
//            qWarning() << "will not kill current coroutine while killall() is called:" << BaseCoroutine::current();
            continue;
        }
        coroutine->kill();
        done = true;
    }

    if(join) {
        copy = coroutines;
        for (QSharedPointer<Coroutine> coroutine: copy) {
            if(coroutine.data() == Coroutine::current()) {
//                qWarning("will not join current coroutine while killall() is called.");
                continue;
            }
            coroutines.removeOne(coroutine);
            coroutine->join();
        }
    }
    return done;
}

bool CoroutineGroup::joinall()
{
    bool hasCoroutines = !coroutines.isEmpty();
    QList<QSharedPointer<Coroutine>> copy = coroutines;
    for (QSharedPointer<Coroutine> coroutine: copy) {
        if(coroutine == Coroutine::current()) {
//            qDebug("will not kill current coroutine while joinall() is called.");
            continue;
        }
        coroutines.removeOne(coroutine);
        coroutine->join();
    }
    return hasCoroutines;
}

class DeleteCoroutineFunctor: public Functor
{
public:
    virtual ~DeleteCoroutineFunctor() override;
    virtual void operator()() override;
    QSharedPointer<BaseCoroutine> coroutine;
};
DeleteCoroutineFunctor::~DeleteCoroutineFunctor() {}
void DeleteCoroutineFunctor::operator()() {}


void CoroutineGroup::deleteCoroutine(BaseCoroutine *baseCoroutine)
{
    Coroutine *coroutine = dynamic_cast<Coroutine*>(baseCoroutine);
    Q_ASSERT(coroutine != nullptr);
    for (QList<QSharedPointer<Coroutine>>::iterator itor = coroutines.begin(); itor != coroutines.end(); ++itor) {
        if(itor->data() == coroutine) {
            DeleteCoroutineFunctor *callback = new DeleteCoroutineFunctor();
            callback->coroutine = *itor;
            EventLoopCoroutine::get()->callLater(0, callback);
            coroutines.erase(itor);
            break;
        }
    }
}

QTNETWORKNG_NAMESPACE_END
