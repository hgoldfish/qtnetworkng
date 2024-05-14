#include <QtCore/qobject.h>
#include "../include/config.h"

QTNETWORKNG_NAMESPACE_BEGIN

class QtEventLoopCoroutinePrivate;
class EventLoopCoroutinePrivateQtHelper : public QObject
{
    Q_OBJECT
public:
    EventLoopCoroutinePrivateQtHelper(QtEventLoopCoroutinePrivate *parent);
public slots:
    virtual void timerEvent(QTimerEvent *event) override;
    void callLaterThreadSafeStub(quint32 msecs, void *callback);
    void handleIoEvent(int socket);
private:
    QtEventLoopCoroutinePrivate * const parent;
};

QTNETWORKNG_NAMESPACE_END
