#include <QtCore/qdebug.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 2, 0)
#  include <QtCore/qloggingcategory.h>
#  define QTNG_LOGGER(name) static Q_LOGGING_CATEGORY(qtng_logger, name)
#  define qtng_debug qCDebug(qtng_logger)
#  define qtng_warning qCWarning(qtng_logger)
#  define qtng_critical qCCritical(qtng_logger)
#else
#  define QTNG_LOGGER(name) \
    while (0) { }
#  define qtng_debug qDebug()
#  define qtng_warning qWarning()
#  define qtng_critical qCritical()
#endif
