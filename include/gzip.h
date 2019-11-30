#ifndef QTNG_GZIP_H
#define QTNG_GZIP_H

#include <QByteArray>
#include "io_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


bool qGzipCompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int level = -1);
bool qGzipDecompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output);


inline QByteArray qGzipCompress(const QByteArray &input, int level = -1)
{
    QSharedPointer<BytesIO> output(new BytesIO());
    bool ok = qGzipCompress(FileLike::bytes(input), output, level);
    if (ok) {
        return output->data();
    } else {
        return QByteArray();
    }
}


inline QByteArray qGzipDecompress(const QByteArray &input)
{
    QSharedPointer<BytesIO> output(new BytesIO());
    bool ok = qGzipDecompress(FileLike::bytes(input), output);
    if (ok) {
        return output->data();
    } else {
        return QByteArray();
    }
}



QTNETWORKNG_NAMESPACE_END

#endif // QTNG_GZIP_H
