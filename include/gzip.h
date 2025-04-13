#ifndef QTNG_GZIP_H
#define QTNG_GZIP_H

#include <QtCore/qbytearray.h>
#include "io_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

class GzipFilePrivate;
class GzipFile : public FileLike
{
public:
    enum IOMode
    {
        Decompress = 0, Compress = 1,
        Inflate = 2, Deflate = 3
    };
public:
    GzipFile(QSharedPointer<FileLike> backend, IOMode mode, int level = -1);
    virtual ~GzipFile() override;
public:
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *data, qint32 size) override;
    virtual void close() override;
    virtual qint64 size() override { return -1; }
public:
    qint64 processedBytes() const;
private:
    GzipFilePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(GzipFile);
};

bool qGzipCompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int level = -1, int blockSize = 1024 * 8);
bool qGzipDecompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int blockSize = 1024 * 8);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_GZIP_H
