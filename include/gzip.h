#ifndef QTNG_GZIP_H
#define QTNG_GZIP_H

#include <QtCore/qbytearray.h>
#include "io_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

class GzipCompressFilePrivate;
class GzipCompressFile : public FileLike
{
public:
    GzipCompressFile(QSharedPointer<FileLike> backend, int level = -1);
    virtual ~GzipCompressFile() override;
public:
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *, qint32) override;
    virtual void close() override { }
    virtual qint64 size() override { return -1; }
private:
    GzipCompressFilePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(GzipCompressFile);
};

class GzipDecompressFilePrivate;
class GzipDecompressFile : public FileLike
{
public:
    GzipDecompressFile(QSharedPointer<FileLike> backend);
    virtual ~GzipDecompressFile() override;
public:
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *, qint32) override;
    virtual void close() override { }
    virtual qint64 size() override { return -1; }
private:
    GzipDecompressFilePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(GzipDecompressFile);
};

bool qGzipCompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int level = -1);
bool qGzipDecompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_GZIP_H
