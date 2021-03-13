#ifndef QTNG_IO_UTILS_H
#define QTNG_IO_UTILS_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qfile.h>
#include "socket.h"

QTNETWORKNG_NAMESPACE_BEGIN


class FileLike
{
public:
    virtual ~FileLike();
    virtual qint32 read(char *data, qint32 size) = 0;
    virtual qint32 write(const char *data, qint32 size) = 0;
    virtual void close() = 0;
    virtual qint64 size() = 0;
    QByteArray readall(bool *ok);
public:
    static QSharedPointer<FileLike> rawFile(QSharedPointer<QFile> f);
    static QSharedPointer<FileLike> rawFile(QFile *f) { return rawFile(QSharedPointer<QFile>(f)); }
    static QSharedPointer<FileLike> bytes(const QByteArray &data);
};


class BytesIOPrivate;
class BytesIO: public FileLike
{
public:
    BytesIO(const QByteArray &buf);
    BytesIO();
    virtual ~BytesIO() override;
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *data, qint32 size) override;
    virtual void close() override;
    virtual qint64 size() override;
    QByteArray data();
private:
    BytesIOPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(BytesIO)
};


bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_IO_UTILS_H
