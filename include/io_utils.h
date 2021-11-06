#ifndef QTNG_IO_UTILS_H
#define QTNG_IO_UTILS_H

#include <QtCore/qsharedpointer.h>
#include <QtCore/qfileinfo.h>
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
    virtual QByteArray readall(bool *ok);
public:
    QByteArray read(qint32 size);
    qint32 write(const QByteArray &data);
public:
    static QSharedPointer<FileLike> rawFile(QSharedPointer<QFile> f);
    static QSharedPointer<FileLike> rawFile(QFile *f) { return rawFile(QSharedPointer<QFile>(f)); }
    static QSharedPointer<FileLike> open(const QString &filepath, const QString &mode = QString());
    static QSharedPointer<FileLike> bytes(const QByteArray &data);
};


class RawFile: public FileLike
{
public:
    RawFile(QSharedPointer<QFile> f)
        : f(f) {}
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *data, qint32 size) override;
    virtual void close() override;
    virtual qint64 size() override;
public:
    QSharedPointer<QFile> f;
};


class BytesIOPrivate;
class BytesIO: public FileLike
{
public:
    BytesIO(const QByteArray &buf, qint32 pos = 0);
    BytesIO();
    virtual ~BytesIO() override;
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 write(const char *data, qint32 size) override;
    virtual void close() override;
    virtual qint64 size() override;
    virtual QByteArray readall(bool *ok) override;
    QByteArray data();
private:
    BytesIOPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(BytesIO)
};


bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy=-1);


// join subPath with parentDir as its virtual root.
QString safeJoinPath(const QString &parentDir, const QString &subPath);
QFileInfo safeJoinPath(const QDir &parentDir, const QString &subPath);


QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_IO_UTILS_H
