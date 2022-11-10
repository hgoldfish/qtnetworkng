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
    static QSharedPointer<FileLike> bytes(QByteArray *data);
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
    bool seek(qint64 pos);
    QString fileName() const;
public:
    static QSharedPointer<RawFile> open(const QString &filepath, const QString &mode = QString());
    static QSharedPointer<RawFile> open(const QString &filepath, QIODevice::OpenMode mode);
public:
    QSharedPointer<QFile> f;
};


class BytesIOPrivate;
class BytesIO: public FileLike
{
public:
    BytesIO(const QByteArray &buf, qint32 pos = 0);
    BytesIO(QByteArray *buf, qint32 pos = 0);
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


bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy=-1, int suitableBlockSize = 1024 * 8);


class PosixPathPrivate;
class PosixPath
{
public:
    PosixPath();
    PosixPath(const QString &path);
    PosixPath(const PosixPath &other);
#ifdef Q_COMPILER_RVALUE_REFS
    PosixPath(PosixPath &&other);
    PosixPath &operator=(PosixPath &&other) Q_DECL_NOTHROW;
#endif
    ~PosixPath();
    PosixPath &operator=(const PosixPath &other);
//    void swap(PosixPath &other) Q_DECL_NOTHROW { qSwap(d, other.d); }
    bool operator==(const PosixPath &other) const;
    inline bool operator!=(const PosixPath &other) const { return !(*this == other); }
public:
    PosixPath operator / (const QString &path) const;
    PosixPath operator | (const QString &path) const;
public:
    bool isNull() const;

    bool isFile() const;
    bool isDir() const;
    bool isSymLink() const;
    bool isAbsolute() const;
    bool isExecutable() const;
    bool isReadable() const;
    bool isRelative() const;
    bool isRoot() const;
    bool isWritable() const;
    bool exists() const;
    qint64 size() const;

    QString path() const;
    QFileInfo fileInfo() const;
    QString parentDir() const;          // returns QString() for /
    PosixPath parentPath() const;       // returns null for /
    QString name() const;               // returns QString() for /
    QString baseName() const;           // xxx.tar.bz -> xxx;        .fish. -> .fish
    QString suffix() const;             // xxx.tar.bz -> bz;         .fish. ->
    QString completeBaseName() const;   // xxx.tar.bz -> xxx.tar     .fish. -> .fish
    QString completeSuffix() const;     // xxx.tar.bz -> tar.bz      .fish. ->
    QString toAbsolute() const;
    QString relativePath(const QString &other) const;
    QString relativePath(const PosixPath &other) const;
    bool isChildOf(const PosixPath &other) const;
    bool hasChildOf(const PosixPath &other) const;

    QDateTime created() const;
    QDateTime lastModified() const;
    QDateTime lastRead() const;

    QStringList listdir() const;
    QList<PosixPath> children() const;

    bool mkdir(bool createParents = false);
    bool touch();
    QSharedPointer<RawFile> open(const QString &mode = QString());

    static PosixPath cwd();
    static QChar point;
    static QString pointpoint;
    static QChar seperator;
private:
    QSharedDataPointer<PosixPathPrivate> d;
};


QDebug &operator << (QDebug &, const PosixPath &);
uint qHash(const PosixPath& path, uint seed = 0);

// join the subPath with parentDir as its virtual root. return the final path and the normalized path
QPair<QString, QString> safeJoinPath(const QString &parentDir, const QString &subPath);
QPair<QFileInfo, QString> safeJoinPath(const QDir &parentDir, const QString &subPath);


QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_IO_UTILS_H
