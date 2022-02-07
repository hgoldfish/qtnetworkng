#include <QtCore/qdir.h>
#include <QtCore/qdatetime.h>
#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
#include "../include/io_utils.h"
#include "../include/coroutine_utils.h"
#include "debugger.h"

QTNG_LOGGER("qtng.io_utils");

QTNETWORKNG_NAMESPACE_BEGIN


FileLike::~FileLike() {}


QByteArray FileLike::readall(bool *ok)
{
    QByteArray data;
    qint64 s = size();
    if (s >= static_cast<qint64>(INT32_MAX)) {
        if (ok) *ok = false;
        return data;
    } else if (s == 0) {
        return data;
    } else if (s < 0) {
        // size() is not supported.
    } else { // 0 < s < INT32_MAX
        data.reserve(static_cast<qint32>(s));
    }
    char buf[1024 * 8];
    while (true) {
        qint32 readBytes = read(buf, 1024 * 8);
        if (readBytes <= 0) {
            if (ok) *ok = (s < 0 || data.size() == s);
            return data;
        }
        data.append(buf, readBytes);
    }
}


QByteArray FileLike::read(qint32 size)
{
    QByteArray buf(size, Qt::Uninitialized);
    qint32 readBytes = this->read(buf.data(), size);
    if (readBytes <= 0) {
        return QByteArray();
    } else if (readBytes >= size) {
        return buf;
    } else {
        buf.resize(readBytes);
        return buf;
    }
}


qint32 FileLike::write(const QByteArray &data)
{
    return this->write(data.constData(), data.size());
}


qint32 RawFile::read(char *data, qint32 size)
{
#ifdef Q_OS_UNIX
    int fd = f->handle();
    if (fd <= 0) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, f->handle());
    while (true) {
        ssize_t r = 0;
        do {
            r = ::read(fd, data, static_cast<size_t>(size));
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case EBADF:
            case EINVAL:
            case EIO:
            default:
                return -1;
            }
        } else {
            return r;
        }
        watcher.start();
    }
#else
    qint64 len = f->read(data, size);
    return static_cast<qint32>(len);
#endif
}


qint32 RawFile::write(const char *data, qint32 size)
{
#ifdef Q_OS_UNIX
    int fd = f->handle();
    if (fd <= 0) {
        return -1;
    }
    ScopedIoWatcher watcher(EventLoopCoroutine::Read, f->handle());
    while (true) {
        ssize_t r = 0;
        do {
            r = ::write(fd, data, static_cast<size_t>(size));
        } while (r < 0 && errno == EINTR);
        if (r <= 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK-0 && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case EAGAIN:
                break;
            case EBADF:
            case EINVAL:
            case EIO:
            default:
                return -1;
            }
        } else {
            return r;
        }
        watcher.start();
    }
#else
    qint64 len = f->write(data, size);
    return static_cast<qint32>(len);
#endif
}


void RawFile::close()
{
    f->close();
}


qint64 RawFile::size()
{
    return f->size();
}


QSharedPointer<FileLike> FileLike::rawFile(QSharedPointer<QFile> f)
{
    return QSharedPointer<RawFile>::create(f).dynamicCast<FileLike>();
}


QSharedPointer<FileLike> FileLike::open(const QString &filepath, const QString &mode)
{
    QSharedPointer<QFile> f(new QFile(filepath));
    QIODevice::OpenMode flag = QIODevice::NotOpen;
    if (mode == QString() || mode == QLatin1String("r") || mode == QLatin1String("r+") || mode == QLatin1String("rb")
            || mode == QLatin1String("rb+") || mode == QLatin1String("r+b")) {
        flag |= QIODevice::ReadOnly;
        if (mode.contains(QLatin1Char('+'))) {
            flag |= QIODevice::WriteOnly;
        }
    } else if (mode == QLatin1String("w") || mode == QLatin1String("w+") || mode == QLatin1String("wb")
               || mode == QLatin1String("wb+") || mode == QLatin1String("w+b")) {
        flag |= QIODevice::WriteOnly;
        flag |= QIODevice::Truncate;
        if (mode.contains(QLatin1Char('+'))) {
            flag |= QIODevice::ReadOnly;
        }
    } else if (mode == QLatin1String("a") || mode == QLatin1String("a+") || mode == QLatin1String("ab")
               || mode == QLatin1String("ab+") || mode == QLatin1String("a+b")) {
        flag |= QIODevice::WriteOnly | QIODevice::Append;
        if (mode.contains(QLatin1Char('+'))) {
            flag |= QIODevice::ReadOnly;
        }
    } else {
        qtng_warning << "unknown file mode:" << mode;
    }
    if (!f->open(flag)) {
        return QSharedPointer<FileLike>();
    } else {
        if (flag & QIODevice::Append && !f->seek(f->size())) {
            return QSharedPointer<FileLike>();
        }
        return FileLike::rawFile(f);
    }
}


class BytesIOPrivate
{
public:
    BytesIOPrivate(qint32 pos)
        : pos(pos) {}
    QByteArray *buf;
    qint32 pos;
    bool ownbuf;
};


BytesIO::BytesIO(const QByteArray &buf, qint32 pos)
    :d_ptr(new BytesIOPrivate(pos))
{
    Q_D(BytesIO);
    d->buf = new QByteArray(buf);
    d->ownbuf = true;
}


BytesIO::BytesIO(QByteArray *buf, qint32 pos)
    :d_ptr(new BytesIOPrivate(pos))
{
    Q_D(BytesIO);
    d->buf = buf;
    d->ownbuf = false;
}


BytesIO::BytesIO()
    :d_ptr(new BytesIOPrivate(0))
{
    Q_D(BytesIO);
    d->buf = new QByteArray();
    d->ownbuf = true;
}


BytesIO::~BytesIO()
{
    Q_D(BytesIO);
    if (d->ownbuf) {
        delete d->buf;
    }
    delete d_ptr;
}


qint32 BytesIO::read(char *data, qint32 size)
{
    Q_D(BytesIO);
    qint32 leftBytes = qMax(d->buf->size() - d->pos, 0);
    qint32 readBytes = qMin(leftBytes, size);
    memcpy(data, d->buf->data() + d->pos, static_cast<size_t>(readBytes));
    d->pos += readBytes;
    return readBytes;
}


qint32 BytesIO::write(const char *data, qint32 size)
{
    Q_D(BytesIO);
    if (d->pos + size > d->buf->size()) {
        d->buf->resize(d->pos + size);
    }
    memcpy(d->buf->data() + d->pos, data, static_cast<size_t>(size));
    d->pos += size;
    return size;
}


void BytesIO::close()
{

}


qint64 BytesIO::size()
{
    Q_D(BytesIO);
    return d->buf->size();
}


QByteArray BytesIO::readall(bool *ok)
{
    Q_D(BytesIO);
    if (ok) *ok = true;
    if (Q_LIKELY(d->pos == 0)) {
        d->pos = d->buf->size();
        return *d->buf;
    } else {
        const QByteArray &t = d->buf->mid(d->pos);
        d->pos = d->buf->size();
        return t;
    }
}


QByteArray BytesIO::data()
{
    Q_D(BytesIO);
    return *d->buf;
}


QSharedPointer<FileLike> FileLike::bytes(const QByteArray &data)
{
    return QSharedPointer<BytesIO>::create(data);
}


QSharedPointer<FileLike> FileLike::bytes(QByteArray *data)
{
    return QSharedPointer<BytesIO>::create(data);
}


bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy, int suitableBlockSize)
{
    if (inputFile.isNull() || outputFile.isNull()) {
        return false;
    }
    if (bytesToCopy == 0) {
        return true;
    } else if (bytesToCopy < 0) {
        bytesToCopy = inputFile->size();
        if (bytesToCopy == 0) {
            return true;
        } else if (bytesToCopy < 0) {
            // size() is not supported.
        }
    }
    QVarLengthArray<char, 1024 * 16> buf;
    qint64 total = 0;
    bool eof = false;
    while (true) {
        qint64 remain = INT64_MAX;
        if (bytesToCopy > 0) {
            remain = qMax<qint64>(0, bytesToCopy - total);
        }
        if (remain > 0 && buf.size() < suitableBlockSize && !eof) {
            qint32 nextBlockSize = qMin<qint64>(suitableBlockSize, remain);
            qint32 oldSize = buf.size();
            buf.resize(oldSize + nextBlockSize);
            qint32 readBytes = inputFile->read(buf.data() + oldSize , nextBlockSize);
            if (readBytes < 0) {
                return false;
            } else if (readBytes > 0) {
                total += readBytes;
                buf.resize(oldSize + readBytes);
            } else {
                buf.resize(oldSize);
                eof = true;
            }
        }
        if (buf.isEmpty()) {
            return bytesToCopy < 0 || total == bytesToCopy;
        } else {
            qint32 writtenBytes = outputFile->write(buf.data(), buf.size());
            if (writtenBytes <= 0) {
                return false;
            }
            buf.remove(0, writtenBytes);
        }
    }
}


class PosixPathPrivate: public QSharedData
{
public:
    PosixPathPrivate(const QString &path)
        : path(path)
    {
        QString t = path;
        while (t.endsWith(QLatin1Char('/'))) {
            t.resize(t.size() - 1);
        }
        if (t.isEmpty()) {
            t = QString::fromLatin1("/");
        }
        info = QFileInfo(t);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
        parts = path.split(QLatin1String("/"), Qt::SkipEmptyParts);
#else
        parts = path.split(QLatin1String("/"), QString::SkipEmptyParts);
#endif
    }
public:
    QString path;
    QFileInfo info;
    QStringList parts;
};


PosixPath::PosixPath(const QString &path)
    : d(new PosixPathPrivate(path))
{
}


PosixPath::PosixPath()
    : d(nullptr)
{}


PosixPath::PosixPath(const PosixPath &other)
    : d(other.d)
{}


#ifdef Q_COMPILER_RVALUE_REFS

PosixPath::PosixPath(PosixPath &&other)
    : d(nullptr)
{
    qSwap(d, other.d);
}


PosixPath::~PosixPath() {}


PosixPath &PosixPath::operator = (PosixPath &&other) Q_DECL_NOTHROW
{
    qSwap(d, other.d);
    return *this;
}

#endif


PosixPath &PosixPath::operator = (const PosixPath &other)
{
    d = other.d;
    return *this;
}


bool PosixPath::operator==(const PosixPath &other) const
{
    if (!d && !other.d) {
        return true;
    } else if (d && !other.d) {
        return false;
    } else if (!d && other.d) {
        return false;
    } else {
        return d->path == other.d->path;
    }
}


PosixPath PosixPath::operator / (const QString &path) const
{
    if (isNull()) {
        return PosixPath();
    }
    if (path.startsWith(QLatin1Char('/'))) {
        return PosixPath(path);
    } else {
        QString t = d->path;
        if (t.endsWith(QLatin1Char('/'))) {
            t += path;
        } else {
            t += QLatin1Char('/') + path;
        }
        return PosixPath(t);
    }
}


bool PosixPath::isNull() const
{
    return !d || d->path.isEmpty();
}


bool PosixPath::isFile() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isFile();
}


bool PosixPath::isDir() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isDir();
}


bool PosixPath::isSymLink() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isSymLink();
}


bool PosixPath::isAbsolute() const
{
    if (isNull()) {
        return false;
    }
    return d->path.startsWith(QLatin1Char('/'));
}


bool PosixPath::isExecutable() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isExecutable();
}


bool PosixPath::isReadable() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isReadable();
}


bool PosixPath::isRelative() const
{
    if (isNull()) {
        return false;
    }

    if (!d->path.startsWith(QLatin1Char('/'))) {
        return true;
    }
    for (const QString &part: d->parts) {
        if (part == QString::fromUtf8(".") || part == QString::fromUtf8("..")) {
            return true;
        }
    }
    return false;
}


bool PosixPath::isRoot() const
{
    if (isNull()) {
        return false;
    }
    return d->path.startsWith(QLatin1Char('/')) && d->parts.isEmpty();
}


bool PosixPath::isWritable() const
{
    if (isNull()) {
        return false;
    }
    return d->info.isWritable();
}


bool PosixPath::exists() const
{
    if (isNull()) {
        return false;
    }
    return d->info.exists();
}


qint64 PosixPath::size() const
{
    if (isNull()) {
        return 0;
    }
    return d->info.size();
}


QString PosixPath::path() const
{
    if (isNull()) {
        return QString();
    }
    return d->path;
}


QFileInfo PosixPath::fileInfo() const
{
    if (isNull()) {
        return QFileInfo();
    }
    return d->info;
}


QString PosixPath::parentDir() const
{
    if (isNull()) {
        return QString();
    }
    QStringList parts = d->parts;
    if (!parts.isEmpty()) {
        parts.takeLast();
    }
    QString parent = parts.join(QLatin1Char('/'));
    if (d->path.startsWith(QLatin1Char('/'))) {
        parent = QLatin1Char('/') + parent;
    }
    return parent;
}


PosixPath PosixPath::parentPath() const
{
    if (isNull()) {
        return PosixPath();
    }
    return PosixPath(parentDir());
}


QString PosixPath::name() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.fileName();
}


QString PosixPath::baseName() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.baseName();
}


QString PosixPath::suffix() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.suffix();
}


QString PosixPath::completeBaseName() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.completeBaseName();
}


QString PosixPath::completeSuffix() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.completeSuffix();
}


QString PosixPath::toAbsolute() const
{
    if (isNull()) {
        return QString();
    }
    return d->info.absoluteFilePath();
}


QString PosixPath::relativePath(const QString &other) const
{
    if (isNull()) {
        return QString();
    }
    QDir dir(d->path);
    return dir.relativeFilePath(other);
}


QString PosixPath::relativePath(const PosixPath &other) const
{
    if (isNull()) {
        return QString();
    }
    QDir dir(d->path);
    return dir.relativeFilePath(other.d->path);
}


bool PosixPath::isChildOf(const PosixPath &other) const
{
    return !other.relativePath(*this).startsWith(QString::fromLatin1(".."));
}


bool PosixPath::hasChildOf(const PosixPath &other) const
{
    return !relativePath(other).startsWith(QString::fromLatin1(".."));
}


QDateTime PosixPath::created() const
{
    if (isNull()) {
        return QDateTime();
    }
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QDateTime dt = d->info.birthTime();
    if (!dt.isValid()) {
        dt = d->info.metadataChangeTime();
    }
    return dt;
#else
    return d->info.created();
#endif
}


QDateTime PosixPath::lastModified() const
{
    if (isNull()) {
        return QDateTime();
    }
    return d->info.lastModified();
}


QDateTime PosixPath::lastRead() const
{
    if (isNull()) {
        return QDateTime();
    }
    return d->info.lastRead();
}


QStringList PosixPath::listdir() const
{
    if (isNull()) {
        return QStringList();
    }
    QDir dir(d->path);
    return dir.entryList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
}


QList<PosixPath> PosixPath::children() const
{
    if (isNull()) {
        return QList<PosixPath>();
    }
    QDir dir(d->path);
    QList<PosixPath> children;
    for (const QString &child: dir.entryList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot)) {
        children.append(*this / child);
    }
    return children;
}


PosixPath PosixPath::cwd()
{
    return PosixPath(QDir::currentPath());
}


static QString makeSafePath(const QString &subPath)
{
    // remove '.' && '.."
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    const QStringList &list = subPath.split(QLatin1Char('/'), Qt::SkipEmptyParts);
#else
    const QStringList &list = subPath.split(QLatin1Char('/'), QString::SkipEmptyParts);
#endif
    QStringList l;
    for (const QString &part: list) {
        if (part == QLatin1String(".")) { // if part contains space, it is not dot dir.
            continue;
        } else if (part == QLatin1String("..")) {
            if (!l.isEmpty()) {
                l.removeLast();
            }
        } else {
            l.append(part);
        }
    }
    return l.join(QLatin1Char('/')); // without the leading slash.
}


QDebug &operator << (QDebug &out, const PosixPath &path)
{
    out << path.path();
    return out;
}


QPair<QString, QString> safeJoinPath(const QString &parentDir, const QString &subPath)
{
    const QString &safeSubPath = makeSafePath(subPath);
    if (parentDir.endsWith(QLatin1Char('/'))) {
        return qMakePair(parentDir + safeSubPath, safeSubPath);
    } else {
        return qMakePair(parentDir + QLatin1Char('/') + safeSubPath, safeSubPath);
    }
}


QPair<QFileInfo, QString> safeJoinPath(const QDir &parentDir, const QString &subPath)
{
    const QString &safeSubPath = makeSafePath(subPath);
    return qMakePair(QFileInfo(parentDir, safeSubPath), safeSubPath);
}


PosixPath PosixPath::operator | (const QString &path) const
{
    if (isNull()) {
        return PosixPath();
    }
    const QString &newPath = d->path + QLatin1Char('/') + makeSafePath(path);
    return PosixPath(newPath);
}


QTNETWORKNG_NAMESPACE_END
