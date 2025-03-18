#include <QtCore/qdir.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qscopeguard.h>
#include <QtCore/qmetaobject.h>
#ifdef Q_OS_UNIX
#include <unistd.h>
#include <fcntl.h>
#ifdef Q_OS_ANDROID
#include <errno.h>
#endif
#endif
#include "../include/io_utils.h"
#include "../include/coroutine_utils.h"
#include "debugger.h"

QTNG_LOGGER("qtng.io_utils");

QTNETWORKNG_NAMESPACE_BEGIN

FileLike::~FileLike() { }

QByteArray FileLike::readall(bool *ok)
{
    QByteArray data;
    qint64 s = size();
    if (s >= static_cast<qint64>(INT32_MAX)) {
        if (ok)
            *ok = false;
        return data;
    } else if (s == 0) {
        return data;
    } else if (s < 0) {
        // size() is not supported.
    } else {  // 0 < s < INT32_MAX
        data.reserve(static_cast<qint32>(s));
    }
    char buf[1024 * 8];
    while (true) {
        qint32 readBytes = read(buf, 1024 * 8);
        if (readBytes <= 0) {
            if (ok)
                *ok = (s < 0 || data.size() == s);
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
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
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
        if (!watcher.start()) {
            return -1;
        }
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
    ScopedIoWatcher watcher(EventLoopCoroutine::Write, f->handle());
    while (true) {
        ssize_t r = 0;
        do {
            r = ::write(fd, data, static_cast<size_t>(size));
        } while (r < 0 && errno == EINTR);
        if (r <= 0) {
            int e = errno;
            switch (e) {
#if EWOULDBLOCK - 0 && EWOULDBLOCK != EAGAIN
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
        if (!watcher.start()) {
            return -1;
        }
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

bool RawFile::seek(qint64 pos)
{
#ifdef Q_OS_UNIX
    int fd = f->handle();
    if (fd <= 0) {
        return false;
    }
#if defined(_LARGEFILE64_SOURCE)
    return ::lseek64(fd, pos, SEEK_SET) >= 0;
#else
    return ::lseek(fd, pos, SEEK_SET) >= 0;
#endif
#else
    return f->seek(pos);
#endif
}

QString RawFile::fileName() const
{
    return f->fileName();
}

static inline bool isTheMode(const QString &mode, const QString &essential)
{
    QString t = mode;
    t.remove(QLatin1Char('+'));
    t.remove(QLatin1Char('b'));
    return t == essential;
}

QSharedPointer<RawFile> RawFile::open(const QString &filepath, const QString &mode)
{
    QSharedPointer<QFile> f(new QFile(filepath));
    QIODevice::OpenMode flags = QIODevice::NotOpen;
    if (mode == QString() || isTheMode(mode, QString::fromUtf8("r"))) {
        flags |= QIODevice::ReadOnly;
        if (mode.contains(QLatin1Char('+'))) {
            flags |= QIODevice::WriteOnly;
        }
    } else if (isTheMode(mode, QString::fromUtf8("w")) || isTheMode(mode, QString::fromUtf8("rw"))
               || isTheMode(mode, QString::fromUtf8("wr"))) {
        flags |= QIODevice::WriteOnly;
        flags |= QIODevice::Truncate;
        if (mode.contains(QLatin1Char('+')) || mode.contains(QLatin1Char('r'))) {
            flags |= QIODevice::ReadOnly;
        }
    } else if (isTheMode(mode, QString::fromUtf8("a"))) {
        flags |= QIODevice::WriteOnly | QIODevice::Append;
        if (mode.contains(QLatin1Char('+'))) {
            flags |= QIODevice::ReadOnly;
        }
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    } else if (isTheMode(mode, QString::fromUtf8("x"))) {
        flags |= QIODevice::WriteOnly | QIODevice::NewOnly;
        if (mode.contains(QLatin1Char('+'))) {
            flags |= QIODevice::ReadOnly;
        }
#endif
    } else {
        qtng_warning << "unknown file mode:" << mode;
        return QSharedPointer<RawFile>();
    }
    if (!f->open(flags)) {
        return QSharedPointer<RawFile>();
    } else {
        QSharedPointer<RawFile> openFile(new RawFile(f));
        if ((flags & QIODevice::Append) && !openFile->seek(f->size())) {
            return QSharedPointer<RawFile>();
        }
#ifdef Q_OS_UNIX
        int fd = f->handle();
        if (fd <= 0) {
            return QSharedPointer<RawFile>();
        }
#if !defined(Q_OS_VXWORKS)
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags == -1 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            return QSharedPointer<RawFile>();
        }
#else  // Q_OS_VXWORKS
        int onoff = 1;
        if (::ioctl(fd, FIONBIO, (int) &onoff) < 0) {
            return QSharedPointer<RawFile>();
        }
#endif  // Q_OS_VXWORKS
#endif
        return openFile;
    }
}

QSharedPointer<RawFile> RawFile::open(const QString &filepath, QIODevice::OpenMode mode)
{
    QSharedPointer<QFile> f(new QFile(filepath));
    if (!f->open(mode)) {
        return QSharedPointer<RawFile>();
    } else {
        QSharedPointer<RawFile> openFile(new RawFile(f));
        if ((mode & QIODevice::Append) && !openFile->seek(f->size())) {
            return QSharedPointer<RawFile>();
        }
        return openFile;
    }
}

QSharedPointer<FileLike> FileLike::rawFile(QSharedPointer<QFile> f)
{
    return QSharedPointer<RawFile>::create(f).staticCast<FileLike>();
}

QSharedPointer<FileLike> FileLike::open(const QString &filepath, const QString &mode)
{
    bool isQtResource = filepath.startsWith(QString::fromUtf8(":/"));
    if (isQtResource) {
        if (!mode.isEmpty() && mode != QString::fromUtf8("r")) {
            return QSharedPointer<FileLike>();
        }
        QFile f(filepath);
        if (!f.open(QIODevice::ReadOnly)) {
            return QSharedPointer<FileLike>();
        }
        QByteArray data = f.readAll();
        return bytes(data);
    }
    return RawFile::open(filepath, mode).staticCast<FileLike>();
}

class BytesIOPrivate
{
public:
    BytesIOPrivate(qint32 pos)
        : buf(nullptr)
        , pos(pos)
        , ownbuf(false)
    {
    }
    QByteArray *buf;
    qint32 pos;
    bool ownbuf;
};

BytesIO::BytesIO(const QByteArray &buf, qint32 pos)
    : d_ptr(new BytesIOPrivate(pos))
{
    Q_D(BytesIO);
    d->buf = new QByteArray(buf);
    d->ownbuf = true;
}

BytesIO::BytesIO(QByteArray *buf, qint32 pos)
    : d_ptr(new BytesIOPrivate(pos))
{
    Q_D(BytesIO);
    d->buf = buf;
    d->ownbuf = false;
}

BytesIO::BytesIO()
    : d_ptr(new BytesIOPrivate(0))
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

void BytesIO::close() { }

qint64 BytesIO::size()
{
    Q_D(BytesIO);
    return d->buf->size();
}

QByteArray BytesIO::readall(bool *ok)
{
    Q_D(BytesIO);
    if (ok)
        *ok = true;
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

bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy,
              int suitableBlockSize)
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
            qint32 readBytes = inputFile->read(buf.data() + oldSize, nextBlockSize);
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

class PipePrivate
{
public:
    PipePrivate(Pipe *q, qint32 maxBufferSize)
        : q_ptr(q)
        , maxBufferSize(maxBufferSize)
        , closed(false)
        , shouldEmitReadyRead(false)
        , shouldEmitBytesWritten(false)
    {
        notEmpty.clear();
        notFull.set();
    }
public:
    Pipe * const q_ptr;
    QByteArray buffer;
    ThreadEvent notEmpty;
    ThreadEvent notFull;
    QMutex lock;
    const qint32 maxBufferSize;
    bool closed;
    bool shouldEmitReadyRead;
    bool shouldEmitBytesWritten;
};

Pipe::Pipe(qint32 maxBufferSize)
    : d(new PipePrivate(this, maxBufferSize))
{
}

class FileToRead : public FileLike
{
public:
    explicit FileToRead(QSharedPointer<PipePrivate> pp)
        : pp(pp)
    {
    }
    virtual ~FileToRead() override { close(); }
public:
    virtual qint32 read(char *data, qint32 size) override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return -1;
        }
        QMutexLocker locker(&pp->lock);
        if (pp->buffer.isEmpty()) {
            if (pp->closed) {
                // pipe is closed.
                return -1;
            } else {
                if (!pp->notEmpty.tryWait()) {
                    return -1;
                }
                if (pp->buffer.isEmpty()) {
                    // another peer closed this pipe
                    Q_ASSERT(pp->closed);
                    return -1;
                }
            }
        }

        qint32 bytesToRead = qMin(size, pp->buffer.size());
        memcpy(data, pp->buffer.constData(), bytesToRead);
        pp->buffer.remove(0, bytesToRead);
        if (pp->buffer.size() < pp->maxBufferSize) {
            pp->notFull.set();
        }
        if (pp->buffer.isEmpty() && !pp->closed) {
            pp->notEmpty.clear();
        }
        if (pp->shouldEmitBytesWritten) {
            QMetaObject::invokeMethod(pp->q_ptr, SIGNAL(bytesWritten(qint64)), Qt::QueuedConnection,
                                      Q_ARG(qint64, bytesToRead));
        }
        return bytesToRead;
    }

    virtual qint32 write(const char *, qint32) override { return -1; }

    virtual void close() override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return;
        }
        QMutexLocker locker(&pp->lock);
        pp->notFull.set();
        pp->notEmpty.set();
        // discard all bytes of buffer.
        pp->buffer.clear();
        pp->closed = true;
    }
    virtual qint64 size() override { return -1; }
public:
    const QWeakPointer<PipePrivate> pp;
    QSharedPointer<Pipe> pipe;
};

QSharedPointer<FileLike> Pipe::fileToRead(bool takePipe)
{
    QSharedPointer<FileToRead> f = QSharedPointer<FileToRead>::create(d);
    if (takePipe) {
        f->pipe = sharedFromThis();
    }
    return f;
}

class FileToWrite : public FileLike
{
public:
    explicit FileToWrite(QSharedPointer<PipePrivate> pp)
        : pp(pp)
    {
    }
    virtual ~FileToWrite() override { close(); }
public:
    virtual qint32 read(char *, qint32) override { return -1; }
    virtual qint32 write(const char *data, qint32 size) override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return -1;
        }
        QMutexLocker locker(&pp->lock);
        if (pp->closed) {
            // pipe is closed. don't write anymore.
            return -1;
        }
        if (pp->buffer.size() >= pp->maxBufferSize) {
            if (!pp->notFull.tryWait()) {
                return -1;
            }
            if (pp->closed) {
                // pipe is closed. don't write anymore.
                return -1;
            } else {
                Q_ASSERT(pp->buffer.size() < pp->maxBufferSize);
            }
        }
        qint32 bytesToWrite = qMin(pp->maxBufferSize - pp->buffer.size(), size);
        pp->buffer.append(data, bytesToWrite);
        pp->notEmpty.set();
        if (!pp->closed && pp->buffer.size() >= pp->maxBufferSize) {
            pp->notFull.clear();
        }
        if (pp->shouldEmitReadyRead) {
            QMetaObject::invokeMethod(pp->q_ptr, SIGNAL(readyRead()));
        }
        return bytesToWrite;
    }
    virtual void close() override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return;
        }
        QMutexLocker locker(&pp->lock);
        pp->notFull.set();
        pp->notEmpty.set();
        // do not discard buffer.
        // pp->buffer.clear();
        pp->closed = true;
    }
    virtual qint64 size() override { return -1; }
public:
    const QWeakPointer<PipePrivate> pp;
    QSharedPointer<Pipe> pipe;
};

QSharedPointer<FileLike> Pipe::fileToWrite(bool takePipe)
{
    QSharedPointer<FileToWrite> f = QSharedPointer<FileToWrite>::create(d);
    if (takePipe) {
        f->pipe = sharedFromThis();
    }
    return f;
}

class DeviceToRead : public QIODevice
{
public:
    explicit DeviceToRead(QSharedPointer<PipePrivate> pp, bool connectSignals)
        : pp(pp)
    {
        bool ok = QIODevice::open(QIODevice::ReadOnly | QIODevice::Unbuffered);
        Q_ASSERT(ok);
        if (connectSignals) {
            pp->shouldEmitReadyRead = true;
            connect(pp->q_ptr, SIGNAL(readyRead()), this, SIGNAL(readyRead()));
        }
    }
    virtual ~DeviceToRead() override { close(); }
public:
    virtual bool atEnd() const override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return true;
        }
        QMutexLocker locker(&pp->lock);
        // may has some bytes left in the internal buffer of QIODevice.
        // for example, some func called peek() before.
        if (!QIODevice::atEnd()) {
            return false;
        }
        return pp->buffer.isEmpty() && pp->closed;
    }

    virtual qint64 bytesAvailable() const override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return 0;
        }
        QMutexLocker locker(&pp->lock);
        // QIODevice::bytesAvailable() can be greater than 0 when peek() is called.
        return pp->buffer.size() + QIODevice::bytesAvailable();
    }

    virtual qint64 bytesToWrite() const override { return 0; }

    virtual bool canReadLine() const override { return false; }

    virtual bool isSequential() const override { return true; }

    virtual void close() override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return;
        }
        QMutexLocker locker(&pp->lock);
        // emit aboutToClose()
        QIODevice::close();
        pp->notFull.set();
        pp->notEmpty.set();
        // discard all content from buffer.
        pp->buffer.clear();
        pp->closed = true;
    }

    virtual qint64 readData(char *data, qint64 maxSize) override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return -1;
        }
        QMutexLocker locker(&pp->lock);
        qint64 bytesToRead = qMin<qint64>(pp->buffer.size(), maxSize);
        memcpy(data, pp->buffer.constData(), bytesToRead);
        pp->buffer.remove(0, bytesToRead);
        if (pp->buffer.size() < pp->maxBufferSize || pp->closed) {
            pp->notFull.set();
        }
        if (pp->buffer.isEmpty() && !pp->closed) {
            pp->notEmpty.clear();
        }
        if (pp->shouldEmitBytesWritten) {
            QMetaObject::invokeMethod(pp->q_ptr, SIGNAL(bytesWritten(qint64)), Q_ARG(qint64, bytesToRead));
        }
        return bytesToRead;
    }
    virtual qint64 writeData(const char *, qint64) override { return -1; }
    virtual bool waitForBytesWritten(int) override { return false; }
    virtual bool waitForReadyRead(int msecs) override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return false;
        }
        if (!pp->lock.tryLock(msecs)) {
            return false;
        }
        auto unlock = qScopeGuard([pp] { pp->lock.unlock(); });
        if (pp->buffer.isEmpty()) {
            if (pp->closed) {
                // pipe is closed.
                return false;
            } else {
                if (!pp->notEmpty.tryWait()) {
                    return false;
                }
                if (pp->buffer.isEmpty()) {
                    // another peer closed this pipe
                    Q_ASSERT(pp->closed);
                    return false;
                }
            }
        }
        return true;
    }
public:
    QWeakPointer<PipePrivate> pp;
    QSharedPointer<Pipe> pipe;
};

QSharedPointer<QIODevice> Pipe::deviceToRead(bool connectSignals, bool takePipe)
{
    QSharedPointer<DeviceToRead> v = QSharedPointer<DeviceToRead>::create(d, connectSignals);
    if (takePipe) {
        v->pipe = sharedFromThis();
    }
    return v;
}

class DeviceToWrite : public QIODevice
{
public:
    explicit DeviceToWrite(QSharedPointer<PipePrivate> pp, bool connectSignals)
        : pp(pp)
    {
        bool ok = QIODevice::open(QIODevice::WriteOnly | QIODevice::Unbuffered);
        Q_ASSERT(ok);
        if (connectSignals) {
            pp->shouldEmitBytesWritten = true;
            connect(pp->q_ptr, SIGNAL(bytesWritten(qint64)), this, SIGNAL(bytesWritten(qint64)));
        }
    }
    virtual ~DeviceToWrite() override { close(); }
public:
    virtual bool atEnd() const override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return true;
        }
        QMutexLocker locker(&pp->lock);
        return pp->closed;
    }

    virtual qint64 bytesAvailable() const override { return 0; }

    virtual qint64 bytesToWrite() const override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return true;
        }
        QMutexLocker locker(&pp->lock);
        if (pp->closed) {
            return 0;
        }
        return qMax(pp->maxBufferSize - pp->buffer.size(), 0);
    }

    virtual bool canReadLine() const override { return false; }

    virtual bool isSequential() const override { return true; }

    virtual void close() override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return;
        }
        QMutexLocker locker(&pp->lock);
        pp->notFull.set();
        pp->notEmpty.set();
        // XXX do not discard buffer. we are writer! not reader!
        // pp->buffer.clear();
        pp->closed = true;
    }

    virtual qint64 readData(char *, qint64) override { return -1; }

    virtual qint64 writeData(const char *data, qint64 size) override
    {
        // according to the document, we must write all data!
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return -1;
        }
        QMutexLocker locker(&pp->lock);
        qint64 total = 0;
        while (total < size) {
            if (pp->buffer.size() >= pp->maxBufferSize) {
                if (!pp->notFull.tryWait()) {
                    return -1;
                }
                if (pp->closed) {
                    return -1;
                }
            }
            Q_ASSERT(pp->buffer.size() < pp->maxBufferSize);
            qint64 bytesToWrite = qMin<qint32>(size - total, pp->maxBufferSize - pp->buffer.size());
            pp->buffer.append(data + total, bytesToWrite);
            total += bytesToWrite;
            pp->notEmpty.set();
            if (pp->buffer.size() >= pp->maxBufferSize && !pp->closed) {
                pp->notFull.clear();
            }
            if (pp->shouldEmitReadyRead) {
                QMetaObject::invokeMethod(pp->q_ptr, SIGNAL(readyRead()));
            }
        }
        return total;
    }

    virtual bool waitForBytesWritten(int msecs) override
    {
        QSharedPointer<PipePrivate> pp = this->pp.toStrongRef();
        if (pp.isNull()) {
            return false;
        }
        if (!pp->lock.tryLock(msecs)) {
            return false;
        }
        auto unlock = qScopeGuard([pp] { pp->lock.unlock(); });
        if (pp->buffer.size() >= pp->maxBufferSize) {
            if (pp->closed) {
                return false;
            } else {
                if (!pp->notFull.tryWait()) {
                    return false;
                }
                if (pp->buffer.size() >= pp->maxBufferSize) {
                    Q_ASSERT(pp->closed);
                    return false;
                }
            }
        }
        return true;
    }

    virtual bool waitForReadyRead(int) override { return false; }
public:
    QWeakPointer<PipePrivate> pp;
    QSharedPointer<Pipe> pipe;
};

QSharedPointer<QIODevice> Pipe::deivceToWrite(bool connectSignals, bool takePipe)
{
    QSharedPointer<DeviceToWrite> v = QSharedPointer<DeviceToWrite>::create(d, connectSignals);
    if (takePipe) {
        v->pipe = sharedFromThis();
    }
    return v;
}

class PosixPathPrivate : public QSharedData
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

        // "[space]..[space]" is not acceptable.
        for (int i = 0; i < parts.size(); ++i) {
            if (parts[i].trimmed() == PosixPath::point) {
                parts[i] = PosixPath::point;
            } else if (parts[i].trimmed() == PosixPath::pointpoint) {
                parts[i] = PosixPath::pointpoint;
            }
        }
    }
public:
    QString path;
    QFileInfo info;
    QStringList parts;
};

QChar PosixPath::point = QChar::fromLatin1('.');
QString PosixPath::pointpoint = QString::fromUtf8("..");
QChar PosixPath::seperator = QChar::fromLatin1('/');

PosixPath::PosixPath(const QString &path)
    : d(new PosixPathPrivate(path))
{
}

PosixPath::PosixPath()
    : d(nullptr)
{
}

PosixPath::PosixPath(const PosixPath &other)
    : d(other.d)
{
}

#ifdef Q_COMPILER_RVALUE_REFS

PosixPath::PosixPath(PosixPath &&other)
    : d(nullptr)
{
    qSwap(d, other.d);
}

PosixPath::~PosixPath() { }

PosixPath &PosixPath::operator=(PosixPath &&other) Q_DECL_NOTHROW
{
    qSwap(d, other.d);
    return *this;
}

#endif

PosixPath &PosixPath::operator=(const PosixPath &other)
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
        // FIXME does not handle absolute path.
        return d->path == other.d->path;
    }
}

PosixPath PosixPath::operator/(const QString &path) const
{
    if (isNull()) {
        return PosixPath();
    }
    if (path.startsWith(seperator)) {
        return PosixPath(path);
    } else {
        QString t = d->path;
        if (t.endsWith(seperator)) {
            t += path;
        } else {
            t += seperator + path;
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
    return d->path.startsWith(seperator);
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

    if (!d->path.startsWith(seperator)) {
        return true;
    }
    for (const QString &part : d->parts) {
        if (part == point || part == pointpoint) {
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
    return d->path.startsWith(seperator) && d->parts.isEmpty();
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
    QString parent = parts.join(seperator);
    if (d->path.startsWith(seperator)) {
        parent = seperator + parent;
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
    if (d->parts.isEmpty()) {
        return QString();
    }
    return d->parts.last();
}

QString PosixPath::baseName() const
{
    if (isNull()) {
        return QString();
    }
    const QString &n = name();
    const QStringList &l = n.split(point);
    if (l.isEmpty()) {
        return QString();
    } else {
        if (n.startsWith(point)) {
            return point + l.first();
        } else {
            return l.first();
        }
    }
}

QString PosixPath::suffix() const
{
    if (isNull()) {
        return QString();
    }
    const QStringList &l = name().split(point);
    if (l.size() <= 1) {
        return QString();
    } else {
        return l.last();
    }
}

QString PosixPath::completeBaseName() const
{
    if (isNull()) {
        return QString();
    }
    const QString &n = name();
    QStringList l = n.split(point);
    if (l.isEmpty()) {
        return QString();
    } else if (l.size() == 1) {
        if (n.startsWith(point)) {
            return point + l.first();
        } else {
            return l.first();
        }
    } else {
        l.removeLast();
        return l.join(point);
    }
}

QString PosixPath::completeSuffix() const
{
    if (isNull()) {
        return QString();
    }
    QStringList l = name().split(point);
    if (l.size() <= 1) {
        return QString();
    } else {
        l.removeFirst();
        return l.join(point);
    }
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
    return !other.relativePath(*this).startsWith(pointpoint);
}

bool PosixPath::hasChildOf(const PosixPath &other) const
{
    return !relativePath(other).startsWith(pointpoint);
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
    for (const QString &child : dir.entryList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot)) {
        children.append(*this / child);
    }
    return children;
}

bool PosixPath::mkdir(bool createParents)
{
    if (isDir()) {
        return true;
    }
    if (exists()) {
        return false;
    }
    QDir d(parentDir());
    if (createParents) {
        return d.mkpath(name());
    } else {
        return d.mkdir(name());
    }
}

bool PosixPath::touch()
{
    Q_ASSERT(false);  // "not implemented."
    return false;
}

QSharedPointer<RawFile> PosixPath::open(const QString &mode) const
{
    return RawFile::open(d->path, mode);
}

QByteArray PosixPath::readall(bool *ok) const
{
    QSharedPointer<RawFile> f = RawFile::open(d->path);
    if (f.isNull()) {
        if (ok) {
            *ok = false;
        }
        return QByteArray();
    }
    return f->readall(ok);
}

PosixPath PosixPath::cwd()
{
    return PosixPath(QDir::currentPath());
}

static QString makeSafePath(const QString &subPath)
{
    // remove '.' && '.."

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    const QVector<QStringRef> &parts = subPath.splitRef(QLatin1Char('/'), Qt::SkipEmptyParts);
#elif (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
    const QVector<QStringRef> &parts = subPath.splitRef(QLatin1Char('/'), QString::SkipEmptyParts);
#else
    const QStringList &parts = subPath.split(QLatin1Char('/'), QString::SkipEmptyParts);
#endif
    QStringList l;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
    for (const QStringRef &part : parts) {
#else
    for (const QString &part : parts) {
#endif
        if (part == PosixPath::point) {  // if part contains space, it is not dot dir.
            continue;
        } else if (part == PosixPath::pointpoint) {
            if (!l.isEmpty()) {
                l.removeLast();
            }
        } else {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
            l.append(part.toString());
#else
            l.append(part);
#endif
        }
    }
    return l.join(PosixPath::seperator);  // without the leading slash.
}

QDebug &operator<<(QDebug &out, const PosixPath &path)
{
    out << path.path();
    return out;
}

QPair<QString, QString> safeJoinPath(const QString &parentDir, const QString &subPath)
{
    const QString &safeSubPath = makeSafePath(subPath);
    if (parentDir.endsWith(PosixPath::seperator)) {
        return qMakePair(parentDir + safeSubPath, safeSubPath);
    } else {
        return qMakePair(parentDir + PosixPath::seperator + safeSubPath, safeSubPath);
    }
}

QPair<QFileInfo, QString> safeJoinPath(const QDir &parentDir, const QString &subPath)
{
    const QString &safeSubPath = makeSafePath(subPath);
    return qMakePair(QFileInfo(parentDir, safeSubPath), safeSubPath);
}

PosixPath PosixPath::operator|(const QString &path) const
{
    if (isNull()) {
        return PosixPath();
    }
    const QString &newPath = d->path + PosixPath::seperator + makeSafePath(path);
    return PosixPath(newPath);
}

uint qHash(const PosixPath &path, uint seed)
{
    return qHash(path.path(), seed);
}

QTNETWORKNG_NAMESPACE_END
