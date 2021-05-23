#include "../include/io_utils.h"
#include "../include/coroutine_utils.h"

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
        return buf.left(readBytes);
    }
}


qint32 FileLike::write(const QByteArray &data)
{
    return this->write(data.constData(), data.size());
}


qint32 RawFile::read(char *data, qint32 size)
{
    qint64 len = f->read(data, size);
    return static_cast<qint32>(len);
}


qint32 RawFile::write(const char *data, qint32 size)
{
    qint64 len = f->write(data, size);
    return static_cast<qint32>(len);
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
    QScopedPointer<QFile> f(new QFile(filepath));
    QIODevice::OpenMode flag = QIODevice::NotOpen;
    if (mode == QString() || mode == QLatin1String("r") || mode == QLatin1String("r+") || mode == QLatin1String("rb")
            || mode == QLatin1String("rb+") || mode == QLatin1String("r+b")) {
        flag |= QIODevice::ReadOnly;
        flag |= QIODevice::ExistingOnly;
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
        qWarning("unknown file mode: %s", qPrintable(mode));
    }
    if (!f->open(flag)) {
        return QSharedPointer<FileLike>();
    } else {
        return FileLike::rawFile(f.take());
    }
}


class BytesIOPrivate
{
public:
    BytesIOPrivate(const QByteArray &buf, qint32 pos)
        :buf(buf), pos(pos) {}
    BytesIOPrivate()
        :pos(0) {}
    QByteArray buf;
    qint32 pos;
};


BytesIO::BytesIO(const QByteArray &buf, qint32 pos)
    :d_ptr(new BytesIOPrivate(buf, pos))
{
}


BytesIO::BytesIO()
    :d_ptr(new BytesIOPrivate())
{

}


BytesIO::~BytesIO()
{
    delete d_ptr;
}


qint32 BytesIO::read(char *data, qint32 size)
{
    Q_D(BytesIO);
    qint32 leftBytes = qMax(d->buf.size() - d->pos, 0);
    qint32 readBytes = qMin(leftBytes, size);
    memcpy(data, d->buf.data() + d->pos, static_cast<size_t>(readBytes));
    d->pos += readBytes;
    return readBytes;
}


qint32 BytesIO::write(const char *data, qint32 size)
{
    Q_D(BytesIO);
    if (d->pos + size > d->buf.size()) {
        d->buf.resize(d->pos + size);
    }
    memcpy(d->buf.data() + d->pos, data, static_cast<size_t>(size));
    d->pos += size;
    return size;
}


void BytesIO::close()
{

}


qint64 BytesIO::size()
{
    Q_D(BytesIO);
    return d->buf.size();
}


QByteArray BytesIO::readall(bool *ok)
{
    Q_D(BytesIO);
    if (ok) *ok = true;
    if (Q_LIKELY(d->pos == 0)) {
        return d->buf;
    } else {
        return d->buf.mid(d->pos);
    }
}


QByteArray BytesIO::data()
{
    Q_D(BytesIO);
    return d->buf;
}


QSharedPointer<FileLike> FileLike::bytes(const QByteArray &data)
{
    return QSharedPointer<BytesIO>::create(data);
}


bool sendfile(QSharedPointer<FileLike> inputFile, QSharedPointer<FileLike> outputFile, qint64 bytesToCopy)
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
    QByteArray buf;
    buf.reserve(1024 * 64);
    QByteArray t(1024 * 8, Qt::Uninitialized);
    qint64 total = 0;
    bool eof = false;
    while (true) {
        qint64 remain = INT64_MAX;
        if (bytesToCopy > 0) {
            remain = qMax<qint64>(0, bytesToCopy - buf.size() - total);
        }
        if (remain > 0 && buf.size() < 1024 * 8 && !eof) {
            qint32 nextBlockSize = qMin<qint64>(t.size(), remain);
            qint32 readBytes = inputFile->read(t.data(), nextBlockSize);
            if (readBytes < 0) {
                return false;
            } else if (readBytes > 0) {
                total += readBytes;
                buf.append(t.data(), readBytes);
            } else {
                eof = true;
            }
        }
        if (buf.isEmpty()) {
            return bytesToCopy < 0 || total == bytesToCopy;
        } else {
            qint32 writtenBytes = outputFile->write(buf, buf.size());
            if (writtenBytes <= 0) {
                return false;
            }
            buf.remove(0, writtenBytes);
        }
    }
}


QTNETWORKNG_NAMESPACE_END
