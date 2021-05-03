#include "../include/gzip.h"
#include <zlib.h>

#define GZIP_WINDOWS_BIT (MAX_WBITS + 32)

QTNETWORKNG_NAMESPACE_BEGIN


class GzipCompressFilePrivate
{
public:
    GzipCompressFilePrivate(QSharedPointer<FileLike> backend, int level)
        : backend(backend)
        , level(qMax(-1, qMin(9, level)))
        , hasError(false)
        , eof(false)
    {}
public:
    QSharedPointer<FileLike> backend;
    QByteArray buf;
    z_stream zstream;
    int level;
    bool hasError;
    bool inited;
    bool eof;
};


class GzipDecompressFilePrivate
{
public:
    GzipDecompressFilePrivate(QSharedPointer<FileLike> backend)
        : backend(backend)
        , hasError(false)
        , triedRawDeflate(false)
        , eof(false)
    {}
public:
    QSharedPointer<FileLike> backend;
    QByteArray buf;
    z_stream zstream;
    bool hasError;
    bool inited;
    bool triedRawDeflate;
    bool eof;
};


GzipCompressFile::GzipCompressFile(QSharedPointer<FileLike> backend, int level)
    : d_ptr(new GzipCompressFilePrivate(backend, level))
{
    Q_D(GzipCompressFile);
    d->zstream.zalloc = nullptr;
    d->zstream.zfree = nullptr;
    d->zstream.opaque = nullptr;
    d->zstream.avail_in = 0;
    d->zstream.next_in = nullptr;
    int ret = deflateInit2(&d->zstream, level, Z_DEFLATED, GZIP_WINDOWS_BIT, 8, Z_DEFAULT_STRATEGY);
    d->inited = (ret == Z_OK);
}


GzipCompressFile::~GzipCompressFile()
{
    Q_D(GzipCompressFile);
    if (d->inited) {
        deflateEnd(&d->zstream);
    }
    delete d_ptr;
}


qint32 GzipCompressFile::read(char *data, qint32 size)
{
    Q_D(GzipCompressFile);
    if (d->hasError || !d->inited) {
        return -1;
    }

    const int OutputBufferSize = 1024 * 32;
    const int InputBufferSize = 1024 * 8;
    while (d->buf.size() < size && !d->eof) {
        QByteArray inBuf(InputBufferSize, Qt::Uninitialized);
        QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

        qint32 readBytes = d->backend->read(inBuf.data(), inBuf.size());
        if (readBytes < 0) {
            d->hasError = true;
            return -1;
        } else if (readBytes == 0) {
            d->eof = true;
        }
        d->zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
        d->zstream.avail_in = static_cast<uint>(readBytes);
        do {
            d->zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
            d->zstream.avail_out = static_cast<uint>(outBuf.size());
            int ret = deflate(&d->zstream, readBytes > 0 ? Z_NO_FLUSH : Z_FINISH);
            if (ret < 0 || ret == Z_NEED_DICT) {
                d->hasError = true;
                return -1;
            }
            if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
                d->hasError = true;
                return -1;
            }
            int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
            if (have > 0) {
                d->buf.append(outBuf.data(), static_cast<qint32>(have));
            }
        } while (d->zstream.avail_out == 0 || d->zstream.avail_in > 0);
    }
    qint32 bytesToRead = qMin(size, d->buf.size());
    memcpy(data, d->buf.data(), bytesToRead);
    d->buf.remove(0, bytesToRead);
    return bytesToRead;
}


qint32 GzipCompressFile::write(const char *data, qint32 size)
{
    Q_D(GzipCompressFile);
    if (d->hasError || !d->inited) {
        return -1;
    }
    if (Q_UNLIKELY(size == 0)) {
        return 0;
    }

    const int OutputBufferSize = 1024 * 32;
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

    d->zstream.next_in = reinterpret_cast<Bytef*>(const_cast<char *>(data));
    d->zstream.avail_in = static_cast<uint>(size);
    do {
        d->zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
        d->zstream.avail_out = static_cast<uint>(outBuf.size());
        int ret = deflate(&d->zstream, size > 0 ? Z_NO_FLUSH : Z_FINISH);
        if (ret < 0 || ret == Z_NEED_DICT) {
            d->hasError = true;
            return -1;
        }
        if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
            d->hasError = true;
            return -1;
        }
        int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
        if (have > 0) {
            d->buf.append(outBuf.data(), static_cast<qint32>(have));
        }
    } while (d->zstream.avail_out == 0 || d->zstream.avail_in > 0);

    qint32 bytesWritten = d->backend->write(d->buf.constData(), d->buf.size());
    bool success = (bytesWritten == d->buf.size());
    d->buf.clear();
    if (success) {
        return size;
    } else {
        return -1;
    }
}


GzipDecompressFile::GzipDecompressFile(QSharedPointer<FileLike> backend)
    : d_ptr(new GzipDecompressFilePrivate(backend))
{
    Q_D(GzipDecompressFile);
    d->zstream.zalloc = nullptr;
    d->zstream.zfree = nullptr;
    d->zstream.opaque = nullptr;
    d->zstream.avail_in = 0;
    d->zstream.next_in = nullptr;
    int ret = inflateInit2(&d->zstream, GZIP_WINDOWS_BIT);
    d->inited = (ret == Z_OK);
}


GzipDecompressFile::~GzipDecompressFile()
{
    Q_D(GzipDecompressFile);
    if (d->inited) {
        deflateEnd(&d->zstream);
    }
    delete d_ptr;
}


qint32 GzipDecompressFile::read(char *data, qint32 size)
{
    Q_D(GzipDecompressFile);
    if (d->hasError || !d->inited) {
        return -1;
    }
    const int OutputBufferSize = 1024 * 32;
    const int InputBufferSize = 1024 * 8;
    QByteArray inBuf(InputBufferSize, Qt::Uninitialized);
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

    while (d->buf.size() < size && !d->eof) {
        qint32 readBytes = d->backend->read(inBuf.data(), inBuf.size());
        if (readBytes < 0) {
            return false;
        } else if (readBytes == 0) {
            d->eof = true;
        }
        d->zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
        d->zstream.avail_in = static_cast<uint>(readBytes);
        do {
            d->zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
            d->zstream.avail_out = static_cast<uint>(outBuf.size());
            int ret = inflate(&d->zstream, readBytes > 0 ? Z_FULL_FLUSH : Z_FINISH);
            if (ret == Z_DATA_ERROR && !d->triedRawDeflate) {
                d->triedRawDeflate = true;
                inflateEnd(&d->zstream);
                d->zstream.zalloc = nullptr;
                d->zstream.zfree = nullptr;
                d->zstream.opaque = nullptr;
                d->zstream.avail_in = 0;
                d->zstream.next_in = nullptr;
                ret = inflateInit2(&d->zstream, -MAX_WBITS);
                if (ret != Z_OK) {
                    d->inited = false;
                    return -1;
                } else {
                    d->zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
                    d->zstream.avail_in = static_cast<uint>(readBytes);
                    continue;
                }
            } else if (ret < 0 || ret == Z_NEED_DICT) {
                d->hasError = true;
                return -1;
            }
            if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
                d->hasError = true;
                return -1;
            }
            d->triedRawDeflate = true;
            int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
            if (have > 0) {
                d->buf.append(outBuf.data(), have);
            }
        } while (d->zstream.avail_out == 0 || d->zstream.avail_in > 0);
    }
    qint32 bytesToRead = qMin(size, d->buf.size());
    memcpy(data, d->buf.data(), bytesToRead);
    d->buf.remove(0, bytesToRead);
    return bytesToRead;
}


qint32 GzipDecompressFile::write(const char *data, qint32 size)
{
    Q_D(GzipDecompressFile);
    if (d->hasError || !d->inited) {
        return -1;
    }
    if (Q_UNLIKELY(size == 0)) {
        return 0;
    }

    const int OutputBufferSize = 1024 * 32;
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

    d->zstream.next_in = reinterpret_cast<Bytef*>(const_cast<char *>(data));
    d->zstream.avail_in = static_cast<uint>(size);
    do {
        d->zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
        d->zstream.avail_out = static_cast<uint>(outBuf.size());
        int ret = inflate(&d->zstream, size > 0 ? Z_FULL_FLUSH : Z_FINISH);
        if (ret == Z_DATA_ERROR && !d->triedRawDeflate) {
            d->triedRawDeflate = true;
            inflateEnd(&d->zstream);
            d->zstream.zalloc = nullptr;
            d->zstream.zfree = nullptr;
            d->zstream.opaque = nullptr;
            d->zstream.avail_in = 0;
            d->zstream.next_in = nullptr;
            int ret = inflateInit2(&d->zstream, -MAX_WBITS);
            if (ret != Z_OK) {
                d->inited = false;
                return -1;
            } else {
                d->zstream.next_in = reinterpret_cast<Bytef*>(const_cast<char *>(data));
                d->zstream.avail_in = static_cast<uint>(size);
                continue;
            }
        } else if (ret < 0 || ret == Z_NEED_DICT) {
            d->hasError = true;
            return -1;
        }
        if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
            d->hasError = true;
            return -1;
        }
        d->triedRawDeflate = true;
        int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
        if (have > 0) {
            d->buf.append(outBuf.data(), have);
        }
    } while (d->zstream.avail_out == 0 || d->zstream.avail_in > 0);

    qint32 bytesWritten = d->backend->write(d->buf.constData(), d->buf.size());
    bool success = (bytesWritten == d->buf.size());
    d->buf.clear();
    if (success) {
        return size;
    } else {
        return -1;
    }
}


bool qGzipCompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int level)
{
    const int OutputBufferSize = 1024 * 32;
    const int InputBufferSize = 1024 * 8;

    level = qMax(-1, qMin(9, level));
    z_stream zstream;
    zstream.zalloc = nullptr;
    zstream.zfree = nullptr;
    zstream.opaque = nullptr;
    zstream.avail_in = 0;
    zstream.next_in = nullptr;

    int ret = deflateInit2(&zstream, level, Z_DEFLATED, GZIP_WINDOWS_BIT, 8, Z_DEFAULT_STRATEGY);

    if (ret != Z_OK) {
        return false;
    }

    QByteArray inBuf(InputBufferSize, Qt::Uninitialized);
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);
    qint32 readBytes = 0;
    do {
        readBytes = input->read(inBuf.data(), inBuf.size());
        if (readBytes < 0) {
            return false;
        }
        zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
        zstream.avail_in = static_cast<uint>(readBytes);
        do {
            zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
            zstream.avail_out = static_cast<uint>(outBuf.size());
            ret = deflate(&zstream, readBytes > 0 ? Z_NO_FLUSH : Z_FINISH);
            if (ret < 0 || ret == Z_NEED_DICT) {
                deflateEnd(&zstream);
                return false;
            }
            if (Q_UNLIKELY(zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
                deflateEnd(&zstream);
                return false;
            }
            int have = outBuf.size() - static_cast<int>(zstream.avail_out);
            if (have > 0) {
                output->write(outBuf.data(), static_cast<qint32>(have));
            }
        } while (zstream.avail_out == 0 || zstream.avail_in > 0);
    } while (readBytes > 0);
    deflateEnd(&zstream);
    return (ret == Z_STREAM_END);
}


bool qGzipDecompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output)
{
    const int OutputBufferSize = 1024 * 32;
    const int InputBufferSize = 1024 * 8;

    z_stream zstream;
    zstream.zalloc = nullptr;
    zstream.zfree = nullptr;
    zstream.opaque = nullptr;
    zstream.avail_in = 0;
    zstream.next_in = nullptr;

    int ret = inflateInit2(&zstream, GZIP_WINDOWS_BIT);
    if (ret != Z_OK) {
        return false;
    }

    QByteArray inBuf(InputBufferSize, Qt::Uninitialized);
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);
    qint32 readBytes = 0;
    bool triedRawDeflate = false;
    do {
        readBytes = input->read(inBuf.data(), inBuf.size());
        if (readBytes < 0) {
            return false;
        }
        zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
        zstream.avail_in = static_cast<uint>(readBytes);
        do {
            zstream.next_out = reinterpret_cast<Bytef*>(outBuf.data());
            zstream.avail_out = static_cast<uint>(outBuf.size());
            ret = inflate(&zstream, readBytes > 0 ? Z_FULL_FLUSH : Z_FINISH);
            if (ret == Z_DATA_ERROR && !triedRawDeflate) {
                triedRawDeflate = true;
                inflateEnd(&zstream);
                zstream.zalloc = nullptr;
                zstream.zfree = nullptr;
                zstream.opaque = nullptr;
                zstream.avail_in = 0;
                zstream.next_in = nullptr;
                int ret = inflateInit2(&zstream, -MAX_WBITS);
                if (ret != Z_OK) {
                    return false;
                } else {
                    zstream.next_in = reinterpret_cast<Bytef*>(inBuf.data());
                    zstream.avail_in = static_cast<uint>(readBytes);
                    continue;
                }
            } else if (ret < 0 || ret == Z_NEED_DICT) {
                deflateEnd(&zstream);
                return false;
            }
            if (Q_UNLIKELY(zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
                deflateEnd(&zstream);
                return false;
            }
            triedRawDeflate = true;
            int have = outBuf.size() - static_cast<int>(zstream.avail_out);
            if (have > 0) {
                output->write(outBuf.data(), static_cast<qint32>(have));
            }
        } while (zstream.avail_out == 0 || zstream.avail_in > 0);
    } while (readBytes > 0 && ret != Z_STREAM_END);
    deflateEnd(&zstream);
    return (ret == Z_STREAM_END);
}


QTNETWORKNG_NAMESPACE_END
