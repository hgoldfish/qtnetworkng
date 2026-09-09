#include "../include/gzip.h"
#include "debugger.h"
extern "C" {
#include <zlib.h>
}

QTNG_LOGGER("qtng.gzip");

QTNETWORKNG_NAMESPACE_BEGIN

class GzipFilePrivate
{
public:
    GzipFilePrivate(QSharedPointer<FileLike> backend, GzipFile::IOMode mode, int level)
        : backend(backend)
        , mode(mode)
        , processedBytes(0)
        , level(qMax(-1, qMin(9, level)))
        , hasError(false)
        , inited(false)
        , triedRawDeflate(false)
        , eof(false)
        , aborted(false)
        , readOffset(0)
    {
    }
public:
    bool initZStream(bool asRawDeflate);
public:
    QSharedPointer<FileLike> backend;
    GzipFile::IOMode mode;
    qint64 processedBytes;
    QByteArray buf;
    z_stream zstream;
    int level;
    bool hasError;
    bool inited;
    bool triedRawDeflate;
    bool eof;
    // set by abort(): close()/dtor must not write the gzip trailer anymore.
    bool aborted;
    // read cursor into buf; the unread data is buf[readOffset, buf.size()).
    qint64 readOffset;
};

bool GzipFilePrivate::initZStream(bool asRawDeflate)
{
    if (inited) {
        deflateEnd(&zstream);
    }
    memset(&zstream, 0, sizeof(zstream));
    int ret;
    if (asRawDeflate) {
        triedRawDeflate = true;
        if (mode == GzipFile::Deflate || mode == GzipFile::Compress) {
            ret = deflateInit2(&zstream, level, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
        } else {
            Q_ASSERT(mode == GzipFile::Inflate || mode == GzipFile::Decompress);
            ret = inflateInit2(&zstream, -MAX_WBITS);
        }
    } else {
        Q_ASSERT(!triedRawDeflate);
        Q_ASSERT(mode != GzipFile::Deflate && mode != GzipFile::Inflate);
        // GZIP_WINDOWS_BIT = MAX_WBITS + 32
        if (mode == GzipFile::Compress) {
            ret = deflateInit2(&zstream, level, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY);
        } else {
            Q_ASSERT(mode == GzipFile::Decompress);
            ret = inflateInit2(&zstream, MAX_WBITS + 32);
        }
    }

    inited = (ret == Z_OK);
    return inited;
}

GzipFile::GzipFile(QSharedPointer<FileLike> backend, GzipFile::IOMode mode, int level)
    : d_ptr(new GzipFilePrivate(backend, mode, level))
{
    d_ptr->initZStream(mode == GzipFile::Inflate || mode == GzipFile::Deflate);
}

GzipFile::~GzipFile()
{
    Q_D(GzipFile);
    close();
    if (d->inited) {
        deflateEnd(&d->zstream);
    }
    delete d_ptr;
}

qint32 GzipFile::read(char *data, qint32 size)
{
    Q_D(GzipFile);
    if (d->hasError || !d->inited || ( d->mode != Decompress && d->mode != Inflate)) {
        return -1;
    }
    const int OutputBufferSize = 1024 * 48;
    const int InputBufferSize = 1024 * 8;
    QByteArray inBuf(InputBufferSize, Qt::Uninitialized);
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

    const qint64 target = size;
    while (d->buf.size() - d->readOffset < target && !d->eof) {
        // compact the already-consumed prefix before appending more decoded
        // output. without this, erase(0, n) on every read would memmove the
        // whole remaining buffer each time (O(n^2) on large streams).
        if (d->readOffset > 0) {
            d->buf.remove(0, static_cast<int>(d->readOffset));
            d->readOffset = 0;
        }
        qint32 readBytes = d->backend->read(inBuf.data(), inBuf.size());
        if (readBytes <= 0) {
            // the gzip stream have an eof mark. we expect it!
            // before the gzip steam eof, readBytes <= 0 is always error.
            if (d->buf.isEmpty()) {
                return -1;
            }
            break;
        }
        d->processedBytes += readBytes;
        d->zstream.next_in = reinterpret_cast<Bytef *>(inBuf.data());
        d->zstream.avail_in = static_cast<uint>(readBytes);
        do {
            d->zstream.next_out = reinterpret_cast<Bytef *>(outBuf.data());
            d->zstream.avail_out = static_cast<uint>(outBuf.size());
            int ret = inflate(&d->zstream, readBytes > 0 ? Z_NO_FLUSH : Z_FINISH);
            if (ret == Z_DATA_ERROR && !d->triedRawDeflate) {
                if (!d->initZStream(true)) {
                    return -1;
                }
                d->zstream.next_in = reinterpret_cast<Bytef *>(inBuf.data());
                d->zstream.avail_in = static_cast<uint>(readBytes);
                continue;
            } else if (ret < 0 || ret == Z_NEED_DICT) {
                qtng_warning << "gzip report need dict?! why this happened?";
                d->hasError = true;
                return -1;
            }
            Q_ASSERT(ret == Z_OK || ret == Z_STREAM_END);
            if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
                qtng_warning << "gzip report avail_out > outBuf.size() at reading, this is impossible!";
                d->hasError = true;
                return -1;
            }
            d->triedRawDeflate = true;
            int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
            if (have > 0) {
                d->buf.append(outBuf.data(), have);
            }
            if (ret == Z_STREAM_END) {
                d->eof = true;
                break;
            }
            if (d->zstream.avail_in == 0) {
                // all readBytes is consumed, we must read more.
                break;
            }
        } while (d->zstream.avail_out == 0);
    }
    if (d->buf.size() - d->readOffset == 0) {
        if (d->eof) {
            return 0;
        }
        // the server closed the connection prematurely, and the data was not sent completely
        return -1;
    }
    qint32 bytesToRead = qMin(size, static_cast<qint32>(d->buf.size() - d->readOffset));
    memcpy(data, d->buf.data() + d->readOffset, static_cast<size_t>(bytesToRead));
    d->readOffset += bytesToRead;
    return bytesToRead;
}

qint32 GzipFile::write(const char *data, qint32 size)
{
    Q_D(GzipFile);
    if (d->hasError || !d->inited || (d->mode != Compress && d->mode != Deflate)) {
        return -1;
    }

    const int OutputBufferSize = 1024 * 32;
    QByteArray outBuf(OutputBufferSize, Qt::Uninitialized);

    // data can be nullptr and size can be 0 while closing.
    d->zstream.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(data));
    d->zstream.avail_in = static_cast<uint>(size);
    do {
        d->zstream.next_out = reinterpret_cast<Bytef *>(outBuf.data());
        d->zstream.avail_out = static_cast<uint>(outBuf.size());
        int ret = deflate(&d->zstream, size > 0 ? Z_NO_FLUSH : Z_FINISH);
        if (ret < 0 || ret == Z_NEED_DICT) {
            if (Q_UNLIKELY(ret == Z_NEED_DICT)) {
                qtng_warning << "gzip report need dict?! why this happened?";
            }
            d->hasError = true;
            return -1;
        }
        if (Q_UNLIKELY(d->zstream.avail_out > static_cast<uint>(outBuf.size()))) {  // is this possible?
            qtng_warning << "gzip report avail_out > outBuf.size() at writing, this is impossible!";
            d->hasError = true;
            return -1;
        }
        int have = outBuf.size() - static_cast<int>(d->zstream.avail_out);
        if (have > 0) {
            d->buf.append(outBuf.data(), static_cast<qint32>(have));
        }
    } while (d->zstream.avail_out == 0 || d->zstream.avail_in > 0);

    if (d->buf.isEmpty()) {
        return size;
    }

    qint32 bytesWritten = d->backend->write(d->buf);
    d->processedBytes += bytesWritten;
    bool success = (bytesWritten == d->buf.size());
    d->buf.clear();
    return success ? size : -1;
}

void GzipFile::close()
{
    Q_D(GzipFile);
    if (d->aborted) {
        // The stream was aborted from outside (e.g. qGzipCompress lost its
        // input midway). Drop whatever is still buffered in zlib and do NOT
        // write the gzip trailer: leaving one would produce a file that looks
        // structurally complete but silently ends early.
        return;
    }
    write(nullptr, 0);
}

void GzipFile::abort()
{
    Q_D(GzipFile);
    d->aborted = true;
}

qint64 GzipFile::processedBytes() const
{
    Q_D(const GzipFile);
    return d->processedBytes;
}

bool qGzipCompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int level, int blockSize)
{
    if (input.isNull() || output.isNull()) {
        return false;
    }
    QSharedPointer<GzipFile> gzip(new GzipFile(output, GzipFile::Compress, level));
    bool success = sendfile(input, gzip, input->size(), blockSize);
    if (!success) {
        // the input failed or ended early: do not let the destructor append the
        // trailer, otherwise the backend would keep a .gz that looks complete
        // but is truncated. note: on failure the already-written output is left
        // on the backend (now obviously truncated), the caller owns cleanup.
        gzip->abort();
    }
    return success;
}

bool qGzipDecompress(QSharedPointer<FileLike> input, QSharedPointer<FileLike> output, int blockSize)
{
    if (input.isNull() || output.isNull()) {
        return false;
    }
    QSharedPointer<GzipFile> gzip(new GzipFile(input, GzipFile::Decompress));
    return sendfile(gzip, output, gzip->size(), blockSize);
}

QTNETWORKNG_NAMESPACE_END
