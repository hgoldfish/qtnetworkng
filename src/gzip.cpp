#include "../include/gzip.h"
#include <zlib.h>

#define GZIP_WINDOWS_BIT (MAX_WBITS + 32)

QTNETWORKNG_NAMESPACE_BEGIN


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
