#include <QBuffer>
#include <QDebug>
#include "../include/msgpack.h"

#undef  CHECK_STREAM_PRECOND
#ifndef QT_NO_DEBUG
#define CHECK_STREAM_PRECOND(retVal) \
    Q_D(MsgPackStream); \
    if (!d->dev) { \
        qWarning("msgpack::Stream: No device"); \
        return retVal; \
    } \
    if (d->status != Ok) { \
        qWarning("msgpack::Stream: Invalid status."); \
        return retVal; \
    }
#else
#define CHECK_STREAM_PRECOND(retVal) \
    Q_D(MsgPackStream); \
    if (!d->dev) { \
        return retVal; \
    } \
    if (d->status != Ok) { \
        return retVal; \
    }
#endif

QTNETWORKNG_NAMESPACE_BEGIN

static inline QDateTime unpackDatetime(const QByteArray &bs)
{
#if QT_VERSION_CHECK(5, 7, 0)
    quint64 t = qFromBigEndian<quint64>(static_cast<const void*>(bs.constData()));
#else
    quint64 t = qFromBigEndian<quint64>(static_cast<const uchar*>(bs.constData()));
#endif
    qint64 msecs = (t & 0x00000003ffffffffL) * 1000 + (t >> 34) / 1000;
    return QDateTime::fromMSecsSinceEpoch(msecs);
}

class MsgPackStreamPrivate
{
public:
    MsgPackStreamPrivate();
    MsgPackStreamPrivate(QIODevice *d);
    MsgPackStreamPrivate(QByteArray *a, QIODevice::OpenMode mode);
    MsgPackStreamPrivate(const QByteArray &a);
    ~MsgPackStreamPrivate();

    QIODevice *dev;
    MsgPackStream::Status status;
    quint32 limit;
    bool owndev;
    bool flushWrites;

    bool readBytes(char *data, qint64 len);
    inline bool readBytes(quint8 *data, int len);
    bool readExtHeader(quint32 &len, quint8 &msgpackType);
    bool writeBytes(const char *data, qint64 len);
    inline bool writeBytes(const quint8 *data, int len);
    bool writeExtHeader(quint32 len, quint8 msgpackType);
    bool unpack_longlong(qint64 &i64);
    bool unpack_ulonglong(quint64 &u64);
    bool unpackString(QString &s);
    bool unpack(QVariant &v);
};

MsgPackStreamPrivate::MsgPackStreamPrivate()
    :dev(nullptr), status(MsgPackStream::Ok), owndev(false), flushWrites(false), limit(std::numeric_limits<quint32>::max())
{
}

MsgPackStreamPrivate::MsgPackStreamPrivate(QIODevice *d)
    :dev(d), status(MsgPackStream::Ok), owndev(false), flushWrites(false), limit(std::numeric_limits<quint32>::max())
{
}


MsgPackStreamPrivate::MsgPackStreamPrivate(QByteArray *a, QIODevice::OpenMode mode)
    :status(MsgPackStream::Ok), owndev(true), flushWrites(false)
{
    QBuffer *buf = new QBuffer(a);
    buf->open(mode);
    dev = buf;
    if (mode == QIODevice::ReadOnly) {
        limit = a->size();
    } else {
        limit = std::numeric_limits<quint32>::max();
    }
}


MsgPackStreamPrivate::MsgPackStreamPrivate(const QByteArray &a)
    :status(MsgPackStream::Ok), owndev(true), flushWrites(false), limit(a.size())
{
    QBuffer *buf = new QBuffer();
    buf->setData(a);
    buf->open(QIODevice::ReadOnly);
    dev = buf;
}

MsgPackStreamPrivate::~MsgPackStreamPrivate()
{
    if (owndev)
        delete dev;
}


bool MsgPackStreamPrivate::readBytes(char *data, qint64 len)
{
    if (status != MsgPackStream::Ok) {
        return false;
    }
    if (!dev) {
        status = MsgPackStream::ReadPastEnd;
        return false;
    }
    if (len > limit) {
        return false;
    }
    qint64 total = 0;
    while (total < len) {
        qint64 bs = dev->read(data, (len - total));
        if (bs < 0) {
            status = MsgPackStream::ReadPastEnd;
            return false;
        }
        data += bs;
        total += bs;
        /* Data might not be available for a bit, so wait before reading again. */
        if (total < len) {
            dev->waitForReadyRead(-1);
        }
    }
    return true;
}

bool MsgPackStreamPrivate::readBytes(quint8 *data, int len)
{
    return readBytes(static_cast<char*>(static_cast<void*>(data)), len);
}

bool MsgPackStreamPrivate::readExtHeader(quint32 &len, quint8 &msgpackType)
{
    if (!dev || status != MsgPackStream::Ok) {
        return false;
    }
    quint8 p[6];
    if (!readBytes(p, 1)) {
        return false;
    }
    if (FirstByte::FIXEXT1 <= p[0] &&
            p[0] <= FirstByte::FIXEX16) {
        len = 1;
        len <<= p[0] - FirstByte::FIXEXT1;
    } else if (p[0] == FirstByte::EXT8){
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        len = p[1];
    } else if (p[0] == FirstByte::EXT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        len = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::EXT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        len = _msgpack_load32(p + 1);
    } else {
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    if (len > limit) {
        qDebug() << "read length is too large.";
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    if (!readBytes(p + 5, 1)) {
        return false;
    }
    msgpackType = p[5];
    return true;
}

bool MsgPackStreamPrivate::unpack_longlong(qint64 &i64)
{
    quint8 p[9];
    if (!readBytes(p, 1)) {
        return false;
    }

    if (p[0] <= FirstByte::POSITIVE_FIXINT) {// positive fixint 0x00 - 0x7f
        i64 = p[0];
    } else if (p[0] >= FirstByte::NEGATIVE_FIXINT) { // negative fixint 0xe0 - 0xff
        i64 = static_cast<qint8>(p[0]);
    } else if (p[0] == FirstByte::UINT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        i64 = p[1];
    } else if (p[0] == FirstByte::INT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        i64 = static_cast<qint8>(p[1]);
    } else if (p[0] == FirstByte::UINT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        i64 = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::INT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        i64 = static_cast<qint16>(_msgpack_load16(p + 1));
    } else if (p[0] == FirstByte::UINT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        i64 = static_cast<qint64>(_msgpack_load32(p + 1));
    } else if (p[0] == FirstByte::INT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        i64 = static_cast<qint32>(_msgpack_load32(p + 1));
    } else if (p[0] == FirstByte::UINT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        quint64 u64;
        u64 = _msgpack_load64(p + 1);
        if (u64 > static_cast<quint64>(std::numeric_limits<qint64>::max())) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        i64 = static_cast<qint64>(u64);
    } else if (p[0] == FirstByte::INT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        i64 = static_cast<qint64>(_msgpack_load64(p + 1));
    } else {
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    return true;
}

bool MsgPackStreamPrivate::unpack_ulonglong(quint64 &u64)
{
    quint8 p[9];
    if (!readBytes(p, 1)) {
        return false;
    }

    if (p[0] <= FirstByte::POSITIVE_FIXINT) {// positive fixint 0x00 - 0x7f
        u64 = p[0];
    } else if (p[0] >= FirstByte::NEGATIVE_FIXINT) { // negative fixint 0xe0 - 0xff
        status = MsgPackStream::ReadCorruptData;
        return false;
    } else if (p[0] == FirstByte::UINT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        u64 = p[1];
    } else if (p[0] == FirstByte::INT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        qint8 i8 = static_cast<qint8>(p[1]);
        if (i8 < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        u64 = static_cast<quint64>(i8);
    } else if (p[0] == FirstByte::UINT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        u64 = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::INT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        qint16 i16 = static_cast<qint16>(_msgpack_load16(p + 1));
        if (i16 < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        u64 = static_cast<quint64>(i16);
    } else if (p[0] == FirstByte::UINT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        u64 = _msgpack_load32(p + 1);
    } else if (p[0] == FirstByte::INT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        qint32 i32 = static_cast<qint32>(_msgpack_load32(p + 1));
        if (i32 < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        u64 = static_cast<quint64>(i32);
    } else if (p[0] == FirstByte::UINT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        u64 = _msgpack_load64(p + 1);
    } else if (p[0] == FirstByte::INT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        u64 = _msgpack_load64(p + 1);
        qint64 i64 = static_cast<qint64>(u64);
        if (i64 < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
    } else {
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    return true;
}

bool MsgPackStreamPrivate::unpackString(QString &s)
{
    quint8 p[5];
    if (!readBytes(p, 1)) {
        return false;
    }

    quint32 len = 0;
    if (p[0] >= FirstByte::FIXSTR && p[0] <= (FirstByte::FIXSTR + 0x1f)) { // fixstr
        len = p[0] - FirstByte::FIXSTR;
    } else if (p[0] == FirstByte::STR8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        len = p[1];
    } else if (p[0] == FirstByte::STR16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        len = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::STR32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        len = _msgpack_load32(p + 1);
        if (static_cast<int>(len) < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
    } else {
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    if (len > limit) {
        qDebug() << "read string length is too large.";
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    QByteArray buf;
    if (len > 0) {
        buf.resize(static_cast<int>(len));
        if (!readBytes(buf.data(), len)) {
            return false;
        }
    }
    s = QString::fromUtf8(buf);
    return true;
}

bool MsgPackStreamPrivate::unpack(QVariant &v)
{
    quint8 p[9];
    if (!readBytes(p, 1)) {
        return false;
    }

    if (p[0] <= FirstByte::POSITIVE_FIXINT) {// positive fixint 0x00 - 0x7f
        v = p[0];
    } else if (p[0] >= FirstByte::NEGATIVE_FIXINT) { // negative fixint 0xe0 - 0xff
        v = static_cast<qint8>(p[0]);
    } else if (FirstByte::FIXMAP <= p[0] && p[0] < FirstByte::FIXARRAY) {
        quint32 len = p[0] & 0xf;
        QVariantMap m;
        for (quint32 i = 0; i < len; ++i) {
            QString key;
            QVariant value;
            if (!unpackString(key)) {
                return false;
            }
            if (!unpack(value)) {
                return false;
            }
            m.insert(key, value);
        }
        v = m;
    } else if (FirstByte::FIXARRAY <= p[0] && p[0] < FirstByte::FIXSTR) {
        quint32 len = p[0] & 0xf;
        QVariantList l;
        for (quint32 i = 0; i < len; ++i) {
            QVariant e;
            if (!unpack(e)) {
                return false;
            }
            l.append(e);
        }
        v = l;
    } else if (FirstByte::FIXSTR <= p[0] && p[0] < FirstByte::NIL) {
        quint32 len = p[0] - FirstByte::FIXSTR;
        QByteArray bs;
        if (len > 0) {
            bs.resize(static_cast<int>(len));
            if (!readBytes(bs.data(), len)) {
                return false;
            }
        }
        v = QString::fromUtf8(bs);
    } else if (p[0] == FirstByte::NIL || p[0] == FirstByte::NEVER_USED) {
        v.clear();
    } else if (p[0] == FirstByte::MFALSE) {
        v = false;
    } else if (p[0] == FirstByte::MTRUE) {
        v = true;
    } else if (p[0] == FirstByte::BIN8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        quint32 len = p[1];
        if (len > limit) {
            qDebug() << "read bytearraty length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray bs;
        if (len > 0) {
            bs.resize(static_cast<int>(len));
            if (!readBytes(bs.data(), len)) {
                return false;
            }
        }
        v = bs;
    } else if (p[0] == FirstByte::BIN16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        quint32 len = _msgpack_load16(p + 1);
        if (len > limit) {
            qDebug() << "read bytearraty length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray bs;
        if (len > 0) {
            bs.resize(static_cast<int>(len));
            if (!readBytes(bs.data(), len)) {
                return false;
            }
        }
        v = bs;
    } else if (p[0] == FirstByte::BIN32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        quint32 len = _msgpack_load32(p + 1);
        if (len > limit) {
            qDebug() << "read bytearraty length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        if (static_cast<int>(len) < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray bs;
        if (len > 0) {
            bs.resize(static_cast<int>(len));
            if (!readBytes(bs.data(), len)) {
                return false;
            }
        }
        v = bs;
    } else if (p[0] == FirstByte::EXT8) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        quint32 len = p[1];
        MsgPackExtData ext;
        ext.type = p[2];
        if (len > 0) {
            ext.payload.resize(static_cast<int>(len));
            if (!readBytes(ext.payload.data(), len)) {
                return false;
            }
        }
        v.setValue(ext);
    } else if (p[0] == FirstByte::EXT16) {
        if (!readBytes(p + 1, 3)) {
            return false;
        }
        quint32 len = _msgpack_load16(p + 1);
        if (len > limit) {
            qDebug() << "read bytearraty length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        MsgPackExtData ext;
        ext.type = p[3];
        if (len > 0) {
            ext.payload.resize(static_cast<int>(len));
            if (!readBytes(ext.payload.data(), len)) {
                return false;
            }
        }
        v.setValue(ext);
    } else if (p[0] == FirstByte::EXT32) {
        if (!readBytes(p + 1, 5)) {
            return false;
        }
        quint32 len = _msgpack_load32(p + 1);
        if (len > limit) {
            qDebug() << "read bytearraty length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        if (static_cast<int>(len) < 0){
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        MsgPackExtData ext;
        ext.type = p[5];
        if (len > 0) {
            ext.payload.resize(static_cast<int>(len));
            if (!readBytes(ext.payload.data(), len)) {
                return false;
            }
        }
        v.setValue(ext);
    } else if (p[0] == FirstByte::FLOAT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        quint32 i32 = _msgpack_load32(p + 1);
        float f = *((float *) &i32);
        v = f;
    } else if (p[0] == FirstByte::FLOAT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        quint64 i64 = _msgpack_load64(p + 1);
        double f = *((double *) &i64);
        v = f;
    } else if (p[0] == FirstByte::UINT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        v = p[1];
    } else if (p[0] == FirstByte::UINT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        v = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::UINT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        v = _msgpack_load32(p + 1);
    } else if (p[0] == FirstByte::UINT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        v = _msgpack_load64(p + 1);
    } else if (p[0] == FirstByte::INT8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        v = static_cast<qint8>(p[1]);
    } else if (p[0] == FirstByte::INT16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        v = static_cast<qint16>(_msgpack_load16(p + 1));
    } else if (p[0] == FirstByte::INT32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        v = static_cast<qint32>(_msgpack_load32(p + 1));
    } else if (p[0] == FirstByte::INT64) {
        if (!readBytes(p + 1, 8)) {
            return false;
        }
        v = static_cast<qint64>(_msgpack_load64(p + 1));
    } else if (FirstByte::FIXEXT1 <= p[0] && p[0] <= FirstByte::FIXEX16) {
        quint32 len = 1;
        len <<= p[0] - FirstByte::FIXEXT1;
        if(!readBytes(p + 1, 1)) {
            return false;
        }
        MsgPackExtData ext;
        ext.type = p[1];
        ext.payload.resize(static_cast<int>(len));
        if (!readBytes(ext.payload.data(), len)) {
            return false;
        }
        if (ext.type == 0xff && ext.payload.size() == 8) {
            const QDateTime &dt = unpackDatetime(ext.payload);
            v.setValue(dt);
        } else {
            v.setValue(ext);
        }
    } else if (p[0] == FirstByte::STR8) {
        if (!readBytes(p + 1, 1)) {
            return false;
        }
        quint32 len = p[1];
        if (len > limit) {
            qDebug() << "read string length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray buf;
        if (len > 0) {
            buf.resize(static_cast<int>(len));
            if (!readBytes(buf.data(), len)) {
                return false;
            }
        }
        v = QString::fromUtf8(buf);
    } else if (p[0] == FirstByte::STR16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        quint32 len = _msgpack_load16(p + 1);
        if (len > limit) {
            qDebug() << "read string length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray buf;
        if (len > 0) {
            buf.resize(static_cast<int>(len));
            if (!readBytes(buf.data(), len)) {
                return false;
            }
        }
        v = QString::fromUtf8(buf);
    } else if (p[0] == FirstByte::STR32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        quint32 len = _msgpack_load32(p + 1);
        if (len > limit) {
            qDebug() << "read string length is too large.";
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        if (static_cast<int>(len) < 0) {
            status = MsgPackStream::ReadCorruptData;
            return false;
        }
        QByteArray buf;
        if (len > 0) {
            buf.resize(static_cast<int>(len));
            if (!readBytes(buf.data(), len)) {
                return false;
            }
        }
        v = QString::fromUtf8(buf);
    } else if (p[0] == FirstByte::ARRAY16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        quint32 len = _msgpack_load16(p + 1);
        QVariantList l;
        for (quint32 i = 0; i < len; ++i) {
            QVariant e;
            if (!unpack(e)) {
                return false;
            }
            l.append(e);
        }
        v = l;
    } else if (p[0] == FirstByte::ARRAY32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        quint32 len = _msgpack_load32(p + 1);
        QVariantList l;
        for (quint32 i = 0; i < len; ++i) {
            QVariant e;
            if (!unpack(e)) {
                return false;
            }
            l.append(e);
        }
        v = l;
    } else if (p[0] == FirstByte::MAP16) {
        if (!readBytes(p + 1, 2)) {
            return false;
        }
        quint32 len = _msgpack_load16(p + 1);
        QVariantMap m;
        for (quint32 i = 0; i < len; ++i) {
            QString key;
            if (!unpackString(key)) {
                return false;
            }
            QVariant value;
            if (!unpack(value)) {
                return false;
            }
            m.insert(key, value);
        }
        v = m;
    } else if (p[0] == FirstByte::MAP32) {
        if (!readBytes(p + 1, 4)) {
            return false;
        }
        quint32 len = _msgpack_load32(p + 1);
        QVariantMap m;
        for (quint32 i = 0; i < len; ++i) {
            QString key;
            if (!unpackString(key)) {
                return false;
            }
            QVariant value;
            if (!unpack(value)) {
                return false;
            }
            m.insert(key, value);
        }
        v = m;
    } else {
        status = MsgPackStream::ReadCorruptData;
        return false;
    }
    return true;
}

bool MsgPackStreamPrivate::writeBytes(const char *data, qint64 len)
{
    if (status != MsgPackStream::Ok) {
        return false;
    }
    if (!dev) {
        status = MsgPackStream::WriteFailed;
        return false;
    }
    qint64 total = 0;
    while (total < len) {
        qint64 bs = dev->write(data, len - total);
        if (bs < 0) {
            status = MsgPackStream::WriteFailed;
            return false;
        }
        /* Apparently on Windows, the buffer size for named pipes is 0, and
         * any data that is written before the remote end reads it is
         * dropped (!!) without error (see https://bugreports.qt.io/browse/QTBUG-18385).
         * We must be very sure that the data has been written before we try
         * another write. This degrades performance in other cases, so callers
         * must enable this behavior explicitly.
         */
        if (flushWrites) {
            dev->waitForBytesWritten(-1);
        }

        /* Increment the write pointer and the total byte count. */
        data += bs;
        total += bs;
    }
    return true;
}

bool MsgPackStreamPrivate::writeBytes(const quint8 *data, int len)
{
    return writeBytes(static_cast<const char*>(static_cast<const void*>(data)), len);
}

bool MsgPackStreamPrivate::writeExtHeader(quint32 len, quint8 msgpackType)
{
    if (status != MsgPackStream::Ok) {
        return false;
    }
    if (!dev) {
        status = MsgPackStream::WriteFailed;
        return false;
    }
    quint8 p[6];

    quint8 sz = 2;
    if (len == 1) {
        p[0] = FirstByte::FIXEXT1;
        p[1] = msgpackType;
    } else if (len == 2) {
        p[0] = FirstByte::FIXEXT2;
        p[1] = msgpackType;
    } else if (len == 4) {
        p[0] = FirstByte::FIXEXT4;
        p[1] = msgpackType;
    } else if (len == 8) {
        p[0] = FirstByte::FIXEXT8;
        p[1] = msgpackType;
    } else if (len == 16) {
        p[0] = FirstByte::FIXEX16;
        p[1] = msgpackType;
    } else if (len <= std::numeric_limits<quint8>::max()) {
        p[0] = FirstByte::EXT8;
        p[1] = static_cast<quint8>(len);
        p[2] = msgpackType;
        sz = 3;
    } else if (len <= std::numeric_limits<quint16>::max()) {
        p[0] = FirstByte::EXT16;
        _msgpack_store16(p + 1, static_cast<quint16>(len));
        p[3] = msgpackType;
        sz = 4;
    } else {
        p[0] = FirstByte::EXT32;
        _msgpack_store32(p + 1, len);
        p[5] = msgpackType;
        sz = 6;
    }
    if (!writeBytes(p, sz)) {
        return false;
    }
    return true;
}


MsgPackStream::MsgPackStream()
    :d_ptr(new MsgPackStreamPrivate()) {}

MsgPackStream::MsgPackStream(QIODevice *d)
    :d_ptr(new MsgPackStreamPrivate(d)) {}

MsgPackStream::MsgPackStream(QByteArray *a, QIODevice::OpenMode mode)
    :d_ptr(new MsgPackStreamPrivate(a, mode)) {}

MsgPackStream::MsgPackStream(const QByteArray &a)
    :d_ptr(new MsgPackStreamPrivate(a)) {}

MsgPackStream::~MsgPackStream()
{
    delete d_ptr;
}


void MsgPackStream::setDevice(QIODevice *dev)
{
    Q_D(MsgPackStream);
    if (d->owndev) {
        delete d->dev;
    }
    d->dev = dev;
    d->owndev = false;
}

QIODevice *MsgPackStream::device() const
{
    Q_D(const MsgPackStream);
    return d->dev;
}

bool MsgPackStream::atEnd() const
{
    Q_D(const MsgPackStream);
    return d->dev ? d->dev->atEnd() : true;
}

MsgPackStream::Status MsgPackStream::status() const
{
    Q_D(const MsgPackStream);
    return d->status;
}

void MsgPackStream::resetStatus()
{
    Q_D(MsgPackStream);
    d->status = Ok;
}

void MsgPackStream::setStatus(Status status)
{
    Q_D(MsgPackStream);
    d->status = status;
}

void MsgPackStream::setFlushWrites(bool flush)
{
    Q_D(MsgPackStream);
    d->flushWrites = flush;
}

bool MsgPackStream::willFlushWrites()
{
    Q_D(const MsgPackStream);
    return d->flushWrites;
}

void MsgPackStream::setLengthLimit(quint32 limit)
{
    Q_D(MsgPackStream);
    d->limit = limit;
}

quint32 MsgPackStream::lengthLimit() const
{
    Q_D(const MsgPackStream);
    return d->limit;
}


MsgPackStream &MsgPackStream::operator>>(bool &b)
{
    CHECK_STREAM_PRECOND(*this)
    quint8 p[1];
    if (!d->readBytes(p, 1)) {
        d->status = ReadPastEnd;
        b = false;
    } else {
        if (p[0] == FirstByte::MTRUE) {
            b = true;
        } else if (p[0] == FirstByte::MFALSE) {
            b = false;
        } else {
            d->status = ReadCorruptData;
        }
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator >>(quint8 &u8)
{
    CHECK_STREAM_PRECOND(*this);
    quint64 u64;
    if (!d->unpack_ulonglong(u64)) {
        return *this;
    }
    if (u64 <= std::numeric_limits<quint8>::max()) {
        u8 = static_cast<quint8>(u64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(quint16 &u16)
{
    CHECK_STREAM_PRECOND(*this);
    quint64 u64;
    if (!d->unpack_ulonglong(u64)) {
        return *this;
    }
    if (u64 <= std::numeric_limits<quint16>::max()) {
        u16 = static_cast<quint16>(u64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(quint32 &u32)
{
    CHECK_STREAM_PRECOND(*this);
    quint64 u64;
    if (!d->unpack_ulonglong(u64)) {
        return *this;
    }
    if (u64 <= std::numeric_limits<quint32>::max()) {
        u32 = static_cast<quint32>(u64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(quint64 &u64)
{
    CHECK_STREAM_PRECOND(*this);
    d->unpack_ulonglong(u64);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(qint8 &i8)
{
    CHECK_STREAM_PRECOND(*this);
    qint64 i64;
    if (!d->unpack_longlong(i64))
        return *this;
    if (std::numeric_limits<qint8>::min() <= i64  &&
        i64 <= std::numeric_limits<qint8>::max()) {
        i8 = static_cast<qint8>(i64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(qint16 &i16)
{
    CHECK_STREAM_PRECOND(*this);
    qint64 i64;
    if (!d->unpack_longlong(i64))
        return *this;
    if (std::numeric_limits<qint16>::min() <= i64 &&
        i64 <= std::numeric_limits<qint16>::max()) {
        i16 = static_cast<qint16>(i64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(qint32 &i32)
{
    CHECK_STREAM_PRECOND(*this);
    qint64 i64;
    if (!d->unpack_longlong(i64))
        return *this;
    if (i64 >= std::numeric_limits<qint32>::min() &&
        i64 <= std::numeric_limits<qint32>::max()) {
        i32 = static_cast<qint32>(i64);
    } else {
        d->status = ReadCorruptData;
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(qint64 &i64)
{
    CHECK_STREAM_PRECOND(*this);
    d->unpack_longlong(i64);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(float &f)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[5];
    if (!d->readBytes(p, 1)) {
        return *this;
    }
    if (p[0] != FirstByte::FLOAT32) {
        d->status = ReadCorruptData;
        return *this;
    }
    if (!d->readBytes(p + 1, 4)) {
        return *this;
    }
    quint32 i32 = _msgpack_load32(p + 1);
    f = *((float *) &i32);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(double &f)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[9];
    if (!d->readBytes(p, 1)) {
        return *this;
    }
    if (p[0] != FirstByte::FLOAT64) {
        d->status = ReadCorruptData;
        return *this;
    }
    if (!d->readBytes(p + 1, 8)) {
        return *this;
    }
    quint64 i64 = _msgpack_load64(p + 1);
    f = *((double *) &i64);
//    strncpy(static_cast<char*>(static_cast<void*>(&f)), static_cast<char*>(static_cast<void*>(&i64)), 8);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(QString &str)
{
    Q_D(MsgPackStream);
    d->unpackString(str);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(QByteArray &array)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[5];
    if (!d->readBytes(p, 1)) {
        return *this;
    }
    quint32 len;
    if (p[0] == FirstByte::BIN8) {
        if (!d->readBytes(p + 1, 1)) {
            return *this;
        }
        len = p[1];
    } else if (p[0] == FirstByte::BIN16) {
        if (!d->readBytes(p + 1, 2)) {
            return *this;
        }
        len = _msgpack_load16(p + 1);
    } else if (p[0] == FirstByte::BIN32) {
        if (!d->readBytes(p + 1, 4)) {
            return *this;
        }
        len = _msgpack_load32(p + 1);
        if (static_cast<int>(len) < 0) {
            d->status = ReadCorruptData;
            return *this;
        }
    } else {
        d->status = ReadCorruptData;
        return *this;
    }
    if (len > d->limit) {
        qDebug() << "read bytearray length is too large.";
        d->status = MsgPackStream::ReadCorruptData;
        return *this;
    }
    array.resize(static_cast<int>(len));
    d->readBytes(array.data(), len);
    return *this;
}


MsgPackStream &MsgPackStream::operator>>(QDateTime &dt)
{
    CHECK_STREAM_PRECOND(*this);
    quint32 len;
    quint8 msgpackType;
    d->readExtHeader(len, msgpackType);
    if (len != 8 || msgpackType != 0xff) {
        d->status = ReadCorruptData;
        dt = QDateTime();
        return *this;
    }
    quint8 p[8];
    if (!d->readBytes(p, 8)) {
        dt = QDateTime();
        return *this;
    }
    dt = unpackDatetime(QByteArray(static_cast<char*>(static_cast<void*>(p)), 8));
    return *this;
}


MsgPackStream &MsgPackStream::operator>>(MsgPackExtData &ext)
{
    Q_D(MsgPackStream);
    quint32 len;
    bool success = d->readExtHeader(len, ext.type);
    if (!success) {
        return *this;
    }
    if (static_cast<int>(len) < 0) {
        d->status = ReadCorruptData;
        return *this;
    }
    ext.payload.resize(static_cast<int>(len));
    d->readBytes(ext.payload.data(), len);
    return *this;
}

MsgPackStream &MsgPackStream::operator>>(QVariant &v)
{
    Q_D(MsgPackStream);
    d->unpack(v);
    return *this;
}

bool MsgPackStream::readBytes(char *data, qint64 len)
{
    Q_D(MsgPackStream);
    return d->readBytes(data, len);
}

bool MsgPackStream::readExtHeader(quint32 &len, quint8 msgpackType)
{
    Q_D(MsgPackStream);
    return d->readExtHeader(len, msgpackType);
}



MsgPackStream &MsgPackStream::operator<<(bool b)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[1];
    p[0] = b ? FirstByte::MTRUE : FirstByte::MFALSE;
    d->writeBytes(p, 1);
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(quint8 u8)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[2];
    if (u8 <= FirstByte::POSITIVE_FIXINT) {
        _msgpack_store8(p, u8);
        d->writeBytes(p, 1);
    } else {
        p[0] = FirstByte::UINT8;
        _msgpack_store8(p + 1, u8);
        d->writeBytes(p, 2);
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(quint16 u16)
{
    CHECK_STREAM_PRECOND(*this);
    if (u16 <= std::numeric_limits<quint8>::max()){
        *this << static_cast<quint8>(u16);
    } else {
        quint8 p[3];
        p[0] = FirstByte::UINT16;
        _msgpack_store16(p + 1, u16);
        d->writeBytes(p, 3);
    }
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(quint32 u32)
{
    CHECK_STREAM_PRECOND(*this);
    if (u32 <= std::numeric_limits<quint16>::max()){
        *this << static_cast<quint16>(u32);
    } else {
        quint8 p[5];
        p[0] = FirstByte::UINT32;
        _msgpack_store32(p + 1, u32);
        d->writeBytes(p, 5);
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(quint64 u64)
{
    CHECK_STREAM_PRECOND(*this);
    if (u64 <= std::numeric_limits<quint32>::max()){
        *this << static_cast<quint32>(u64);
    } else {
        quint8 p[9];
        p[0] = FirstByte::UINT64;
        _msgpack_store64(p + 1, u64);
        d->writeBytes(p, 9);
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(qint8 i8)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[2];
    if (-32 <= i8) { //  && i8 <= 127 is always true
        _msgpack_store8(p, i8);
        d->writeBytes(p, 1);
    } else {
        p[0] = i8 > 0 ? FirstByte::UINT8 : FirstByte::INT8;
        _msgpack_store8(p + 1, i8);
        d->writeBytes(p, 2);
    }
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(qint16 i16)
{
    CHECK_STREAM_PRECOND(*this);

    if (std::numeric_limits<qint8>::min() <= i16 && i16 <= std::numeric_limits<qint8>::max()) {
        *this << static_cast<qint8>(i16);
    } else if(std::numeric_limits<qint8>::max() <= i16 && i16 <= std::numeric_limits<quint8>::max()) {
        quint8 p[2];
        p[0] = FirstByte::UINT8;
        _msgpack_store8(p + 1, static_cast<quint8>(i16));
        d->writeBytes(p, 2);
    } else {
        quint8 p[3];
        p[0] = i16 > 0 ? FirstByte::UINT16 : FirstByte::INT16;
        _msgpack_store16(p + 1, i16);
        d->writeBytes(p, 3);
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(qint32 i32)
{
    CHECK_STREAM_PRECOND(*this);
    if (std::numeric_limits<qint16>::min() <= i32 && i32 <= std::numeric_limits<qint16>::max()) {
        *this << static_cast<qint16>(i32);
    } else if(std::numeric_limits<qint16>::max() <= i32 && i32 <= std::numeric_limits<quint16>::max()) {
        quint8 p[3];
        p[0] = FirstByte::UINT16;
        _msgpack_store16(p + 1, static_cast<quint16>(i32));
        d->writeBytes(p, 3);
    } else {
        quint8 p[5];
        p[0] = i32 > 0 ? FirstByte::UINT32 : FirstByte::INT32;
        _msgpack_store32(p + 1, i32);
        d->writeBytes(p, 5);
    }
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(qint64 i64)
{
    CHECK_STREAM_PRECOND(*this);
    if (std::numeric_limits<qint32>::min() <= i64 && i64 <= std::numeric_limits<qint32>::max()) {
        *this << static_cast<qint32>(i64);
    } else if(std::numeric_limits<qint32>::max() <= i64 && i64 <= std::numeric_limits<quint32>::max()) {
        quint8 p[5];
        p[0] = FirstByte::UINT32;
        _msgpack_store32(p + 1, static_cast<quint32>(i64));
        d->writeBytes(p, 5);
    } else {
        quint8 p[9];
        p[0] = i64 > 0 ? FirstByte::UINT64 : FirstByte::INT64;
        _msgpack_store64(p + 1, i64);
        d->writeBytes(p, 9);
    }
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(float f)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[5];
    p[0] = FirstByte::FLOAT32;
    quint32 u32;
    u32 = *((quint32 *) &f);
//    strncpy(static_cast<char*>(static_cast<void*>(&u32)), static_cast<char*>(static_cast<void*>(&f)), 4);
    _msgpack_store32(p + 1, u32);
    d->writeBytes(p, 5);
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(double f)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[9];
    p[0] = FirstByte::FLOAT64;
    quint64 u64;
    u64 = *((quint64 *) &f);
    _msgpack_store64(p + 1, u64);
    d->writeBytes(p, 9);
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(const QString &str)
{
    CHECK_STREAM_PRECOND(*this);
    const QByteArray &bytes = str.toUtf8();
    quint32 len = static_cast<quint32>(bytes.size());
    quint8 p[5];
    int sz;
    if (len <= 31) {
        p[0] = FirstByte::FIXSTR | len;
        sz = 1;
    } else if (len <= std::numeric_limits<quint8>::max()) {
        p[0] = FirstByte::STR8;
        _msgpack_store8(p + 1, static_cast<quint8>(len));
        sz = 2;
    } else if (len <= std::numeric_limits<quint16>::max()) {
        p[0] = FirstByte::STR16;
        _msgpack_store16(p + 1, static_cast<quint16>(len));
        sz = 3;
    } else {
        p[0] = FirstByte::STR32;
        _msgpack_store32(p + 1, len);
        sz = 5;
    }
    if (!d->writeBytes(p, sz)) {
        return *this;
    }
    d->writeBytes(bytes.data(), len);
    return *this;
}


MsgPackStream &MsgPackStream::operator<<(const QByteArray &array)
{
    CHECK_STREAM_PRECOND(*this);
    quint8 p[5];
    quint32 len = static_cast<quint32>(array.length());
    int sz;
    if (len <= std::numeric_limits<quint8>::max()) {
        p[0] = FirstByte::BIN8;
        _msgpack_store8(p + 1, static_cast<quint8>(len));
        sz = 2;
    } else if (len <= std::numeric_limits<quint16>::max()) {
        p[0] = FirstByte::BIN16;
        _msgpack_store16(p + 1, static_cast<quint16>(len));
        sz = 3;
    } else {
        p[0] = FirstByte::BIN32;
        _msgpack_store32(p + 1, len);
        sz = 5;
    }
    if (!d->writeBytes(p, sz)) {
        return *this;
    }
    d->writeBytes(array.data(), len);
    return *this;
}

static QByteArray packDatetime(const QDateTime &dt)
{
    if(!dt.isValid()) {
        return QByteArray();
    }
    quint64 msecs = static_cast<quint64>(dt.toMSecsSinceEpoch());
    quint64 t = ((msecs % 1000) * 1000) << 34 | (msecs / 1000);
    QByteArray bs;
    bs.resize(8);
#if QT_VERSION_CHECK(5, 7, 0)
    qToBigEndian(t, static_cast<void*>(bs.data()));
#else
    qToBigEndian(t, static_cast<uchar*>(bs.data()));
#endif
    return bs;
}

MsgPackStream &MsgPackStream::operator<<(const QDateTime &dt)
{
    CHECK_STREAM_PRECOND(*this);
    const QByteArray &bs = packDatetime(dt);
    if (bs.isEmpty()) {
        d->status = WriteFailed;
        return *this;
    }
    if (!d->writeExtHeader(static_cast<quint32>(bs.size()), 0xff)) {
        return *this;
    }
    d->writeBytes(bs.data(), bs.size());
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(const MsgPackExtData &ext)
{
    CHECK_STREAM_PRECOND(*this);
    bool success = d->writeExtHeader(static_cast<quint32>(ext.payload.size()), ext.type);
    if (!success) {
        return *this;
    }
    d->writeBytes(ext.payload.data(), ext.payload.size());
    return *this;
}

MsgPackStream &MsgPackStream::operator<<(const QVariant &v)
{
    CHECK_STREAM_PRECOND(*this);
    QVariant::Type t = v.type();
    if (!v.isValid()) {
        quint8 p[1];
        p[0] = FirstByte::NIL;
        d->writeBytes(p, 1);
        return *this;
    } else if (t == QVariant::Int) {
        return *this << v.toInt();
    } else if (t == QVariant::UInt) {
        return *this << v.toUInt();
    } else if (t == QVariant::LongLong) {
        return *this << v.toLongLong();
    } else if (t == QVariant::ULongLong) {
        return *this << v.toULongLong();
    } else if (t == QVariant::Bool) {
        return *this << v.toBool();
    } else if (t == QVariant::String) {
        return *this << v.toString();
    } else if (t == QVariant::List) {
        return *this << v.toList();
    } else if (t == QVariant::StringList) {
        return *this << v.toStringList();
    } else if (t == QVariant::Double) {
        return *this << v.toDouble();
    } else if (t == QVariant::ByteArray) {
        return *this << v.toByteArray();
    } else if (t == QVariant::Map) {
        return *this << v.toMap();
    } else if (t == QVariant::DateTime) {
        return *this << v.toDateTime();
    } else {
        if (v.canConvert<MsgPackExtData>()) {
            const MsgPackExtData &ext = v.value<MsgPackExtData>();
            return *this << ext;
        } else {
            d->status = WriteFailed;
            return *this;
        }
    }
}


bool MsgPackStream::writeBytes(const char *data, qint64 len)
{
    Q_D(MsgPackStream);
    return d->writeBytes(data, len);
}


bool MsgPackStream::writeExtHeader(quint32 len, quint8 msgpackType)
{
    Q_D(MsgPackStream);
    return d->writeExtHeader(len, msgpackType);
}


QTNETWORKNG_NAMESPACE_END
