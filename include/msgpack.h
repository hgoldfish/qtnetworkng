#ifndef QTNG_MSGPACK_H
#define QTNG_MSGPACK_H

#include <limits>
#include <type_traits>
#include <QtCore/qvariant.h>
#include <QtCore/qiodevice.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qendian.h>
#include "config.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct MsgPackExtData
{
    quint8 type;
    QByteArray payload;
};

class MsgPackExtUserData
{
public:
    virtual ~MsgPackExtUserData();
};

class MsgPackStreamPrivate;
class MsgPackStream
{
public:
    MsgPackStream();
    MsgPackStream(QIODevice *d);
    MsgPackStream(QByteArray *a, QIODevice::OpenMode mode);
    MsgPackStream(const QByteArray &a);
    virtual ~MsgPackStream();

    void setDevice(QIODevice *d);
    QIODevice *device() const;
    QByteArray data() const;
    bool atEnd() const;

    enum Status { Ok, ReadPastEnd, ReadCorruptData, WriteFailed };
    Status status() const;
    inline bool isOk() const { return status() == Ok; }
    void resetStatus();
    void setStatus(Status status);
    void setFlushWrites(bool flushWrites);
    bool willFlushWrites();
    void setLengthLimit(quint32 limit);
    quint32 lengthLimit() const;
    void setVersion(int version);
    int version() const;
    void setUserData(intptr_t key, MsgPackExtUserData *userData);  // take the ownership
    template<typename T>
    T *userData(intptr_t key) const
    {
        return dynamic_cast<T *>(getUserData(key));
    }

    MsgPackStream &operator>>(bool &b);
    MsgPackStream &operator>>(quint8 &u8);
    MsgPackStream &operator>>(quint16 &u16);
    MsgPackStream &operator>>(quint32 &u32);
    MsgPackStream &operator>>(quint64 &u64);
    MsgPackStream &operator>>(qint8 &i8);
    MsgPackStream &operator>>(qint16 &i16);
    MsgPackStream &operator>>(qint32 &i32);
    MsgPackStream &operator>>(qint64 &i64);
    MsgPackStream &operator>>(float &f);
    MsgPackStream &operator>>(double &d);
    MsgPackStream &operator>>(QString &str);
    MsgPackStream &operator>>(QByteArray &array);
    MsgPackStream &operator>>(QDateTime &dt);
    MsgPackStream &operator>>(MsgPackExtData &ext);
    MsgPackStream &operator>>(QVariant &v);
    bool readBytes(char *data, qint64 len);
    bool readArrayHeader(quint32 &len);
    bool readMapHeader(quint32 &len);
    bool readExtHeader(quint32 &len, quint8 msgpackType);

    MsgPackStream &operator<<(bool b);
    MsgPackStream &operator<<(quint8 u8);
    MsgPackStream &operator<<(quint16 u16);
    MsgPackStream &operator<<(quint32 u32);
    MsgPackStream &operator<<(quint64 u64);
    MsgPackStream &operator<<(qint8 i8);
    MsgPackStream &operator<<(qint16 i16);
    MsgPackStream &operator<<(qint32 i32);
    MsgPackStream &operator<<(qint64 i64);
    MsgPackStream &operator<<(float f);
    MsgPackStream &operator<<(double d);
    MsgPackStream &operator<<(const QString &str);
    MsgPackStream &operator<<(const QByteArray &array);
    MsgPackStream &operator<<(const QDateTime &dt);
    MsgPackStream &operator<<(const MsgPackExtData &ext);
    MsgPackStream &operator<<(const QVariant &v);

    bool writeBytes(const char *data, qint64 len);
    bool writeString(const char *data, quint32 len);
    bool writeArrayHeader(quint32 len);
    bool writeMapHeader(quint32 len);
    bool writeExtHeader(quint32 len, quint8 msgpackType);
private:
    MsgPackExtUserData *getUserData(intptr_t key) const;
private:
    MsgPackStreamPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(MsgPackStream)
    Q_DISABLE_COPY(MsgPackStream);
};

/**
 * @brief The FirstByte enum
 * From Message Pack spec
 */
namespace FirstByte {
const quint8 POSITIVE_FIXINT = 0x7f;
const quint8 FIXMAP = 0x80;
const quint8 FIXARRAY = 0x90;
const quint8 FIXSTR = 0xa0;
const quint8 NIL = 0xc0;
const quint8 NEVER_USED = 0xc1;
const quint8 MFALSE = 0xc2;
const quint8 MTRUE = 0xc3;
const quint8 BIN8 = 0xc4;
const quint8 BIN16 = 0xc5;
const quint8 BIN32 = 0xc6;
const quint8 EXT8 = 0xc7;
const quint8 EXT16 = 0xc8;
const quint8 EXT32 = 0xc9;
const quint8 FLOAT32 = 0xca;
const quint8 FLOAT64 = 0xcb;
const quint8 UINT8 = 0xcc;
const quint8 UINT16 = 0xcd;
const quint8 UINT32 = 0xce;
const quint8 UINT64 = 0xcf;
const quint8 INT8 = 0xd0;
const quint8 INT16 = 0xd1;
const quint8 INT32 = 0xd2;
const quint8 INT64 = 0xd3;
const quint8 FIXEXT1 = 0xd4;
const quint8 FIXEXT2 = 0xd5;
const quint8 FIXEXT4 = 0xd6;
const quint8 FIXEXT8 = 0xd7;
const quint8 FIXEX16 = 0xd8;
const quint8 STR8 = 0xd9;
const quint8 STR16 = 0xda;
const quint8 STR32 = 0xdb;
const quint8 ARRAY16 = 0xdc;
const quint8 ARRAY32 = 0xdd;
const quint8 MAP16 = 0xde;
const quint8 MAP32 = 0xdf;
const quint8 NEGATIVE_FIXINT = 0xe0;
}  // namespace FirstByte

#if QT_VERSION >= QT_VERSION_CHECK(5, 7, 0)
inline void _msgpack_store16(quint8 *p, quint16 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline void _msgpack_store16(quint8 *p, qint16 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline void _msgpack_store32(quint8 *p, quint32 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline void _msgpack_store32(quint8 *p, qint32 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline void _msgpack_store64(quint8 *p, quint64 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline void _msgpack_store64(quint8 *p, qint64 i)
{
    qToBigEndian(i, static_cast<void *>(p));
}
inline quint16 _msgpack_load16(quint8 *p)
{
    return qFromBigEndian<quint16>(static_cast<const void *>(p));
}
inline quint32 _msgpack_load32(quint8 *p)
{
    return qFromBigEndian<quint32>(static_cast<const void *>(p));
}
inline quint64 _msgpack_load64(quint8 *p)
{
    return qFromBigEndian<quint64>(static_cast<const void *>(p));
}
#else
inline void _msgpack_store16(quint8 *p, quint16 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline void _msgpack_store16(quint8 *p, qint16 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline void _msgpack_store32(quint8 *p, quint32 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline void _msgpack_store32(quint8 *p, qint32 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline void _msgpack_store64(quint8 *p, quint64 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline void _msgpack_store64(quint8 *p, qint64 i)
{
    qToBigEndian(i, static_cast<uchar *>(p));
}
inline quint16 _msgpack_load16(quint8 *p)
{
    return qFromBigEndian<quint16>(static_cast<const uchar *>(p));
}
inline quint32 _msgpack_load32(quint8 *p)
{
    return qFromBigEndian<quint32>(static_cast<const uchar *>(p));
}
inline quint64 _msgpack_load64(quint8 *p)
{
    return qFromBigEndian<quint64>(static_cast<const uchar *>(p));
}
#endif

inline void _msgpack_store8(quint8 *p, quint8 i)
{
    *p = i;
}

inline void _msgpack_store8(quint8 *p, qint8 i)
{
    *p = static_cast<quint8>(static_cast<qint32>(i));
}

inline quint8 _msgpack_load8(quint8 *p)
{
    return *p;
}

template<typename T>
MsgPackStream &operator<<(MsgPackStream &s, const QList<T> &list)
{
    if (!s.writeArrayHeader(list.size())) {
        return s;
    }
    for (int i = 0; i < list.size(); ++i) {
        s << list[i];
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
    }
    return s;
}

template<typename T>
MsgPackStream &operator<<(MsgPackStream &s, const QSet<T> &set)
{
    if (!s.writeArrayHeader(set.size())) {
        return s;
    }
    for (typename QSet<T>::const_iterator it = set.constBegin(); it != set.constEnd(); ++it) {
        s << *it;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
    }
    return s;
}

template<typename T>
MsgPackStream &operator<<(MsgPackStream &s, const QVector<T> &list)
{
    if (!s.writeArrayHeader(list.size())) {
        return s;
    }
    for (int i = 0; i < list.size(); ++i) {
        s << list[i];
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
    }
    return s;
}

template<typename K, typename V>
MsgPackStream &operator<<(MsgPackStream &s, const QMap<K, V> &map)
{
    if (!s.writeMapHeader(map.size())) {
        return s;
    }
    QMapIterator<K, V> itor(map);
    while (itor.hasNext()) {
        itor.next();
        s << itor.key();
        s << itor.value();
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
    }
    return s;
}

template<typename K, typename V>
MsgPackStream &operator<<(MsgPackStream &s, const QHash<K, V> &map)
{
    if (!s.writeMapHeader(map.size())) {
        return s;
    }
    QHashIterator<K, V> itor(map);
    while (itor.hasNext()) {
        itor.next();
        s << itor.key();
        s << itor.value();
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
    }
    return s;
}

template<typename>
struct is_qt_pointer
{
    static constexpr bool value = false;
};

template<typename Tp>
struct is_qt_pointer<QSharedPointer<Tp>>
{
    static constexpr bool value = true;
};

template<typename T>
inline typename std::enable_if<!is_qt_pointer<T>::value, T>::type s_allocate()
{
    return T();
}

template<typename T>
inline typename std::enable_if<is_qt_pointer<T>::value, T>::type s_allocate()
{
    return T::create();
}

template<typename T>
MsgPackStream &operator>>(MsgPackStream &s, QList<T> &list)
{
    quint32 len = 0;
    if (!s.readArrayHeader(len)) {
        return s;
    }
    list.clear();
    list.reserve(len);
    for (quint32 i = 0; i < len; ++i) {
        T t = s_allocate<T>();
        s >> t;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        list.append(t);
        if (s.atEnd())
            break;
    }
    return s;
}

template<typename T>
MsgPackStream &operator>>(MsgPackStream &s, QSet<T> &set)
{
    quint32 len = 0;
    if (!s.readArrayHeader(len)) {
        return s;
    }
    set.clear();
    set.reserve(len);
    for (quint32 i = 0; i < len; ++i) {
        T t = s_allocate<T>();
        s >> t;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        set.insert(t);
        if (s.atEnd())
            break;
    }
    return s;
}

template<typename T>
MsgPackStream &operator>>(MsgPackStream &s, QVector<T> &list)
{
    quint32 len = 0;
    if (!s.readArrayHeader(len)) {
        return s;
    }
    list.clear();
    list.reserve(len);
    for (quint32 i = 0; i < len; ++i) {
        T t = s_allocate<T>();
        s >> t;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        list.append(t);
        if (s.atEnd()) {
            break;
        }
    }
    return s;
}

template<typename K, typename V>
MsgPackStream &operator>>(MsgPackStream &s, QMap<K, V> &map)
{
    quint32 len = 0;
    if (!s.readMapHeader(len)) {
        return s;
    }
    map.clear();
    for (quint32 i = 0; i < len; ++i) {
        K k = s_allocate<K>();
        s >> k;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        V v = s_allocate<V>();
        s >> v;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        map.insert(k, v);
    }
    return s;
}

template<typename K, typename V>
MsgPackStream &operator>>(MsgPackStream &s, QHash<K, V> &map)
{
    quint32 len = 0;
    if (!s.readMapHeader(len)) {
        return s;
    }
    map.clear();
    map.reserve(len);
    for (quint32 i = 0; i < len; ++i) {
        K k = s_allocate<K>();
        s >> k;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        V v = s_allocate<V>();
        s >> v;
        if (s.status() != MsgPackStream::Ok) {
            break;
        }
        map.insert(k, v);
    }
    return s;
}

QTNETWORKNG_NAMESPACE_END

Q_DECLARE_METATYPE(QTNETWORKNG_NAMESPACE::MsgPackExtData)

#endif  // STREAM_H
