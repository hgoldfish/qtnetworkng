#include <QtCore/qobject.h>
#include <QtCore/qpointer.h>
#include <QtCore/qstring.h>
#include <QtCore/qendian.h>
#include "./config.h"

QTNETWORKNG_NAMESPACE_BEGIN

namespace internal {
inline QByteArray int2bytes(qint64 i)
{
    QByteArray buf(sizeof(qint64), Qt::Uninitialized);
    qToLittleEndian<qint64>(i, buf.data());
    return buf;
}

inline qint64 bytes2int(const QByteArray &buf)
{
    Q_ASSERT(buf.size() == sizeof(qint64));
    return qFromLittleEndian<qint64>(buf.constData());
}
}  // namespace internal

class DatabasePrivate;
class Database;
class TransactionPrivate;
class Transaction;
class LmdbIteratorPrivate;
class LmdbIterator;
class ConstLmdbIterator;

class ConstLmdbIterator
{
public:
    typedef std::bidirectional_iterator_tag iterator_category;
    typedef qptrdiff difference_type;
    typedef QByteArray value_type;
    typedef const QByteArray *pointer;
    typedef const QByteArray &reference;
public:
    ~ConstLmdbIterator();
    inline ConstLmdbIterator(LmdbIterator &&other);
    inline ConstLmdbIterator(ConstLmdbIterator &&other)
        : d_ptr(other.d_ptr)
    {
        other.d_ptr = nullptr;
    }
public:
    QByteArray key() const;
    QByteArray value() const;
    bool isEnd() const;
public:
    inline qint64 intKey() const { return internal::bytes2int(key()); }
    inline const QString strKey() const { return QString::fromUtf8(key()); }
public:
    bool operator==(const ConstLmdbIterator &other) const;
    inline bool operator!=(const ConstLmdbIterator &other) const { return !(*this == other); }
    ConstLmdbIterator &operator++();
    ConstLmdbIterator &operator--();
private:
    inline ConstLmdbIterator(LmdbIteratorPrivate *d)
        : d_ptr(d)
    {
    }
    LmdbIteratorPrivate *d_ptr;
    friend class Database;
};

class LmdbIterator
{
public:
    typedef std::bidirectional_iterator_tag iterator_category;
    typedef qptrdiff difference_type;
    typedef QByteArray value_type;
    typedef const QByteArray *pointer;
    typedef const QByteArray &reference;
public:
    ~LmdbIterator();
    inline LmdbIterator(LmdbIterator &&other);
public:
    QByteArray key() const;
    QByteArray value() const;
    bool isEnd() const;
    void set(const QByteArray &value);
public:
    inline qint64 intKey() const { return internal::bytes2int(key()); }
    inline QString strKey() const { return QString::fromUtf8(key()); }
public:
    inline bool operator==(const ConstLmdbIterator &) const { return false; }
    inline bool operator!=(const ConstLmdbIterator &) const { return true; }
    bool operator==(const LmdbIterator &other) const;
    inline bool operator!=(const LmdbIterator &other) const { return !(*this == other); }
    LmdbIterator &operator++();
    LmdbIterator &operator--();
private:
    inline LmdbIterator(LmdbIteratorPrivate *d)
        : d_ptr(d)
    {
    }
    LmdbIteratorPrivate *d_ptr;
    friend class Database;
    friend class ConstLmdbIterator;
};

ConstLmdbIterator::ConstLmdbIterator(LmdbIterator &&other)
    : d_ptr(other.d_ptr)
{
    other.d_ptr = nullptr;
}

LmdbIterator::LmdbIterator(LmdbIterator &&other)
    : d_ptr(other.d_ptr)
{
    other.d_ptr = nullptr;
}

class Database
{
    Q_DISABLE_COPY_MOVE(Database);
public:
    typedef LmdbIterator iterator;
    typedef ConstLmdbIterator const_iterator;
    typedef QByteArray key_type;
    typedef QByteArray mapped_type;
    typedef qptrdiff difference_type;
    typedef qint64 size_type;
    ~Database();
public:
    inline QByteArray value(const QByteArray &key) const { return constFind(key).value(); }
    iterator insert(const QByteArray &key, const QByteArray &value);
    iterator reserve(const QByteArray &key, size_t size);
    qint64 insert(const Database &other);
    void clear();
    QList<QByteArray> keys() const;
    QStringList strKeys() const;
    QList<qint64> intKeys() const;
    int remove(const QByteArray &key);
    QByteArray take(const QByteArray &key);
    bool contains(const QByteArray &key) const;
    bool isNull() const;
    bool isEmpty() const;
    qint64 size() const;
public:
    iterator begin();
    const_iterator constBegin() const;
    iterator end();
    const_iterator constEnd() const;
    iterator erase(const QByteArray &key);
    iterator find(const QByteArray &key);
    const_iterator constFind(const QByteArray &key) const;
    const_iterator lowerBound(const QByteArray &key) const;
    iterator lowerBound(const QByteArray &key);
    const_iterator upperBound(const QByteArray &key) const;
    iterator upperBound(const QByteArray &key);
    inline QByteArray firstKey() const
    {
        Q_ASSERT(!isEmpty());
        return constBegin().key();
    }
    inline QByteArray firstValue() const
    {
        Q_ASSERT(!isEmpty());
        return constBegin().value();
    }
    inline QByteArray lastKey() const
    {
        Q_ASSERT(!isEmpty());
        return constEnd().key();
    }
    inline QByteArray lastValue() const
    {
        Q_ASSERT(!isEmpty());
        return constEnd().value();
    }
public:
    inline qint64 count() const { return size(); }
    inline QByteArray value(const QString &key) const { return value(key.toUtf8()); }
    inline QByteArray value(qint64 key) const { return value(internal::int2bytes(key)); }
    inline iterator insert(const QString &key, const QByteArray &value) { return insert(key.toUtf8(), value); }
    inline iterator insert(qint64 key, const QByteArray &value) { return insert(internal::int2bytes(key), value); }
    inline const_iterator begin() const { return constBegin(); }
    inline const_iterator cbegin() const { return constBegin(); }
    inline const_iterator end() const { return constEnd(); }
    inline const_iterator cend() const { return constEnd(); }
    inline bool contains(const QString &key) const { return contains(key.toUtf8()); }
    inline bool contains(qint64 key) const { return contains(internal::int2bytes(key)); }
    inline iterator erase(const QString &key) { return erase(key.toUtf8()); }
    inline iterator erase(qint64 key) { return erase(internal::int2bytes(key)); }
    inline iterator find(const QString &key) { return find(key.toUtf8()); }
    inline iterator find(qint64 key) { return find(internal::int2bytes(key)); }
    inline const_iterator find(const QByteArray &key) const { return constFind(key); }
    inline const_iterator find(const QString &key) const { return constFind(key.toUtf8()); }
    inline const_iterator find(qint64 key) const { return constFind(internal::int2bytes(key)); }
    inline const_iterator constFind(const QString &key) const { return constFind(key.toUtf8()); }
    inline const_iterator constFind(qint64 key) const { return constFind(internal::int2bytes(key)); }
    //    inline const_iterator lowBound(const QString &key) const { return lowBound(key.toUtf8()); }
    //    inline iterator lowBound(const QString &key)  { return lowBound(key.toUtf8()); }
    //    inline const_iterator lowBound(qint64 key) const { return lowBound(int2bytes(key)); }
    //    inline iterator lowBound(qint64 key)  { return lowBound(int2bytes(key)); }
    inline const_iterator upperBound(const QString &key) const { return upperBound(key.toUtf8()); }
    inline iterator upperBound(const QString &key) { return upperBound(key.toUtf8()); }
    inline const_iterator upperBound(qint64 key) const { return upperBound(internal::int2bytes(key)); }
    inline iterator upperBound(qint64 key) { return upperBound(internal::int2bytes(key)); }
    inline int remove(const QString &key) { return remove(key.toUtf8()); }
    inline int remove(qint64 key) { return remove(internal::int2bytes(key)); }
    inline QByteArray take(const QString &key) { return take(key.toUtf8()); }
    inline QByteArray take(qint64 key) { return take(internal::int2bytes(key)); }
    inline QByteArray operator[](const QByteArray &key) const { return value(key); }
    inline QByteArray operator[](const QString &key) const { return value(key.toUtf8()); }
    inline QByteArray operator[](int key) const { return value(internal::int2bytes(key)); }
private:
    Database(DatabasePrivate *d)
        : d_ptr(d)
    {
    }
    friend class DatabasePrivate;
    friend class LmdbIteratorPrivate;
    friend class TransactionPrivate;
private:
    DatabasePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Database);
};

class TransactionPrivate;
class Transaction
{
    Q_DISABLE_COPY_MOVE(Transaction);
public:
    ~Transaction();
public:
    const Database &db(const QString &name) const;
    Database &db(const QString &name);
    QSharedPointer<Transaction> sub();
    QSharedPointer<const Transaction> sub() const;
    bool commit();
    void abort();
private:
    Transaction(TransactionPrivate *d)
        : d_ptr(d)
    {
    }
    TransactionPrivate * const d_ptr;
    friend class TransactionPrivate;
    friend class Environment;
};

class EnvironmentPrivate;
class EnvironmentBuilder;
class Environment : public QObject
{
    Q_DISABLE_COPY_MOVE(Environment);
public:
    typedef EnvironmentBuilder Builder;
    ~Environment();
public:
    QSharedPointer<const Transaction> toRead();
    QSharedPointer<Transaction> toWrite();
    QString version() const;
    void sync(bool force = false);
    bool backupTo(const QString &dirPath);
private:
    Environment(EnvironmentPrivate *d)
        : dd_ptr(d)
    {
    }
    EnvironmentPrivate * const dd_ptr;
    Q_DECLARE_PRIVATE_D(dd_ptr, Environment);
    friend class EnvironmentBuilder;
};

class EnvironmentBuilder
{
    Q_DISABLE_COPY_MOVE(EnvironmentBuilder);
public:
    EnvironmentBuilder(const QString &dirPath);
    EnvironmentBuilder &maxMapSize(size_t size);
    EnvironmentBuilder &maxReaders(int readers);
    EnvironmentBuilder &maxDbs(int maxDbs);
    EnvironmentBuilder &dirPath(const QString &path);
    EnvironmentBuilder &noSync(bool noSync);
    QSharedPointer<Environment> create();
private:
    size_t m_maxMapSize = 1024 * 1024 * 16;
    int m_maxReaders = 256;
    int m_maxDbs = 1024;
    QString m_dirPath;
    bool m_noSync = false;
};

QTNETWORKNG_NAMESPACE_END
