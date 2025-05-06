#include <QtCore/qobject.h>
#include <QtCore/qpointer.h>
#include <QtCore/qstring.h>
#include <QtCore/qendian.h>
#include "./config.h"

QTNETWORKNG_NAMESPACE_BEGIN

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
    const char *data() const;
    size_t size() const;
public:
    inline const QString strKey() const { return QString::fromUtf8(key()); }
public:
    bool operator==(const ConstLmdbIterator &other) const;
    inline bool operator!=(const ConstLmdbIterator &other) const { return !(*this == other); }
    bool operator!() const { return isEnd(); }
    explicit operator bool() const { return !isEnd(); }
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
public:
    char *data() const;  // use this at your risk! you must known what you're doing.
    size_t size() const;
public:
    inline QString strKey() const { return QString::fromUtf8(key()); }
public:
    inline bool operator==(const ConstLmdbIterator &) const { return false; }
    inline bool operator!=(const ConstLmdbIterator &) const { return true; }
    bool operator==(const LmdbIterator &other) const;
    inline bool operator!=(const LmdbIterator &other) const { return !(*this == other); }
    bool operator!() const { return isEnd(); }
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
    iterator reserve(const QByteArray &key, size_t size); // insert value using itor.data() and itor.size()
    qint64 insert(const Database &other);
    void clear();
    QList<QByteArray> keys() const;
    QStringList strKeys() const;
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
    iterator erase(const iterator &itor);
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
    inline const_iterator begin() const { return constBegin(); }
    inline const_iterator cbegin() const { return constBegin(); }
    inline const_iterator end() const { return constEnd(); }
    inline const_iterator cend() const { return constEnd(); }
    inline const_iterator find(const QByteArray &key) const { return constFind(key); }
    inline QByteArray operator[](const QByteArray &key) const { return value(key); }
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
    Q_DECLARE_PRIVATE(Database)
private:
    Q_DISABLE_COPY(Database)
    Database(Database &&) = delete;
    Database &operator=(Database &&) = delete;
};

class TransactionPrivate;
class Transaction
{
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
    friend class Lmdb;
private:
    Q_DISABLE_COPY(Transaction)
    Transaction(Transaction &&) = delete;
    Transaction &operator=(Transaction &&) = delete;
};

class LmdbPrivate;
class LmdbBuilder;
class Lmdb
{
public:
    typedef LmdbBuilder Builder;
    ~Lmdb();
public:
    QSharedPointer<const Transaction> toRead();
    QSharedPointer<Transaction> toWrite();
    QString version() const;
    void sync(bool force = false);
    bool backupTo(const QString &dirPath);
private:
    Lmdb(LmdbPrivate *d)
        : d_ptr(d)
    {
    }
    LmdbPrivate * const d_ptr;
    Q_DECLARE_PRIVATE_D(d_ptr, Lmdb)
    friend class LmdbBuilder;
private:
    Q_DISABLE_COPY(Lmdb)
    Lmdb(Lmdb &&) = delete;
    Lmdb &operator=(Lmdb &&) = delete;
};

class LmdbBuilder
{
public:
    LmdbBuilder(const QString &dirPath);
    LmdbBuilder &maxMapSize(size_t size);
    LmdbBuilder &maxReaders(int readers);
    LmdbBuilder &maxDbs(int maxDbs);
    LmdbBuilder &noSync(bool noSync);
    LmdbBuilder &noSubDir(bool noSubDir);
    LmdbBuilder &writeMap(bool writable);
    QSharedPointer<Lmdb> create();
private:
    size_t m_maxMapSize = 1024 * 1024 * 16;
    int m_maxReaders = 256;
    int m_maxDbs = 1024;
    QString m_dirPath;
    bool m_noSync = false;
    bool m_writeMap = false;
    bool m_noSubDir = true;
private:
    Q_DISABLE_COPY(LmdbBuilder)
    LmdbBuilder(LmdbBuilder &&) = delete;
    LmdbBuilder &operator=(LmdbBuilder &&) = delete;
};

QTNETWORKNG_NAMESPACE_END
