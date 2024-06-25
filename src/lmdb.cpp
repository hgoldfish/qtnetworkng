#include <QtCore/qloggingcategory.h>
#include "../include/config.h"
#include "../include/lmdb.h"
#include "./liblmdb/lmdb.h"
#include "./debugger.h"

QTNETWORKNG_NAMESPACE_BEGIN

#define QTLMDB_DEBUG 1

QTNG_LOGGER("qtng.lmdb")

class LmdbIteratorPrivate
{
public:
    LmdbIteratorPrivate(QByteArray key, MDB_cursor *cursor, MDB_val mdbValue)
        : key(key)
        , cursor(cursor)
        , mdbValue(mdbValue)
    {
    }
public:
    void load(MDB_cursor_op op);
public:
    QByteArray key;
    MDB_cursor *cursor;
    MDB_val mdbValue;
};

class DatabasePrivate
{
public:
    DatabasePrivate(MDB_txn *txn, MDB_dbi dbi, bool readOnly)
        : txn(txn)
        , dbi(dbi)
        , readOnly(readOnly)
    {
    }
public:
    MDB_cursor *makeCursor();
    MDB_cursor *setCursor(const QByteArray &key, MDB_val &mdbKey, MDB_val &mdbData, MDB_cursor_op op = MDB_SET);
    LmdbIteratorPrivate *end(MDB_cursor *cursor = nullptr);
public:
    MDB_txn * const txn;
    MDB_dbi dbi;
    bool readOnly;
};

class TransactionPrivate
{
public:
    TransactionPrivate(MDB_env *env, MDB_txn *txn, bool readOnly)
        : env(env)
        , txn(txn)
        , finished(false)
        , readOnly(readOnly)
    {
    }
public:
    Database &open(const QString &name);
public:
    QMap<QString, QSharedPointer<Database>> dbs;
    MDB_env * const env;
    MDB_txn * const txn;
    bool finished;
    bool readOnly;
};

class LmdbPrivate
{
public:
    MDB_env *env;
};

void LmdbIteratorPrivate::load(MDB_cursor_op op)
{
    Q_ASSERT(cursor);
    MDB_val mdbKey;
    memset(&mdbKey, 0, sizeof(MDB_val));
    int rt = mdb_cursor_get(cursor, &mdbKey, &mdbValue, op);
    if (rt) {
#if QTLMDB_DEBUG
        if (rt != MDB_NOTFOUND || (op != MDB_NEXT && op != MDB_PREV && op != MDB_SET && op != MDB_SET_KEY)) {
            qCInfo(qtng_logger) << "can not open lmdb cursor:" << mdb_strerror(rt);
        }
#endif
        key.clear();
    } else {
        key = QByteArray(static_cast<const char *>(mdbKey.mv_data), mdbKey.mv_size);
    }
}

MDB_cursor *DatabasePrivate::makeCursor()
{
    MDB_cursor *cursor;
    int rt = mdb_cursor_open(txn, dbi, &cursor);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not open lmdb cursor:" << mdb_strerror(rt);
#endif
        return nullptr;
    }
    return cursor;
}

MDB_cursor *DatabasePrivate::setCursor(const QByteArray &key, MDB_val &mdbKey, MDB_val &mdbData, MDB_cursor_op op)
{
    MDB_cursor *cursor = makeCursor();
    if (!cursor) {
        return nullptr;
    }

    QVarLengthArray<char, 1024> keyBuf;
    keyBuf.append(key.constData(), key.size());

    mdbKey.mv_size = keyBuf.size();
    mdbKey.mv_data = keyBuf.data();
    memset(&mdbData, 0, sizeof(MDB_val));

    int rt = mdb_cursor_get(cursor, &mdbKey, &mdbData, op);
    if (rt) {
        mdb_cursor_close(cursor);
        if (rt != MDB_NOTFOUND) {
#if QTLMDB_DEBUG
            qtng_warning << "can not iterate lmdb cursor:" << mdb_strerror(rt);
#endif
        }
        return nullptr;
    }
    return cursor;
}

ConstLmdbIterator::~ConstLmdbIterator()
{
    if (!d_ptr) {
        return;
    }
    mdb_cursor_close(d_ptr->cursor);
    delete d_ptr;
}

QByteArray ConstLmdbIterator::key() const
{
    if (isEnd()) {
        return QByteArray();
    }
    return d_ptr->key;
}

QByteArray ConstLmdbIterator::value() const
{
    if (isEnd()) {
        return QByteArray();
    }
    return QByteArray(static_cast<const char *>(d_ptr->mdbValue.mv_data), d_ptr->mdbValue.mv_size);
}

const char *ConstLmdbIterator::data() const
{
    if (isEnd()) {
        return nullptr;
    }
    return static_cast<const char *>(d_ptr->mdbValue.mv_data);
}

size_t ConstLmdbIterator::size() const
{
    if (isEnd()) {
        return 0;
    }
    return d_ptr->mdbValue.mv_size;
}

bool ConstLmdbIterator::isEnd() const
{
    return !d_ptr || d_ptr->key.isEmpty();
}

bool ConstLmdbIterator::operator==(const ConstLmdbIterator &other) const
{
    if (isEnd()) {
        return other.isEnd();
    }
    if (other.isEnd()) {
        return false;
    }
    if (d_ptr->cursor != other.d_ptr->cursor) {
        return false;
    }
    return d_ptr->key == other.d_ptr->key;
}

ConstLmdbIterator &ConstLmdbIterator::operator++()
{
    if (isEnd()) {
        return *this;
    }
    d_ptr->load(MDB_NEXT);
    return *this;
}

ConstLmdbIterator &ConstLmdbIterator::operator--()
{
    if (!d_ptr->cursor) {
        return *this;
    }
    d_ptr->load(MDB_PREV);
    return *this;
}

LmdbIterator::~LmdbIterator()
{
    if (!d_ptr) {
        return;
    }
    mdb_cursor_close(d_ptr->cursor);
    delete d_ptr;
}

QByteArray LmdbIterator::key() const
{
    if (isEnd()) {
        return QByteArray();
    }
    return d_ptr->key;
}

QByteArray LmdbIterator::value() const
{
    if (isEnd()) {
        return QByteArray();
    }
    return QByteArray(static_cast<const char *>(d_ptr->mdbValue.mv_data), d_ptr->mdbValue.mv_size);
}

bool LmdbIterator::isEnd() const
{
    return !d_ptr || d_ptr->key.isEmpty();
}

char *LmdbIterator::data() const
{
    if (isEnd()) {
        return nullptr;
    }
    return static_cast<char *>(d_ptr->mdbValue.mv_data);
}

size_t LmdbIterator::size() const
{
    if (isEnd()) {
        return 0;
    }
    return d_ptr->mdbValue.mv_size;
}

bool LmdbIterator::operator==(const LmdbIterator &other) const
{
    if (isEnd()) {
        return other.isEnd();
    }
    if (other.isEnd()) {
        return false;
    }
    if (d_ptr->cursor != other.d_ptr->cursor) {
        return false;
    }
    return d_ptr->key == other.d_ptr->key;
}

LmdbIterator &LmdbIterator::operator++()
{
    if (isEnd()) {
        return *this;
    }
    d_ptr->load(MDB_NEXT);
    return *this;
}

LmdbIterator &LmdbIterator::operator--()
{
    if (!d_ptr->cursor) {
        return *this;
    }
    d_ptr->load(MDB_PREV);
    return *this;
}

Database::~Database()
{
    delete d_ptr;
}

Database::iterator Database::insert(const QByteArray &key, const QByteArray &value)
{
    Database::iterator itor = reserve(key, value.size());

    if (itor.isEnd()) {
        return itor;
    }
    if (itor.d_ptr->mdbValue.mv_size == 0) {
        return end();
    }
    if (static_cast<size_t>(value.size()) != itor.d_ptr->mdbValue.mv_size) {
        qtng_warning << "setting value is too large for lmdb reserved key-value.";
    }
    size_t minSize = qMin(static_cast<size_t>(value.size()), itor.d_ptr->mdbValue.mv_size);
    memcpy(itor.d_ptr->mdbValue.mv_data, value.constData(), minSize);
    return itor;
}

Database::iterator Database::reserve(const QByteArray &key, size_t size)
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    QVarLengthArray<char, 1024> keyBuf;
    keyBuf.append(key.constData(), key.size());

    MDB_val mdbKey, mdbData;
    mdbKey.mv_size = keyBuf.size();
    mdbKey.mv_data = keyBuf.data();
    mdbData.mv_size = size;
    mdbData.mv_data = NULL;

    unsigned flags = MDB_RESERVE;
    mdb_cursor_put(cursor, &mdbKey, &mdbData, flags);

    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(key, cursor, mdbData);
    return LmdbIterator(d);
}

qint64 Database::insert(const Database &other)
{
    if (isNull() || d_ptr->readOnly) {
        return -1;
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return -1;
    }

    qint64 count = 0;
    for (const_iterator itor = other.begin(); itor != other.end(); ++itor) {
        QByteArray &key = itor.d_ptr->key;

        MDB_val mdbKey;
        mdbKey.mv_size = key.size();
        mdbKey.mv_data = key.data();

        int rt = mdb_cursor_put(cursor, &mdbKey, &itor.d_ptr->mdbValue, 0);
        if (rt) {
#if QTLMDB_DEBUG
            qtng_warning << "can not put lmdb value:" << mdb_strerror(rt);
#endif
            mdb_cursor_close(cursor);
            return -1;
        }
        ++count;
    }
    mdb_cursor_close(cursor);
    return count;
}

void Database::clear()
{
    if (isNull() || d_ptr->readOnly) {
        return;
    }

    int rt = mdb_drop(d_ptr->txn, d_ptr->dbi, 0);
    if (rt < 0) {
#if QTLMDB_DEBUG
        qtng_warning << "can not clear lmdb database:" << mdb_strerror(rt);
#endif
    }
}

QList<QByteArray> Database::keys() const
{
    if (isNull()) {
        return QList<QByteArray>();
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return QList<QByteArray>();
    }

    MDB_val key, data;
    memset(&key, 0, sizeof(MDB_val));
    memset(&data, 0, sizeof(MDB_val));

    QList<QByteArray> ks;
    int rt;
    while ((rt = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        ks.append(QByteArray(static_cast<const char *>(key.mv_data), key.mv_size));
    }

    mdb_cursor_close(cursor);

    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not iterate lmdb cursor:" << mdb_strerror(rt);
#endif
        // if iterator was failed, we return the loaded keys anyway.
        // return QList<QByteArray>();
    }
    return ks;
}

QStringList Database::strKeys() const
{
    if (isNull()) {
        return QStringList();
    }
    QList<QByteArray> ks = keys();
    QStringList sl;
    sl.reserve(ks.size());
    for (const QByteArray &key : ks) {
        sl.append(QString::fromUtf8(key));
    }
    return sl;
}

int Database::remove(const QByteArray &key)
{
    if (isNull() || d_ptr->readOnly) {
        return -1;
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData);
    if (!cursor) {
        return -1;
    }

    int rt = mdb_cursor_del(cursor, 0);
    mdb_cursor_close(cursor);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not delete lmdb cursor:" << mdb_strerror(rt);
#endif
        return -1;
    }
    return 1;
}

Database::iterator Database::erase(const QByteArray &key)
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData);
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    int rt = mdb_cursor_del(cursor, 0);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not delete lmdb cursor:" << mdb_strerror(rt) << key;
#endif
        mdb_cursor_close(cursor);
        return LmdbIterator(nullptr);
    }

    rt = mdb_cursor_get(cursor, &mdbKey, &mdbData, MDB_NEXT);

    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not next lmdb cursor:" << mdb_strerror(rt);
#endif
        mdb_cursor_close(cursor);
        return LmdbIterator(nullptr);
    }

    QByteArray newKey(static_cast<const char *>(mdbKey.mv_data), mdbKey.mv_size);
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(newKey, cursor, mdbData);
    return LmdbIterator(d);
}

QByteArray Database::take(const QByteArray &key)
{
    if (isNull() || d_ptr->readOnly) {
        return QByteArray();
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData);
    if (!cursor) {
        return QByteArray();
    }

    const QByteArray &value = QByteArray(static_cast<const char *>(mdbData.mv_data), mdbData.mv_size);

    int rt = mdb_cursor_del(cursor, 0);
    mdb_cursor_close(cursor);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not delete lmdb cursor:" << mdb_strerror(rt);
#endif
        return QByteArray();
    }
    return value;
}

bool Database::contains(const QByteArray &key) const
{
    if (isNull()) {
        return false;
    }
    return find(key) != end();
}

bool Database::isNull() const
{
    return d_ptr == nullptr;
}

bool Database::isEmpty() const
{
    return d_ptr == nullptr || size() <= 0;
}

qint64 Database::size() const
{
    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return -1;
    }

    mdb_size_t count;
    int rt = mdb_cursor_count(cursor, &count);
    mdb_cursor_close(cursor);

    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not count lmdb cursor:" << mdb_strerror(rt);
#endif
        return -1;
    }
    return count;
}

Database::iterator Database::begin()
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    MDB_val mdbData;
    memset(&mdbData, 0, sizeof(MDB_val));
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(QByteArray(), cursor, mdbData);
    d->load(MDB_FIRST);
    return d;
}

Database::const_iterator Database::constBegin() const
{
    if (isNull()) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_val mdbData;
    memset(&mdbData, 0, sizeof(MDB_val));
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(QByteArray(), cursor, mdbData);
    d->load(MDB_FIRST);
    return d;
}

Database::iterator Database::end()
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    MDB_val mdbData;
    memset(&mdbData, 0, sizeof(MDB_val));
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(QByteArray(), cursor, mdbData);
    return LmdbIterator(d);
}

Database::const_iterator Database::constEnd() const
{
    if (isNull()) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_cursor *cursor = d_ptr->makeCursor();
    if (!cursor) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_val mdbData;
    memset(&mdbData, 0, sizeof(MDB_val));
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(QByteArray(), cursor, mdbData);
    return ConstLmdbIterator(d);
}

Database::iterator Database::find(const QByteArray &key)
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData, MDB_SET);
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(key, cursor, mdbData);
    return LmdbIterator(d);
}

Database::const_iterator Database::constFind(const QByteArray &key) const
{
    if (isNull()) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData, MDB_SET);
    if (!cursor) {
        return ConstLmdbIterator(nullptr);
    }

    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(key, cursor, mdbData);
    return ConstLmdbIterator(d);
}

Database::const_iterator Database::lowerBound(const QByteArray &key) const
{
    if (isNull()) {
        return ConstLmdbIterator(nullptr);
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData, MDB_SET_RANGE);
    if (!cursor) {
        return ConstLmdbIterator(nullptr);
    }

    QByteArray newKey(static_cast<const char *>(mdbKey.mv_data), mdbKey.mv_size);
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(newKey, cursor, mdbData);
    return ConstLmdbIterator(d);
}

Database::iterator Database::lowerBound(const QByteArray &key)
{
    if (isNull() || d_ptr->readOnly) {
        return LmdbIterator(nullptr);
    }

    MDB_val mdbKey, mdbData;
    MDB_cursor *cursor = d_ptr->setCursor(key, mdbKey, mdbData, MDB_SET_RANGE);
    if (!cursor) {
        return LmdbIterator(nullptr);
    }

    QByteArray newKey(static_cast<const char *>(mdbKey.mv_data), mdbKey.mv_size);
    LmdbIteratorPrivate *d = new LmdbIteratorPrivate(newKey, cursor, mdbData);
    return LmdbIterator(d);
}

Database::const_iterator Database::upperBound(const QByteArray &key) const
{
    Database::const_iterator itor = lowerBound(key);
    if (itor.key() == key) {
        ++itor;
    }
    return itor;
}

Database::iterator Database::upperBound(const QByteArray &key)
{
    Database::iterator itor = lowerBound(key);
    if (itor.key() == key) {
        ++itor;
    }
    return itor;
}

Database &TransactionPrivate::open(const QString &name)
{
    static Database empty(nullptr);

    if (finished) {
        if (readOnly) {
            mdb_txn_renew(txn);
            finished = false;
        } else {
            return empty;
        }
    }

    QMap<QString, QSharedPointer<Database>>::const_iterator itor = dbs.constFind(name);
    if (itor != dbs.constEnd()) {
        return *itor.value();
    }

    MDB_dbi dbi;
    unsigned int flags = readOnly ? 0 : MDB_CREATE;
    int rt = mdb_dbi_open(txn, name.toUtf8(), flags, &dbi);
    if (rt < 0) {
        return empty;
    }
    QScopedPointer<DatabasePrivate> d(new DatabasePrivate(txn, dbi, readOnly));
    QSharedPointer<Database> db(new Database(d.take()));
    dbs.insert(name, db);
    return *db;
}

Transaction::~Transaction()
{
    if (!d_ptr->finished) {
#if QTLMDB_DEBUG
        if (!d_ptr->readOnly) {
            qtng_warning << "lmdb transaction is not finished.";
        }
#endif
        commit();
    }
    delete d_ptr;
}

const Database &Transaction::db(const QString &name) const
{
    return d_ptr->open(name);
}

Database &Transaction::db(const QString &name)
{
    return d_ptr->open(name);
}

QSharedPointer<Transaction> Transaction::sub()
{
    MDB_txn *txn;
    unsigned int flags = 0;
    int rt = mdb_txn_begin(d_ptr->env, d_ptr->txn, flags, &txn);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not begin lmdb transaction:" << mdb_strerror(rt);
#endif
        return QSharedPointer<Transaction>();
    }
    TransactionPrivate *d = new TransactionPrivate(d_ptr->env, txn, false);
    return QSharedPointer<Transaction>(new Transaction(d));
}

QSharedPointer<const Transaction> Transaction::sub() const
{
    MDB_txn *txn;
    unsigned int flags = MDB_RDONLY;
    int rt = mdb_txn_begin(d_ptr->env, d_ptr->txn, flags, &txn);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not begin lmdb transaction:" << mdb_strerror(rt);
#endif
        return QSharedPointer<const Transaction>();
    }
    TransactionPrivate *d = new TransactionPrivate(d_ptr->env, txn, true);
    return QSharedPointer<Transaction>(new Transaction(d));
}

bool Transaction::commit()
{
    int rt = mdb_txn_commit(d_ptr->txn);
    d_ptr->dbs.clear();
    d_ptr->finished = true;
    if (rt < 0) {
#if QTLMDB_DEBUG
        qtng_warning << "can not commit lmdb transaction:" << mdb_strerror(rt);
#endif
        return false;
    }
    return true;
}

void Transaction::abort()
{
    mdb_txn_abort(d_ptr->txn);
    d_ptr->dbs.clear();
    d_ptr->finished = true;
}

Lmdb::~Lmdb()
{
    mdb_env_close(d_ptr->env);
    delete d_ptr;
}

QSharedPointer<const Transaction> Lmdb::toRead()
{
    MDB_txn *txn;
    unsigned int flags = MDB_RDONLY;
    int rt = mdb_txn_begin(d_ptr->env, NULL, flags, &txn);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not begin lmdb transaction:" << mdb_strerror(rt);
#endif
        return QSharedPointer<const Transaction>();
    }
    TransactionPrivate *d = new TransactionPrivate(d_ptr->env, txn, true);
    return QSharedPointer<const Transaction>(new Transaction(d));
}

QSharedPointer<Transaction> Lmdb::toWrite()
{
    MDB_txn *txn;
    unsigned int flags = 0;
    int rt = mdb_txn_begin(d_ptr->env, NULL, flags, &txn);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not begin lmdb transaction:" << mdb_strerror(rt);
#endif
        return QSharedPointer<Transaction>();
    }
    TransactionPrivate *d = new TransactionPrivate(d_ptr->env, txn, false);
    return QSharedPointer<Transaction>(new Transaction(d));
}

QString Lmdb::version() const
{
    char *s = mdb_version(NULL, NULL, NULL);
    return QString::fromLatin1(s);
}

void Lmdb::sync(bool force)
{
    int rt = mdb_env_sync(d_ptr->env, force);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not sync lmdb env:" << mdb_strerror(rt);
#endif
    }
}

bool Lmdb::backupTo(const QString &dirPath)
{
    unsigned int flags = 0;
    int rt = mdb_env_copy2(d_ptr->env, dirPath.toUtf8(), flags);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not backup lmdb env:" << mdb_strerror(rt);
#endif
        return false;
    }
    return true;
}

LmdbBuilder::LmdbBuilder(const QString &dirPath)
    : m_dirPath(dirPath)
{
}

LmdbBuilder &LmdbBuilder::maxMapSize(size_t size)
{
    m_maxMapSize = size;
    return *this;
}

LmdbBuilder &LmdbBuilder::maxReaders(int readers)
{
    m_maxReaders = readers;
    return *this;
}

LmdbBuilder &LmdbBuilder::maxDbs(int maxDbs)
{
    m_maxDbs = maxDbs;
    return *this;
}

LmdbBuilder &LmdbBuilder::noSync(bool noSync)
{
    m_noSync = noSync;
    return *this;
}

QSharedPointer<Lmdb> LmdbBuilder::create()
{
    Q_ASSERT(!m_dirPath.isEmpty());
    QScopedPointer<LmdbPrivate> d(new LmdbPrivate());
    int rt = mdb_env_create(&d->env);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not create lmdb env:" << mdb_strerror(rt);
        return QSharedPointer<Lmdb>();
#endif
    }
    mdb_env_set_mapsize(d->env, m_maxMapSize);
    mdb_env_set_maxdbs(d->env, m_maxDbs);
    mdb_env_set_maxreaders(d->env, m_maxReaders);

    unsigned int flags = MDB_NOSUBDIR | MDB_NOTLS;
    if (m_noSync) {
        flags |= MDB_NOSYNC | MDB_MAPASYNC;
    }
    mdb_mode_t mode = 0660;
    rt = mdb_env_open(d->env, m_dirPath.toUtf8(), flags, mode);
    if (rt) {
#if QTLMDB_DEBUG
        qtng_warning << "can not open lmdb env:" << mdb_strerror(rt);
        return QSharedPointer<Lmdb>();
#endif
    }
    return QSharedPointer<Lmdb>(new Lmdb(d.take()));
}

QTNETWORKNG_NAMESPACE_END
