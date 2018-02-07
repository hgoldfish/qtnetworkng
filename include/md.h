#ifndef QTNG_MD_H
#define QTNG_MD_H

#include <QtCore/qbytearray.h>
#include "crypto.h"

QTNETWORKNG_NAMESPACE_BEGIN

class MessageDigestPrivate;
class MessageDigest
{
public:
    enum Algorithm
    {
        Md4 = 0,
        Md5 = 1,
        Sha1 = 2,
        Sha224 = 3,
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6,
        Sha3_224 = 7,
        Sha3_256 = 8,
        Sha3_384 = 9,
        Sha3_512 = 10,
        Ripemd160 = 11,
        Blake2s256 = 12,
        Blake2b512 = 13,
    };
public:
    explicit MessageDigest(Algorithm algo);
    virtual ~MessageDigest();
public:
    void addData(const QByteArray &data);
    QByteArray result();
public:
    inline void update(const QByteArray &data) { addData(data); }
    inline QByteArray digest() { return result(); }
    inline QByteArray hexDigest() { return result().toHex(); }
public:
    static QByteArray hash(const QByteArray &data, Algorithm algo);
private:
    MessageDigestPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(MessageDigest)
};


inline QByteArray MessageDigest::hash(const QByteArray &data, Algorithm algo)
{
    MessageDigest m(algo);
    m.addData(data);
    return m.result().toHex();
}

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_MD_H
