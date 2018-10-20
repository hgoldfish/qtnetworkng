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
        Ripemd160 = 11,
        Whirlpool = 12
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

QByteArray PBKDF2_HMAC(int keylen, const QByteArray &password, const QByteArray &salt,
                       const MessageDigest::Algorithm hashAlgo = MessageDigest::Sha256,
                       int i = 10000);

QByteArray scrypt(int keylen, const QByteArray &password, const QByteArray &salt,
                  int n = 1048576, int r = 8, int p = 1);

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_MD_H
