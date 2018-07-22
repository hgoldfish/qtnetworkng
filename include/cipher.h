#ifndef QTNG_CIPHER_H
#define QTNG_CIPHER_H

#include <QtCore/qpair.h>
#include "md.h"

QTNETWORKNG_NAMESPACE_BEGIN

class CipherPrivate;
class Cipher
{
public:
    enum Algorithm
    {
        Null = 1,
        AES128 = 2,
        AES192 = 3,
        AES256 = 4,
        DES = 5,
        DES2 = 6,
        DES3 = 7,
        RC2 = 8,
        RC4 = 9,
        RC5 = 10,
        IDEA = 11,
        Blowfish = 12,
        CAST5 = 13,
        Chacha20 = 14,
    };
    enum Mode
    {
        ECB = 1,
        CBC = 2,
        CFB = 3,
        // PGP = 4,
        OFB = 5,
        CTR = 6,
        OPENPGP = 7,
    };
    enum Operation
    {
        Encrypt = 1,
        Decrypt = 2,
    };
public:
    Cipher(Algorithm alog, Mode mode, Operation operation);
    virtual ~Cipher();
public:
    bool setKey(const QByteArray &key);
    QByteArray key() const;
    bool setInitialVector(const QByteArray &iv);
    QByteArray initialVector() const;
    bool setPassword(const QByteArray &password,
                     const MessageDigest::Algorithm hashAlgo = MessageDigest::Sha256,
                     const QByteArray &salt = QByteArray(), int i = 100000 /* same as django PBKDF2*/);
    bool setOpensslPassword(const QByteArray &password,
                            const MessageDigest::Algorithm hashAlgo = MessageDigest::Md5,
                            const QByteArray &salt = QByteArray(), int i = 1);
    QByteArray salt() const;
    QByteArray saltHeader() const; // `openssl enc` generate a header contains salt
    QPair<QByteArray, QByteArray> parseSalt(const QByteArray &header); // parse salt from `openssl enc` header
    bool setPadding(bool padding);
public:
    QByteArray addData(const QByteArray &data);
    QByteArray finalData();
public:
    QByteArray update(const QByteArray &data) { return addData(data); }
    QByteArray final() { return finalData(); }
private:
    CipherPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Cipher)
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_CIPHER_H
