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
        Blowfish = 8,
        CAST5 = 9,
        Chacha20 = 10,
        ChaCha20Poly1305 = 11
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
    Cipher *copy(Operation operation);
public:
    bool isValid() const;
    bool isStream() const;
    bool isBlock() const { return !isStream(); }
    bool setKey(const QByteArray &key);
    QByteArray key() const;
    bool setInitialVector(const QByteArray &iv);
    QByteArray initialVector() const;
    inline QByteArray iv() const { return initialVector(); }
    bool setPassword(const QByteArray &password, const QByteArray &salt,
                     const MessageDigest::Algorithm hashAlgo = MessageDigest::Sha256,
                     int i = 100000 /* same as django PBKDF2*/);
    bool setOpensslPassword(const QByteArray &password, const QByteArray &salt,
                            const MessageDigest::Algorithm hashAlgo = MessageDigest::Md5,
                            int i = 1); // same as openssl command line.
    QByteArray salt() const;
    QByteArray saltHeader() const; // `openssl enc` generate a header contains salt
    bool setPadding(bool padding);
    bool padding() const;
    int keySize() const;
    int ivSize() const;
    int blockSize() const;
public:
    QByteArray addData(const QByteArray &data) { return addData(data.constData(), data.size()); }
    QByteArray addData(const char *data, int len);
    QByteArray finalData();
public:
    QByteArray update(const QByteArray &data) { return addData(data.constData(), data.size()); }
    QByteArray update(const char *data, int len) { return addData(data, len); }
    QByteArray final() { return finalData(); }
public:
    static QPair<QByteArray, QByteArray> parseSalt(const QByteArray &header); // parse salt from `openssl enc` header
private:
    CipherPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Cipher)
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_CIPHER_H
