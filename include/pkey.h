#ifndef QTNG_PKEY_H
#define QTNG_PKEY_H

#include <QtCore/qsharedpointer.h>
#include "cipher.h"

QTNETWORKNG_NAMESPACE_BEGIN

class PrivateKey;
class PrivateKeyWriterPrivate;
class PrivateKeyReaderPrivate;
class PublicKeyPrivate;
class PublicKey
{
public:
    enum Algorithm {
        Opaque = 0,
        Rsa = 1,
        Dsa = 2,
        Ec = 3,
    };

    enum RsaPadding { // copy from openssl header
        RSA_PKCS1_PADDING = 1,
        RSA_NO_PADDING = 3,
        RSA_PKCS1_OAEP_PADDING = 4,
//        RSA_SSLV23_PADDING = 2,
//        RSA_X931_PADDING = 5,
//        RSA_PKCS1_PSS_PADDING = 6,
    };

public:
    PublicKey();
    ~PublicKey();
    PublicKey(const PublicKey &other);
    PublicKey(PublicKey &&other):d_ptr(0)  {qSwap(d_ptr, other.d_ptr); }
public:
    Qt::HANDLE handle() const;
    bool isNull() const;
    bool isValid() const;
    Algorithm algorithm() const;
    int bits() const;
    bool verify(const QByteArray &data, const QByteArray &hash, MessageDigest::Algorithm hashAlgo);
    QByteArray encrypt(const QByteArray &data);
public:
    QByteArray rsaPublicEncrypt(const QByteArray &data, RsaPadding padding = RSA_PKCS1_PADDING); // RSA_PKCS1_OAEP_PADDING?
    QByteArray rsaPublicDecrypt(const QByteArray &data, RsaPadding padding = RSA_PKCS1_PADDING);
public:
    static PublicKey load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem);
    QByteArray save(Ssl::EncodingFormat format = Ssl::Pem) const;
public:
    PublicKey &operator=(const PublicKey &other);
    bool operator ==(const PublicKey &other) const;
    bool operator ==(const PrivateKey &) const { return false; }
    bool operator !=(const PublicKey &other) const { return !(*this == other); }
    bool operator !=(const PrivateKey &) const { return true; }
protected:
    PublicKeyPrivate * d_ptr;
    Q_DECLARE_PRIVATE(PublicKey)
    friend class PrivateKeyWriterPrivate;
    friend class PrivateKeyReaderPrivate;
};

class PrivateKey: public PublicKey
{
public:
    PrivateKey(): PublicKey() {}
    PrivateKey(const PrivateKey &other): PublicKey(other) {}
    PrivateKey(PrivateKey &&other): PublicKey(other) {}
    PrivateKey &operator=(const PublicKey &other) { PublicKey::operator =(other); return *this; }
    PrivateKey &operator=(const PrivateKey &other) { PublicKey::operator =(other); return *this; }
    bool operator ==(const PrivateKey &other) const;
    bool operator ==(const PublicKey &) const { return false; }
    bool operator !=(const PrivateKey &other) const { return !(*this == other); }
    bool operator !=(const PublicKey &) const { return true; }
public:
    PublicKey publicKey() const;
    QByteArray sign(const QByteArray &data, MessageDigest::Algorithm hashAlgo);
    QByteArray decrypt(const QByteArray &data);
public:
    QByteArray rsaPrivateEncrypt(const QByteArray &data, RsaPadding padding = RSA_PKCS1_PADDING);
    QByteArray rsaPrivateDecrypt(const QByteArray &data, RsaPadding padding = RSA_PKCS1_PADDING); // RSA_PKCS1_OAEP_PADDING?
public:
    static PrivateKey generate(Algorithm algo, int bits);
    static PrivateKey load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &password = QByteArray());
    QByteArray save(Ssl::EncodingFormat format = Ssl::Pem, const QByteArray &password = QByteArray()) const;
    QByteArray savePublic(Ssl::EncodingFormat format = Ssl::Pem) const { return PublicKey::save(format); }
private:
    friend class PublicKeyPrivate;
    friend class PrivateKeyReaderPrivate;
    friend class PrivateKeyWriterPrivate;
};


class PasswordCallback
{
public:
    virtual ~PasswordCallback() = default;
    virtual QByteArray get(bool writing) = 0;
};


class PrivateKeyWriter
{
public:
    explicit PrivateKeyWriter(const PrivateKey &key);
    explicit PrivateKeyWriter(const PublicKey &key);
    ~PrivateKeyWriter();
public:
    PrivateKeyWriter &setCipher(Cipher::Algorithm algo, Cipher::Mode mode);
    PrivateKeyWriter &setPassword(const QByteArray &password);
    PrivateKeyWriter &setPassword(QSharedPointer<PasswordCallback> callback);
    PrivateKeyWriter &setPublicOnly(bool publicOnly);
    QByteArray asPem();
    QByteArray asDer();
    bool save(const QString &filePath);
private:
    Q_DECLARE_PRIVATE(PrivateKeyWriter)
    PrivateKeyWriterPrivate * const d_ptr;
};


class PrivateKeyReader
{
public:
    PrivateKeyReader();
    ~PrivateKeyReader();
public:
    PrivateKeyReader &setPassword(const QByteArray &password);
    PrivateKeyReader &setPassword(QSharedPointer<PasswordCallback> callback);
    PrivateKeyReader &setFormat(Ssl::EncodingFormat format);
    PrivateKey read(const QByteArray &data);
    PublicKey readPublic(const QByteArray &data);
    PrivateKey read(const QString &filePath);
    PublicKey readPublic(const QString &filePath);
private:
    Q_DECLARE_PRIVATE(PrivateKeyReader)
    PrivateKeyReaderPrivate * const d_ptr;
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_PKEY_H
