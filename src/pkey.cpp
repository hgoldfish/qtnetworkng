#include <QtCore/qdebug.h>
#include <QtCore/qfile.h>
#include "../include/pkey.h"
#include "../include/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN


struct PublicKeyPrivate
{
    PublicKeyPrivate();
    PublicKeyPrivate(PublicKeyPrivate *other);
    ~PublicKeyPrivate();

    PublicKey::Algorithm algorithm() const;
    int bits() const;
    QByteArray sign(const QByteArray &data, MessageDigest::Algorithm hashAlgo);
    bool verify(const QByteArray &data, const QByteArray &hash, MessageDigest::Algorithm hashAlgo);
    QByteArray encrypt(const QByteArray &data);
    QByteArray decrypt(const QByteArray &data);
    QByteArray rsaPublicEncrypt(const QByteArray &data, PublicKey::RsaPadding padding) const;
    QByteArray rsaPublicDecrypt(const QByteArray &data, PublicKey::RsaPadding padding) const;
    QByteArray rsaPrivateEncrypt(const QByteArray &data, PublicKey::RsaPadding padding) const;
    QByteArray rsaPrivateDecrypt(const QByteArray &data, PublicKey::RsaPadding padding) const;
    static PrivateKey generate(PublicKey::Algorithm algo, int bits);
    static bool inline setPkey(PublicKey *key, openssl::EVP_PKEY *pkey, bool hasPrivate);

    openssl::EVP_PKEY_CTX *context;
    QSharedPointer<openssl::EVP_PKEY> pkey;
    bool hasPrivate;
};


PublicKeyPrivate::PublicKeyPrivate()
    :context(0), hasPrivate(false)
{
    initOpenSSL();
}

PublicKeyPrivate::PublicKeyPrivate(PublicKeyPrivate *other)
    :context(0), hasPrivate(false)
{
    initOpenSSL();
    if(other->context && !other->pkey.isNull()) {
        context = openssl::q_EVP_PKEY_CTX_dup(other->context);
        pkey = other->pkey;
        hasPrivate = other->hasPrivate;
    }
}

PublicKeyPrivate::~PublicKeyPrivate()
{
    if(context) {
        openssl::q_EVP_PKEY_CTX_free(context);
    }
}


PublicKey::Algorithm PublicKeyPrivate::algorithm() const
{
    if(!pkey.isNull()) {
        int type = openssl::q_EVP_PKEY_base_id(pkey.data());
        switch(type) {
        case EVP_PKEY_RSA:
            return PublicKey::Rsa;
        case EVP_PKEY_DSA:
            return PublicKey::Dsa;
        case EVP_PKEY_EC:
            return PublicKey::Ec;
        default:
            return PublicKey::Opaque;
        }
    } else {
        return PublicKey::Opaque;
    }
}

int PublicKeyPrivate::bits() const
{
    if(!pkey.isNull()) {
        return openssl::q_EVP_PKEY_bits(pkey.data());
    } else {
        return 0;
    }
}

bool openssl_setPkey(PublicKey *key, openssl::EVP_PKEY *pkey, bool hasPrivate)
{
    return PublicKeyPrivate::setPkey(key, pkey, hasPrivate);
}

bool PublicKeyPrivate::setPkey(PublicKey *key, openssl::EVP_PKEY *pkey, bool hasPrivate)
{
    openssl::EVP_PKEY_CTX *context = NULL;
    context = openssl::q_EVP_PKEY_CTX_new(pkey, NULL); // should i free pkey?
    if(!context) {
        openssl::q_EVP_PKEY_free(pkey);
        return false;
    } else {
        key->d_ptr->context = context;
        key->d_ptr->pkey.reset(pkey, openssl::q_EVP_PKEY_free);
        key->d_ptr->hasPrivate = hasPrivate;
        return true;
    }
}

PrivateKey PublicKeyPrivate::generate(PublicKey::Algorithm algo, int bits)
{
    PrivateKey key;
    int rvalue;

    openssl::EVP_PKEY *pkey = NULL;

    pkey = openssl::q_EVP_PKEY_new();
    if (!pkey) {
        return key;
    }

    if (algo == PrivateKey::Rsa) {
        openssl::RSA *rsa = openssl::q_RSA_new();
        if(!rsa) {
            openssl::q_EVP_PKEY_free(pkey);
            return key;
        }
        openssl::BIGNUM *e = openssl::q_BN_new();
        if(!e) {
            openssl::q_RSA_free(rsa);
            openssl::q_EVP_PKEY_free(pkey);
            return key;
        }
        openssl::q_BN_set_word(e, 65537);
        rvalue = openssl::q_RSA_generate_key_ex(rsa, bits, e, NULL);
        openssl::q_BN_free(e);
        if(rvalue) {
            rvalue = openssl::q_EVP_PKEY_set1_RSA(pkey, rsa);
        }
        openssl::q_RSA_free(rsa);
        if(!rvalue) {
            openssl::q_EVP_PKEY_free(pkey);
            return key;
        }
    } else if (algo == PrivateKey::Dsa) {
        openssl::DSA *dsa = openssl::q_DSA_new();
        if(!dsa) {
            openssl::q_EVP_PKEY_free(pkey);
            return key;
        }
        rvalue = openssl::q_DSA_generate_parameters_ex(dsa, bits, NULL, 0, NULL, NULL, NULL);
        if(rvalue) {
            rvalue = openssl::q_DSA_generate_key(dsa);
            if(rvalue) {
                rvalue = openssl::q_EVP_PKEY_set1_DSA(pkey, dsa);
            }
        }
        openssl::q_DSA_free(dsa);
        if(!rvalue) {
            openssl::q_EVP_PKEY_free(pkey);
            return key;
        }
    } else if (algo == PrivateKey::Ec) {
        return key;
    } else {
        Q_UNREACHABLE();
        return key;
    }
    openssl_setPkey(&key, pkey, true);
    return key;
}


QByteArray PublicKeyPrivate::sign(const QByteArray &data, MessageDigest::Algorithm hashAlgo)
{
    if(pkey.isNull() || !hasPrivate) {
        return QByteArray();
    }

    int rvalue = 0;
    const openssl::EVP_MD *md = getOpenSSL_MD(hashAlgo);
    if(!md) {
        return QByteArray();
    }

    openssl::EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if(!mctx) {
        return QByteArray();
    }
    rvalue = openssl::q_EVP_DigestSignInit(mctx, NULL, md, NULL, pkey.data());
    if(!rvalue) {
        EVP_MD_CTX_free(mctx);
        return QByteArray();
    }
    rvalue = openssl::q_EVP_DigestSignUpdate(mctx, data.data(), data.size());
    if(!rvalue) {
        EVP_MD_CTX_free(mctx);
        return QByteArray();
    }
    size_t siglen;
    rvalue = openssl::q_EVP_DigestSignFinal(mctx, NULL, &siglen);
    if(!rvalue) {
        EVP_MD_CTX_free(mctx);
        return QByteArray();
    }

    QByteArray result;
    result.resize(siglen);
    rvalue = openssl::q_EVP_DigestSignFinal(mctx, (unsigned char*) result.data(), &siglen);
    EVP_MD_CTX_free(mctx);
    if(!rvalue) {
        return QByteArray();
    } else {
        return result;
    }
}


bool PublicKeyPrivate::verify(const QByteArray &data, const QByteArray &hash, MessageDigest::Algorithm hashAlgo)
{
    if(pkey.isNull()) {
        return false;
    }

    int rvalue = 0;
    const openssl::EVP_MD *md = getOpenSSL_MD(hashAlgo);
    if(!md) {
        return false;
    }

    openssl::EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    if(!mctx) {
        return false;
    }
    rvalue = openssl::q_EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey.data());
    if(!rvalue) {
        EVP_MD_CTX_free(mctx);
        return false;
    }
    rvalue = openssl::q_EVP_DigestVerifyUpdate(mctx, data.data(), data.size());
    if(!rvalue) {
        EVP_MD_CTX_free(mctx);
        return false;
    }
    rvalue = openssl::q_EVP_DigestVerifyFinal(mctx, (const unsigned char *) hash.data(), (size_t) hash.size());
    EVP_MD_CTX_free(mctx);
    if(!rvalue) {
        return false;
    } else {
        return true;
    }
}


QByteArray PublicKeyPrivate::encrypt(const QByteArray &data)
{
    if(pkey.isNull() || !context || data.isEmpty()) {
        return QByteArray();
    }

    int rvalue = openssl::q_EVP_PKEY_encrypt_init(context);
    if(rvalue) {
        size_t outlen = 0;
        rvalue = openssl::q_EVP_PKEY_encrypt(context, NULL, &outlen, (const unsigned char *) data.data(), data.size());
        if(rvalue && outlen) {
            QByteArray result;
            result.resize(outlen);
            rvalue = openssl::q_EVP_PKEY_encrypt(context, (unsigned char *) result.data(), &outlen, (const unsigned char *) data.data(), data.size());
            if(rvalue) {
                result.resize(outlen);
                return result;
            }
        }
    }
    qDebug() << "can not encrypt data." << rvalue;
    return QByteArray();
}


QByteArray PublicKeyPrivate::decrypt(const QByteArray &data)
{
    if(pkey.isNull() || !context || data.isEmpty() || !hasPrivate) {
        return QByteArray();
    }
    int rvalue;
    rvalue = openssl::q_EVP_PKEY_decrypt_init(context);
    if(rvalue) {
        size_t outlen;
        rvalue = openssl::q_EVP_PKEY_decrypt(context, NULL, &outlen, (const unsigned char *) data.data(), data.size());
        if(rvalue && outlen) {
            QByteArray result;
            result.resize(outlen);
            rvalue = openssl::q_EVP_PKEY_decrypt(context, (unsigned char *) result.data(), &outlen, (const unsigned char *) data.data(), data.size());
            if(rvalue) {
                result.resize(outlen);
                return result;
            }
        }
    }
    qDebug() << "can not private decrypt data." << rvalue;
    return QByteArray();
}


QByteArray PublicKeyPrivate::rsaPublicEncrypt(const QByteArray &data, PublicKey::RsaPadding padding) const
{
    if(pkey.isNull() || data.isEmpty()) {
        return QByteArray();
    }

    if(padding != PublicKey::RSA_PKCS1_PADDING && padding != PublicKey::RSA_NO_PADDING
            && padding != PublicKey::RSA_PKCS1_OAEP_PADDING) {
        qDebug() << "invalid padding" << padding;
        return QByteArray();
    }

    openssl::RSA *rsa = openssl::q_EVP_PKEY_get1_RSA(pkey.data());
    if(!rsa) {
        return QByteArray();
    }

    int rsaSize = openssl::q_RSA_size(rsa);
    if(!rsaSize) {
        openssl::q_RSA_free(rsa);
        return QByteArray();
    }

    int rvalue;
    QByteArray result;
    result.resize(rsaSize);
    rvalue = openssl::q_RSA_public_encrypt(data.size(), (unsigned char *) data.data(), (unsigned char *) result.data(), rsa, (int) padding);
    openssl::q_RSA_free(rsa);
    if(rvalue) {
        result.resize(rvalue);
        return result;
    }
    qDebug() << "can not public encrypt data." << rvalue;
    return QByteArray();
}


QByteArray PublicKeyPrivate::rsaPublicDecrypt(const QByteArray &data, PublicKey::RsaPadding padding) const
{
    if(pkey.isNull() || data.isEmpty()) {
        return QByteArray();
    }
    if(padding != PublicKey::RSA_PKCS1_PADDING && padding != PublicKey::RSA_NO_PADDING) {
        qDebug() << "invalid padding" << padding;
        return QByteArray();
    }

    openssl::RSA *rsa = openssl::q_EVP_PKEY_get1_RSA(pkey.data());
    if(!rsa) {
        return QByteArray();
    }

    int rsaSize = openssl::q_RSA_size(rsa);
    if(!rsaSize) {
        openssl::q_RSA_free(rsa);
        return QByteArray();
    }

    int rvalue;
    QByteArray result;
    result.resize(rsaSize);
    rvalue = openssl::q_RSA_public_decrypt(data.size(), (unsigned char *) data.data(), (unsigned char *) result.data(), rsa, (int) padding);
    openssl::q_RSA_free(rsa);
    if(rvalue) {
        result.resize(rvalue);
        return result;
    }
    qDebug() << "can not public decrypt data." << rvalue;
    return QByteArray();
}


QByteArray PublicKeyPrivate::rsaPrivateEncrypt(const QByteArray &data, PrivateKey::RsaPadding padding) const
{
    if(pkey.isNull() || data.isEmpty() || !hasPrivate) {
        return QByteArray();
    }

    if(padding != PrivateKey::RSA_PKCS1_PADDING && padding != PrivateKey::RSA_NO_PADDING) {
        qDebug() << "invalid padding" << padding;
        return QByteArray();
    }

    openssl::RSA *rsa = openssl::q_EVP_PKEY_get1_RSA(pkey.data());
    if(!rsa) {
        return QByteArray();
    }

    int rsaSize = openssl::q_RSA_size(rsa);
    if(!rsaSize) {
        openssl::q_RSA_free(rsa);
        return QByteArray();
    }

    int rvalue;
    QByteArray result;
    result.resize(rsaSize);
    rvalue = openssl::q_RSA_private_encrypt(data.size(), (unsigned char *) data.data(), (unsigned char *) result.data(), rsa, (int) padding);
    openssl::q_RSA_free(rsa);
    if(rvalue) {
        result.resize(rvalue);
        return result;
    }
    qDebug() << "can not private encrypt data." << rvalue;
    return QByteArray();
}


QByteArray PublicKeyPrivate::rsaPrivateDecrypt(const QByteArray &data, PrivateKey::RsaPadding padding) const
{
    if(pkey.isNull() || data.isEmpty() || !hasPrivate) {
        return QByteArray();
    }

    if(padding != PrivateKey::RSA_PKCS1_PADDING && padding != PrivateKey::RSA_NO_PADDING
            && padding != PrivateKey::RSA_PKCS1_OAEP_PADDING) {
        qDebug() << "invalid padding" << padding;
        return QByteArray();
    }

    openssl::RSA *rsa = openssl::q_EVP_PKEY_get1_RSA(pkey.data());
    if(!rsa) {
        return QByteArray();
    }

    int rsaSize = openssl::q_RSA_size(rsa);
    if(!rsaSize) {
        openssl::q_RSA_free(rsa);
        return QByteArray();
    }

    int rvalue;
    QByteArray result;
    result.resize(rsaSize);
    rvalue = openssl::q_RSA_private_decrypt(data.size(), (unsigned char *) data.data(), (unsigned char *) result.data(), rsa, (int) padding);
    openssl::q_RSA_free(rsa);
    if(rvalue) {
        result.resize(rvalue);
        return result;
    }
    qDebug() << "can not private decrypt data." << rvalue;
    return QByteArray();
}


struct SimplePasswordCallback: public PasswordCallback
{
public:
    SimplePasswordCallback(const QByteArray &password) : password(password) {}
    virtual QByteArray get(bool writing) override { Q_UNUSED(writing); return password; }
    QByteArray password;
};


static int pem_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    if(userdata == NULL) {
        return 0;
    }

    PasswordCallback *callback = static_cast<PasswordCallback*>(userdata);
    const QByteArray &password = callback->get(rwflag == 1);
    int move = qMin(size, password.size());
    if(!move) {
        return 0;
    }
    strncpy(buf, password.data(), move);
    return move;
}

struct PrivateKeyWriterPrivate
{
    PrivateKeyWriterPrivate(const PublicKey &key)
        :key(key), algo(Cipher::Null), mode(Cipher::CBC), publicOnly(true) {}
    PrivateKeyWriterPrivate(const PrivateKey &key)
        :key(key), algo(Cipher::Null), mode(Cipher::CBC), publicOnly(false) {}
    QByteArray asPem();
    QByteArray asDer();
    QByteArray save(Ssl::EncodingFormat format);

    const PublicKey &key;
    Cipher::Algorithm algo;
    Cipher::Mode mode;
    QSharedPointer<PasswordCallback> callback;
    QByteArray password;
    bool publicOnly;
};


QByteArray PrivateKeyWriterPrivate::asPem()
{
    if(!key.isValid()) {
        return QByteArray();
    }

    openssl::BIO *bio = openssl::q_BIO_new(openssl::q_BIO_s_mem());
    if(!bio) {
        return QByteArray();
    }
    const openssl::EVP_CIPHER *cipher = NULL;
    if(algo != Cipher::Null && (!password.isEmpty() || !callback.isNull()))  {
        cipher = getOpenSSL_CIPHER(algo, mode);
        if(!cipher) {
            openssl::q_BIO_free(bio);
            return QByteArray();
        }
    }
    int rvalue;
    if(key.d_ptr->hasPrivate && !publicOnly) {
        // we don't use PEM_write_bio_RSAPrivateKey() & PEM_write_bio_DSAPrivateKey
        if(!callback.isNull()) {
            //q_PEM_write_bio_PrivateKey
            rvalue = openssl::q_PEM_write_bio_PKCS8PrivateKey(bio, key.d_ptr->pkey.data(), cipher, NULL, 0, pem_password_cb, callback.data());
        } else if(!password.isEmpty()) {
            rvalue = openssl::q_PEM_write_bio_PKCS8PrivateKey(bio, key.d_ptr->pkey.data(), cipher, (unsigned char *) password.data(), password.size(), NULL, NULL);
        } else {
            rvalue = openssl::q_PEM_write_bio_PKCS8PrivateKey(bio, key.d_ptr->pkey.data(), NULL, NULL, 0, NULL, NULL);
        }
    } else {
        rvalue = openssl::q_PEM_write_bio_PUBKEY(bio, key.d_ptr->pkey.data());
    }
    if(rvalue) {
        char *p = NULL;
        int size = openssl::q_BIO_get_mem_data(bio, &p);
        if(size > 0 && p != NULL) {
            QByteArray result(p, size);
            openssl::q_BIO_free(bio);
            return result;
        }
    }
    openssl::q_BIO_free(bio);
    return QByteArray();
}


QByteArray PrivateKeyWriterPrivate::asDer()
{
    //FIXME
    return QByteArray();
}


QByteArray PrivateKeyWriterPrivate::save(Ssl::EncodingFormat format)
{
    if(format == Ssl::Pem) {
        return asPem();
    } else if(format == Ssl::Der) {
        return asDer();
    } else {
        return QByteArray();
    }
}


struct PrivateKeyReaderPrivate
{
    PrivateKey read(const QByteArray &data);
    PrivateKey read(const QString &filePath);
    PublicKey readPublic(const QByteArray &data);
    PublicKey readPublic(const QString &filePath);

    QSharedPointer<PasswordCallback> callback;
    QByteArray password;
    Ssl::EncodingFormat format;
};


PrivateKey PrivateKeyReaderPrivate::read(const QByteArray &data)
{
    PrivateKey key;
    if(format != Ssl::Pem) {
        return key;
    }

    openssl::BIO *bio = openssl::q_BIO_new_mem_buf(data.data(), data.size());
    openssl::EVP_PKEY *pkey = NULL;
    if(!password.isEmpty()) {
        QSharedPointer<SimplePasswordCallback> cb(new SimplePasswordCallback(password));
        openssl::q_PEM_read_bio_PrivateKey(bio, &pkey, pem_password_cb, cb.data());
    } else if (!callback.isNull()) {
        openssl::q_PEM_read_bio_PrivateKey(bio, &pkey, pem_password_cb, callback.data());
    } else {
        openssl::q_PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
    }
    if(!pkey) {
        openssl::q_BIO_free(bio);
        return key;
    }
    openssl::EVP_PKEY_CTX *context = NULL;
    context = openssl::q_EVP_PKEY_CTX_new(pkey, NULL); // should i free pkey?
    if(!context) {
        openssl::q_EVP_PKEY_free(pkey);
    } else {
        key.d_ptr->hasPrivate = true;
        key.d_ptr->context = context;
        key.d_ptr->pkey.reset(pkey, openssl::q_EVP_PKEY_free);
    }
    openssl::q_BIO_free(bio);
    return key;
}


PrivateKey PrivateKeyReaderPrivate::read(const QString &filePath)
{
    QFile f(filePath);
    if(!f.open(QIODevice::ReadOnly)) {
        return PrivateKey();
    }
    QByteArray data = f.readAll();
    f.close();
    return read(data);
}


PublicKey PrivateKeyReaderPrivate::readPublic(const QByteArray &data)
{
    PublicKey key;
    if(format != Ssl::Pem) {
        return key;
    }

    openssl::BIO *bio = openssl::q_BIO_new_mem_buf(data.data(), data.size());
    openssl::EVP_PKEY *pkey = NULL;
    if(!password.isEmpty()) {
        QSharedPointer<SimplePasswordCallback> cb(new SimplePasswordCallback(password));
        openssl::q_PEM_read_bio_PUBKEY(bio, &pkey, pem_password_cb, cb.data());
    } else if (!callback.isNull()) {
        openssl::q_PEM_read_bio_PUBKEY(bio, &pkey, pem_password_cb, callback.data());
    } else {
        openssl::q_PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
    }
    if(!pkey) {
        openssl::q_BIO_free(bio);
        return key;
    }

    openssl::EVP_PKEY_CTX *context = NULL;
    context = openssl::q_EVP_PKEY_CTX_new(pkey, NULL); // should i free pkey?
    if(!context) {
        openssl::q_EVP_PKEY_free(pkey);
    } else {
        key.d_ptr->context = context;
        key.d_ptr->pkey.reset(pkey, openssl::q_EVP_PKEY_free);
        key.d_ptr->hasPrivate = false;
    }
    return key;
}


PublicKey PrivateKeyReaderPrivate::readPublic(const QString &filePath)
{
    QFile f(filePath);
    if(!f.open(QIODevice::ReadOnly)) {
        return PrivateKey();
    }
    QByteArray data = f.readAll();
    f.close();
    return readPublic(data);
}

PublicKey::PublicKey()
    :d_ptr(new PublicKeyPrivate)
{
}


PublicKey::PublicKey(const PublicKey &other)
    :d_ptr(new PublicKeyPrivate(other.d_ptr))
{
}


PublicKey &PublicKey::operator=(const PublicKey &other)
{
    delete d_ptr;
    d_ptr = new PublicKeyPrivate(other.d_ptr);
    return *this;
}


bool comparePublicKey(const PublicKeyPrivate * d1, const PublicKeyPrivate *d2)
{
    if(d1->pkey == d2->pkey) {
        return true;
    }
    if(d1->pkey.isNull() || d2->pkey.isNull()) {
        return false;
    }
    return openssl::q_EVP_PKEY_cmp(d1->pkey.data(), d2->pkey.data());
}


bool PublicKey::operator ==(const PublicKey &other) const
{
    Q_D(const PublicKey);
    return comparePublicKey(d, other.d_ptr);
}


PublicKey::~PublicKey()
{
    if(d_ptr) {
        delete d_ptr;
    }
}


PublicKey PublicKey::load(const QByteArray &data, Ssl::EncodingFormat format)
{
    PrivateKeyReader reader;
    return reader.setFormat(format).readPublic(data);
}


QByteArray PublicKey::save(Ssl::EncodingFormat format) const
{
    PrivateKeyWriter writer(*this);
    if(format == Ssl::Pem) {
        return writer.asPem();
    } else if (format == Ssl::Der) {
        return writer.asDer();
    } else {
        Q_UNREACHABLE();
        return QByteArray();
    }
}

bool PublicKey::isNull() const
{
    Q_D(const PublicKey);
    return d->context == NULL;
}

bool PublicKey::isValid() const
{
    Q_D(const PublicKey);
    return d->context != NULL;
}

Qt::HANDLE PublicKey::handle() const
{
    Q_D(const PublicKey);
    return static_cast<Qt::HANDLE>(d->pkey.data());
}


PublicKey::Algorithm PublicKey::algorithm() const
{
    Q_D(const PublicKey);
    return d->algorithm();
}


int PublicKey::bits() const
{
    Q_D(const PublicKey);
    return d->bits();
}


bool PublicKey::verify(const QByteArray &data, const QByteArray &hash, MessageDigest::Algorithm hashAlgo)
{
    Q_D(PublicKey);
    return d->verify(data, hash, hashAlgo);
}


QByteArray PublicKey::encrypt(const QByteArray &data)
{
    Q_D(PublicKey);
    return d->encrypt(data);
}


QByteArray PublicKey::rsaPublicEncrypt(const QByteArray &data, PrivateKey::RsaPadding padding)
{
    Q_D(PublicKey);
    return d->rsaPublicEncrypt(data, padding);
}


QByteArray PublicKey::rsaPublicDecrypt(const QByteArray &data, PrivateKey::RsaPadding padding)
{
    Q_D(PublicKey);
    return d->rsaPublicDecrypt(data, padding);
}


bool PrivateKey::operator ==(const PrivateKey &other) const
{
    Q_D(const PublicKey);
    return comparePublicKey(d, other.d_ptr);
}

PrivateKey PrivateKey::load(const QByteArray &data, Ssl::EncodingFormat format, const QByteArray &password)
{
    PrivateKeyReader reader;
    if(!password.isEmpty()) {
        reader.setPassword(password);
    }
    return reader.setFormat(format).read(data);
}


PrivateKey PrivateKey::generate(PrivateKey::Algorithm algo, int bits)
{
    return PublicKeyPrivate::generate(algo, bits);
}


QByteArray PrivateKey::save(Ssl::EncodingFormat format, const QByteArray &password) const
{
    PrivateKeyWriter writer(*this);
    if(!password.isEmpty()) {
        writer.setPassword(password);
    }
    if(format == Ssl::Pem) {
        return writer.asPem();
    } else if (format == Ssl::Der) {
        return writer.asDer();
    } else {
        Q_UNREACHABLE();
        return QByteArray();
    }
}


PublicKey PrivateKey::publicKey() const
{
    return *this;
}


QByteArray PrivateKey::sign(const QByteArray &data, MessageDigest::Algorithm hashAlgo)
{
    Q_D(PublicKey);
    return d->sign(data, hashAlgo);
}


QByteArray PrivateKey::decrypt(const QByteArray &data)
{
    Q_D(PublicKey);
    return d->decrypt(data);
}


QByteArray PrivateKey::rsaPrivateEncrypt(const QByteArray &data, PrivateKey::RsaPadding padding)
{
    Q_D(PublicKey);
    return d->rsaPrivateEncrypt(data, padding);
}

QByteArray PrivateKey::rsaPrivateDecrypt(const QByteArray &data, PrivateKey::RsaPadding padding)
{
    Q_D(PublicKey);
    return d->rsaPrivateDecrypt(data, padding);
}

PrivateKeyWriter::PrivateKeyWriter(const PrivateKey &key)
    :d_ptr(new PrivateKeyWriterPrivate(key))
{
}

PrivateKeyWriter::PrivateKeyWriter(const PublicKey &key)
    :d_ptr(new PrivateKeyWriterPrivate(key))
{
}

PrivateKeyWriter::~PrivateKeyWriter()
{
    delete d_ptr;
}

PrivateKeyWriter &PrivateKeyWriter::setCipher(Cipher::Algorithm algo, Cipher::Mode mode)
{
    Q_D(PrivateKeyWriter);
    d->algo = algo;
    d->mode = mode;
    return *this;
}

PrivateKeyWriter &PrivateKeyWriter::setPassword(const QByteArray &password)
{
    Q_D(PrivateKeyWriter);
    if(d->algo == Cipher::Null) {
        qDebug() << "no cipher specified.";
    }
    d->password = password;
    d->callback.reset();
    return *this;
}

PrivateKeyWriter &PrivateKeyWriter::setPassword(QSharedPointer<PasswordCallback> callback)
{
    Q_D(PrivateKeyWriter);
    if(d->algo == Cipher::Null) {
        qDebug() << "no cipher specified.";
    }
    d->callback = callback;
    d->password.clear();
    return *this;
}

PrivateKeyWriter &PrivateKeyWriter::setPublicOnly(bool publicOnly)
{
    Q_D(PrivateKeyWriter);
    d->publicOnly = publicOnly;
    return *this;
}


QByteArray PrivateKeyWriter::asPem()
{
    Q_D(PrivateKeyWriter);
    return d->asPem();
}

QByteArray PrivateKeyWriter::asDer()
{
    return QByteArray();
}

bool PrivateKeyWriter::save(const QString &filePath)
{
    QFile f(filePath);
    if(f.open(QIODevice::WriteOnly)) {
        f.write(asPem());
        f.close();
        if(f.error() == QFileDevice::NoError) {
            return true;
        }
    }
    return false;
}


PrivateKeyReader::PrivateKeyReader()
    :d_ptr(new PrivateKeyReaderPrivate())
{
}

PrivateKeyReader::~PrivateKeyReader()
{
    delete d_ptr;
}

PrivateKeyReader &PrivateKeyReader::setPassword(const QByteArray &password)
{
    Q_D(PrivateKeyReader);
    d->password = password;
    d->callback.reset();
    return *this;
}

PrivateKeyReader &PrivateKeyReader::setPassword(QSharedPointer<PasswordCallback> callback)
{
    Q_D(PrivateKeyReader);
    d->password.clear();
    d->callback = callback;
    return *this;
}


PrivateKeyReader &PrivateKeyReader::setFormat(Ssl::EncodingFormat format)
{
    Q_D(PrivateKeyReader);
    d->format = format;
    return *this;
}


PrivateKey PrivateKeyReader::read(const QByteArray &data)
{
    Q_D(PrivateKeyReader);
    return d->read(data);
}


PublicKey PrivateKeyReader::readPublic(const QByteArray &data)
{
    Q_D(PrivateKeyReader);
    return d->readPublic(data);
}

PrivateKey PrivateKeyReader::read(const QString &filePath)
{
    Q_D(PrivateKeyReader);
    return d->read(filePath);
}


PublicKey PrivateKeyReader::readPublic(const QString &filePath)
{
    Q_D(PrivateKeyReader);
    return d->readPublic(filePath);
}

QTNETWORKNG_NAMESPACE_END
