#include "../include/md.h"
#include "../include/private/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

const EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo)
{
    const EVP_MD *md = nullptr;
    switch(algo)
    {
    case MessageDigest::Md4:
        md = EVP_md4();
        break;
    case MessageDigest::Md5:
        md = EVP_md5();
        break;
    case MessageDigest::Sha1:
        md = EVP_sha1();
        break;
    case MessageDigest::Sha224:
        md = EVP_sha224();
        break;
    case MessageDigest::Sha256:
        md = EVP_sha256();
        break;
    case MessageDigest::Sha384:
        md = EVP_sha384();
        break;
    case MessageDigest::Sha512:
        md = EVP_sha512();
        break;
    case MessageDigest::Ripemd160:
        md = EVP_ripemd160();
        break;
    case MessageDigest::Whirlpool:
        md = EVP_whirlpool();
    default:
        Q_UNREACHABLE();
    }
    return md;
}


class MessageDigestPrivate
{
public:
    MessageDigestPrivate(MessageDigest::Algorithm algo);
    ~MessageDigestPrivate();
    void addData(const QByteArray &data);
    QByteArray result();
    EVP_MD_CTX *context;
    QByteArray finalData;
    MessageDigest::Algorithm algo;
    bool hasError;
};


MessageDigestPrivate::MessageDigestPrivate(MessageDigest::Algorithm algo)
    :context(nullptr), algo(algo), hasError(false)
{
    initOpenSSL();
    const EVP_MD *md = getOpenSSL_MD(algo);

    if(!md) {
        hasError = true;
        return;
    }

    context = EVP_MD_CTX_new();

    if(!context) {
        hasError = true;
        return;
    }
    if(!EVP_DigestInit_ex(context, md, nullptr)) {
        EVP_MD_CTX_free(context);
        context = nullptr;
        hasError = true;
        return;
    }
}

MessageDigestPrivate::~MessageDigestPrivate()
{
    if(context) {
        EVP_MD_CTX_free(context);
    }
}

void MessageDigestPrivate::addData(const QByteArray &data)
{
    if(hasError)
        return;
    int rvalue = EVP_DigestUpdate(context, data.data(), static_cast<size_t>(data.size()));
    hasError = !rvalue;
}

QByteArray MessageDigestPrivate::result()
{
    if(hasError) {
        return QByteArray();
    }
    if(!finalData.isEmpty()) {
        return finalData;
    }
    unsigned int len;
    finalData.resize(EVP_MAX_MD_SIZE);
    int rvalue = EVP_DigestFinal_ex(context, reinterpret_cast<unsigned char*>(finalData.data()), &len);
    if(!rvalue) {
        hasError = true;
        finalData.clear();
    } else {
        finalData.resize(static_cast<int>(len));
    }

    return finalData;
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algo)
    :d_ptr(new MessageDigestPrivate(algo))
{
}


MessageDigest::~MessageDigest()
{
    delete d_ptr;
}


void MessageDigest::addData(const QByteArray &data)
{
    Q_D(MessageDigest);
    d->addData(data);
}


QByteArray MessageDigest::result()
{
    Q_D(MessageDigest);
    return d->result();
}

QByteArray PBKDF2_HMAC(int keylen, const QByteArray &password, const QByteArray &salt,
                       const MessageDigest::Algorithm hashAlgo, int i)
{
    initOpenSSL();
    const EVP_MD *dgst = getOpenSSL_MD(hashAlgo);

    if(!dgst || salt.isEmpty() || password.isEmpty() || i <= 0) {
        return QByteArray();
    }

    QByteArray key;
    key.resize(keylen);

    int rvalue = PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                                   reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
                                   i, dgst, keylen, reinterpret_cast<unsigned char *>(key.data()));
    if (rvalue) {
        return key;
    } else {
        return QByteArray();
    }
}

//QByteArray scrypt(const QByteArray &password, int keylen, const QByteArray &salt,
//                  int n, int r, int p)
//{
//    initOpenSSL();
//    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);

//    if(!pctx || password.isEmpty() || salt.isEmpty()) {
//        return QByteArray();
//    }

//    QByteArray key;
//    key.resize(keylen);

//    int rvalue = EVP_PKEY_derive_init(pctx);
//    if (rvalue <= 0) {
//        qDebug() << "can not init scrypt kdf.";
//        return QByteArray();
//    }
//    rvalue = EVP_PKEY_CTX_set1_pbe_pass(pctx, password.data(), password.size());
//    if (rvalue <= 0) {
//        qDebug() << "can not set scrypt password.";
//        return QByteArray();
//    }
//    rvalue = EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt.data(), salt.size());
//    if (rvalue <= 0) {
//        qDebug() << "can not set scrypt salt.";
//        return QByteArray();
//    }

//}

QTNETWORKNG_NAMESPACE_END
