#include "../include/md.h"
#include "../include/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

const openssl::EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo)
{
    const openssl::EVP_MD *md = NULL;
    switch(algo)
    {
    case MessageDigest::Md4:
        md = openssl::q_EVP_md4();
        break;
    case MessageDigest::Md5:
        md = openssl::q_EVP_md5();
        break;
    case MessageDigest::Sha1:
        md = openssl::q_EVP_sha1();
        break;
    case MessageDigest::Sha224:
        md = openssl::q_EVP_sha224();
        break;
    case MessageDigest::Sha256:
        md = openssl::q_EVP_sha256();
        break;
    case MessageDigest::Sha384:
        md = openssl::q_EVP_sha384();
        break;
    case MessageDigest::Sha512:
        md = openssl::q_EVP_sha512();
        break;
    case MessageDigest::Ripemd160:
        md = openssl::q_EVP_ripemd160();
        break;
    case MessageDigest::Blake2s256:
        md = openssl::q_EVP_blake2s256();
        break;
    case MessageDigest::Blake2b512:
        md = openssl::q_EVP_blake2b512();
        break;
    default:
        Q_UNREACHABLE();
    }
    return md;
}


openssl::EVP_MD_CTX *EVP_MD_CTX_new()
{
    openssl::EVP_MD_CTX *context = NULL;
    if(openssl::has_EVP_MD_CTX_new()) {
        context = openssl::q_EVP_MD_CTX_new();
    } else {
        context = openssl::q_EVP_MD_CTX_create();
    }
    return context;
}


void EVP_MD_CTX_free(openssl::EVP_MD_CTX *context)
{
    if(openssl::has_EVP_MD_CTX_new()) {
        openssl::q_EVP_MD_CTX_free(context);
    } else {
        openssl::q_EVP_MD_CTX_cleanup(context);
    }
}

class MessageDigestPrivate
{
public:
    MessageDigestPrivate(MessageDigest::Algorithm algo);
    ~MessageDigestPrivate();
    void addData(const QByteArray &data);
    QByteArray result();
    MessageDigest::Algorithm algo;
    openssl::EVP_MD_CTX *context;
    bool hasError;
    QByteArray finalData;
};


MessageDigestPrivate::MessageDigestPrivate(MessageDigest::Algorithm algo)
    :algo(algo), context(0), hasError(false)
{
    initOpenSSL();
    const openssl::EVP_MD *md = getOpenSSL_MD(algo);

    if(!md) {
        hasError = true;
        return;
    }

    context = EVP_MD_CTX_new();

    if(!context) {
        hasError = true;
        return;
    }
    if(!openssl::q_EVP_DigestInit_ex(context, md, 0)) {
        EVP_MD_CTX_free(context);
        context = 0;
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
    int rvalue = openssl::q_EVP_DigestUpdate(context, data.data(), data.size());
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
    int rvalue = openssl::q_EVP_DigestFinal_ex(context, (unsigned char*)finalData.data(), &len);
    if(!rvalue) {
        hasError = true;
        finalData.clear();
    } else {
        finalData.resize(len);
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

QTNETWORKNG_NAMESPACE_END
