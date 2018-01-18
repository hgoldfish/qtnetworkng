#include "../include/cipher.h"
#include "../include/crypto_p.h"
#include "../include/random.h"

QTNETWORKNG_NAMESPACE_BEGIN

const openssl::EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo);

const openssl::EVP_CIPHER *getOpenSSL_CIPHER(Cipher::Algorithm algo, Cipher::Mode mode)
{
    const openssl::EVP_CIPHER * cipher = NULL;
    switch(algo) {
    case Cipher::Null:
        cipher = openssl::q_EVP_enc_null();
        break;
    case Cipher::AES128:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_aes_128_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_aes_128_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_aes_128_cfb128();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_aes_128_ofb();
            break;
        case Cipher::CTR:
            cipher = openssl::q_EVP_aes_128_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::AES192:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_aes_192_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_aes_192_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_aes_192_cfb128();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_aes_192_ofb();
            break;
        case Cipher::CTR:
            cipher = openssl::q_EVP_aes_192_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::AES256:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_aes_256_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_aes_256_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_aes_256_cfb128();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_aes_256_ofb();
            break;
        case Cipher::CTR:
            cipher = openssl::q_EVP_aes_256_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_des_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_des_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_des_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_des_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES2:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_des_ede_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_des_ede_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_des_ede_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_des_ede_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES3:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_des_ede3_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_des_ede3_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_des_ede3_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_des_ede3_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::RC2:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_rc2_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_rc2_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_rc2_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_rc2_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::RC4:
        break;
    case Cipher::RC5:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_rc5_32_12_16_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_rc5_32_12_16_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_rc5_32_12_16_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_rc5_32_12_16_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::IDEA:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_idea_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_idea_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_idea_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_idea_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::Blowfish:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_bf_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_bf_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_bf_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_bf_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::CAST5:
        switch(mode) {
        case Cipher::ECB:
            cipher = openssl::q_EVP_cast5_ecb();
            break;
        case Cipher::CBC:
            cipher = openssl::q_EVP_cast5_cbc();
            break;
        case Cipher::CFB:
            cipher = openssl::q_EVP_cast5_cfb64();
            break;
        case Cipher::OFB:
            cipher = openssl::q_EVP_cast5_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::Chacha20:
        cipher = openssl::q_EVP_chacha20();
    default:
        Q_UNREACHABLE();
    }
    return cipher;
}

struct CipherPrivate
{
    CipherPrivate(Cipher::Algorithm algo, Cipher::Mode mode, Cipher::Operation operation);
    ~CipherPrivate();
    QByteArray addData(const QByteArray &data);
    QByteArray finalData();
    QPair<QByteArray, QByteArray> bytesToKey(const QByteArray &password,MessageDigest::Algorithm hashAlgo,
                                             const QByteArray &salt, int i);
    bool setPassword(const QByteArray &password,const MessageDigest::Algorithm hashAlgo,
                     const QByteArray &salt, int i);
    bool init();
    bool setPadding(bool padding);

    Cipher::Algorithm algo;
    Cipher::Mode mode;
    Cipher::Operation operation;
    openssl::EVP_CIPHER_CTX *context;
    const openssl::EVP_CIPHER *cipher;
    bool hasError;
    QByteArray key;
    QByteArray iv;
    bool inited;
    QByteArray salt;
};

CipherPrivate::CipherPrivate(Cipher::Algorithm algo, Cipher::Mode mode, Cipher::Operation operation)
    :algo(algo), mode(mode), operation(operation), context(0), cipher(0), hasError(false), inited(false)
{
    initOpenSSL();
    cipher = getOpenSSL_CIPHER(algo, mode);
    if(!cipher) {
        hasError = true;
        qFatal("cipher is not supported.");
        return;
    }

    context = openssl::q_EVP_CIPHER_CTX_new();
    if(!context) {
        hasError = true;
        return;
    }
}

CipherPrivate::~CipherPrivate()
{
    if(context) {
        openssl::q_EVP_CIPHER_CTX_free(context);
    }
}

bool CipherPrivate::init()
{
    if(inited || !context || !cipher || key.isEmpty())
        return false;
    int rvalue = openssl::q_EVP_CipherInit_ex(context, cipher, NULL, (unsigned char*) key.data(), (unsigned char*) iv.data(), operation == Cipher::Decrypt? 0 : 1);
    if(rvalue) {
        inited = true;
        return true;
    } else {
        return false;
    }
}

QPair<QByteArray, QByteArray> CipherPrivate::bytesToKey(const QByteArray &password,MessageDigest::Algorithm hashAlgo,
                                         const QByteArray &salt, int i)
{
    const openssl::EVP_MD *dgst = getOpenSSL_MD(hashAlgo);
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    if(hasError || !context || !cipher || !dgst || (!salt.isEmpty() && salt.size() != 8) || password.isEmpty() || i <= 0) {
        return qMakePair(QByteArray(), QByteArray());
    }
    const unsigned char *saltPtr = NULL;
    if(!salt.isEmpty()) {
        saltPtr = (unsigned char*) salt.data();
    }
    int rvalue = openssl::q_EVP_BytesToKey(cipher, dgst, saltPtr, (const unsigned char *) password.data(), password.size(), i, key, iv);
    if(rvalue) {
        int keylen = openssl::q_EVP_CIPHER_key_length(cipher);
        int ivlen = openssl::q_EVP_CIPHER_iv_length(cipher);
        if(keylen > 0 && ivlen >= 0) {
            return qMakePair(QByteArray((const char*) key, keylen), QByteArray((const char *) iv, ivlen));
        }
    }
    return qMakePair(QByteArray(), QByteArray());
}

QByteArray CipherPrivate::addData(const QByteArray &data)
{
    if(!context || !inited || hasError) {
        return QByteArray();
    }
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outl = 0;
    int rvalue = openssl::q_EVP_CipherUpdate(context, (unsigned char *) outbuf, &outl, (unsigned char *) data.data(), data.size());
    if(rvalue) {
        return QByteArray((const char *) outbuf, outl);
    } else {
        hasError = true;
        return QByteArray();
    }
}

QByteArray CipherPrivate::finalData()
{
    if(!context || !inited || hasError) {
        return QByteArray();
    }
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outl = 0;
    int rvalue = openssl::q_EVP_CipherFinal_ex(context, outbuf, &outl);
    if(rvalue) {
        return QByteArray((const char *) outbuf, outl);
    } else {
        hasError = true;
        return QByteArray();
    }
}

bool CipherPrivate::setPassword(const QByteArray &password,const MessageDigest::Algorithm hashAlgo,
                 const QByteArray &salt, int i)
{
    QByteArray s;
    if(salt.isEmpty()) {
        s = randomBytes(8);
    } else {
        if(salt.size() == 8) {
            s = salt;
        } else {
            return false;
        }
    }
    this->salt = s;
    const QPair<QByteArray, QByteArray> &t = bytesToKey(password, hashAlgo, s, i);
    key = t.first;
    iv = t.second;
    if(key.isEmpty()) {
        return false;
    }
    return init();
}

bool CipherPrivate::setPadding(bool padding)
{
    if(!context) {
        return false;
    }
    int rvalue = openssl::q_EVP_CIPHER_CTX_set_padding(context, padding ? 1 : 0);
    return rvalue == 1;
}

Cipher::Cipher(Cipher::Algorithm alog, Cipher::Mode mode, Cipher::Operation operation)
    :d_ptr(new CipherPrivate(alog, mode, operation))
{
}


Cipher::~Cipher()
{
    delete d_ptr;
}


QByteArray Cipher::addData(const QByteArray &data)
{
    Q_D(Cipher);
    return d->addData(data);
}


QByteArray Cipher::finalData()
{
    Q_D(Cipher);
    return d->finalData();
}


bool Cipher::setInitialVector(const QByteArray &iv)
{
    Q_D(Cipher);
    d->iv = iv;
    return d->init();
}


bool Cipher::setKey(const QByteArray &key)
{
    Q_D(Cipher);
    d->key = key;
    return d->init();
}


bool Cipher::setPassword(const QByteArray &password, const MessageDigest::Algorithm hashAlgo, const QByteArray &salt, int i)
{
    Q_D(Cipher);
    return d->setPassword(password, hashAlgo, salt, i);
}


QByteArray Cipher::saltHeader() const
{
    Q_D(const Cipher);
    if(d->salt.isEmpty()) {
        return QByteArray();
    } else {
        const QByteArray &saltHeader = QByteArray("Salted__") + d->salt;
        return saltHeader;
    }
}


QByteArray Cipher::salt() const
{
    Q_D(const Cipher);
    return d->salt;
}


QPair<QByteArray, QByteArray> parseSalt(const QByteArray &header)
{
    if(header.startsWith("Salted_") && header.size() >= 15) {
        const QByteArray &salt = header.mid(7, 8);
        const QByteArray &other = header.mid(15);
        return qMakePair(salt, other);
    } else {
        return qMakePair(QByteArray(), QByteArray());
    }
}


bool Cipher::setPadding(bool padding)
{
    Q_D(Cipher);
    return d->setPadding(padding);
}


QByteArray Cipher::key() const
{
    Q_D(const Cipher);
    return d->key;
}


QByteArray Cipher::initialVector() const
{
    Q_D(const Cipher);
    return d->iv;
}

QTNETWORKNG_NAMESPACE_END
