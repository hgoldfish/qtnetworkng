#include "../include/cipher.h"
#include "../include/private/crypto_p.h"
#include "../include/random.h"

QTNETWORKNG_NAMESPACE_BEGIN


const EVP_MD *getOpenSSL_MD(MessageDigest::Algorithm algo);

const EVP_CIPHER *getOpenSSL_CIPHER(Cipher::Algorithm algo, Cipher::Mode mode)
{
    const EVP_CIPHER * cipher = nullptr;
    switch (algo) {
    case Cipher::Null:
        cipher = EVP_enc_null();
        break;
    case Cipher::AES128:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_aes_128_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_aes_128_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_aes_128_cfb128();
            break;
        case Cipher::OFB:
            cipher = EVP_aes_128_ofb();
            break;
        case Cipher::CTR:
            cipher = EVP_aes_128_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::AES192:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_aes_192_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_aes_192_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_aes_192_cfb128();
            break;
        case Cipher::OFB:
            cipher = EVP_aes_192_ofb();
            break;
        case Cipher::CTR:
            cipher = EVP_aes_192_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::AES256:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_aes_256_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_aes_256_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_aes_256_cfb128();
            break;
        case Cipher::OFB:
            cipher = EVP_aes_256_ofb();
            break;
        case Cipher::CTR:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_des_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_des_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_des_cfb64();
            break;
        case Cipher::OFB:
            cipher = EVP_des_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES2:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_des_ede_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_des_ede_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_des_ede_cfb64();
            break;
        case Cipher::OFB:
            cipher = EVP_des_ede_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::DES3:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_des_ede3_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_des_ede3_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_des_ede3_cfb64();
            break;
        case Cipher::OFB:
            cipher = EVP_des_ede3_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::Blowfish:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_bf_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_bf_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_bf_cfb64();
            break;
        case Cipher::OFB:
            cipher = EVP_bf_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::CAST5:
        switch (mode) {
        case Cipher::ECB:
            cipher = EVP_cast5_ecb();
            break;
        case Cipher::CBC:
            cipher = EVP_cast5_cbc();
            break;
        case Cipher::CFB:
            cipher = EVP_cast5_cfb64();
            break;
        case Cipher::OFB:
            cipher = EVP_cast5_ofb();
            break;
        case Cipher::CTR:
        default:
            Q_UNREACHABLE();
        }
        break;
    case Cipher::Chacha20:
        cipher = EVP_chacha20();
        break;
//    case Cipher::ChaCha20Poly1305:
//        cipher = EVP_chacha20_poly1305();
//        break;
    default:
        break;
    }
    return cipher;
}


class CipherPrivate
{
public:
    CipherPrivate(Cipher::Algorithm algo, Cipher::Mode mode, Cipher::Operation operation);
    ~CipherPrivate();
    QByteArray addData(const char *data, int len);
    QByteArray finalData();
    QPair<QByteArray, QByteArray> bytesToKey(const QByteArray &password,MessageDigest::Algorithm hashAlgo,
                                             const QByteArray &salt, int i);
    QPair<QByteArray, QByteArray> PBKDF2_HMAC(const QByteArray &password, const QByteArray &salt,
                                              MessageDigest::Algorithm hashAlgo, int i);
    bool setPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo, int i);
    bool setOpensslPassword(const QByteArray &password, const QByteArray &salt,
                            const MessageDigest::Algorithm hashAlgo, int i);
    bool init();
    bool setPadding(bool padding);

    EVP_CIPHER_CTX *context;
    const EVP_CIPHER *cipher;
    QByteArray key;
    QByteArray iv;
    QByteArray salt;
    Cipher::Algorithm algo;
    Cipher::Mode mode;
    Cipher::Operation operation;
    bool hasError;
    bool inited;
    bool padding;
};


CipherPrivate::CipherPrivate(Cipher::Algorithm algo, Cipher::Mode mode, Cipher::Operation operation)
    :context(nullptr), cipher(nullptr), algo(algo), mode(mode), operation(operation), hasError(false), inited(false), padding(true)
{
    initOpenSSL();
    cipher = getOpenSSL_CIPHER(algo, mode);
    if (!cipher) {
        hasError = true;
        qWarning("cipher is not supported.");
        return;
    }

    context = EVP_CIPHER_CTX_new();
    if (!context) {
        hasError = true;
        return;
    }
    setPadding(true);
}


CipherPrivate::~CipherPrivate()
{
    if (context) {
        EVP_CIPHER_CTX_free(context);
    }
    cleanupOpenSSL();
}


bool CipherPrivate::init()
{
    if (inited || !context || !cipher || key.isEmpty() || iv.isEmpty() || hasError) {
        return false;
    }
    int rvalue = EVP_CipherInit_ex(context, cipher, nullptr,
                                   reinterpret_cast<unsigned char*>(key.data()),
                                   reinterpret_cast<unsigned char*>(iv.data()),
                                   operation == Cipher::Decrypt ? 0 : 1);
    if (rvalue) {
        inited = true;
        return true;
    } else {
        return false;
    }
}


QPair<QByteArray, QByteArray> CipherPrivate::bytesToKey(const QByteArray &password,
                                                        MessageDigest::Algorithm hashAlgo,
                                                        const QByteArray &salt, int i)
{
    const EVP_MD *dgst = getOpenSSL_MD(hashAlgo);
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    if (hasError || !context || !cipher || !dgst
            || (!salt.isEmpty() && salt.size() != 8) || password.isEmpty() || i <= 0) {
        return qMakePair(QByteArray(), QByteArray());
    }
    const unsigned char *saltPtr = nullptr;
    if (!salt.isEmpty()) {
        saltPtr = reinterpret_cast<const unsigned char*>(salt.data());
    }
    int rvalue = EVP_BytesToKey(cipher, dgst, saltPtr,
                                           reinterpret_cast<const unsigned char *>(password.data()),
                                           password.size(), i, key, iv);
    if (rvalue) {
        int keylen = EVP_CIPHER_key_length(cipher);
        int ivlen = EVP_CIPHER_iv_length(cipher);
        if(keylen > 0 && ivlen >= 0) {
            return qMakePair(QByteArray(reinterpret_cast<const char*>(key), keylen), QByteArray(reinterpret_cast<const char *>(iv), ivlen));
        }
    }
    return qMakePair(QByteArray(), QByteArray());
}


QPair<QByteArray, QByteArray> CipherPrivate::PBKDF2_HMAC(const QByteArray &password, const QByteArray &salt,
                                                         MessageDigest::Algorithm hashAlgo, int i)
{
    const EVP_MD *dgst = getOpenSSL_MD(hashAlgo);
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    if (hasError || !context || !cipher || !dgst || salt.isEmpty() || password.isEmpty() || i <= 0) {
        return qMakePair(QByteArray(), QByteArray());
    }
    int keylen = EVP_CIPHER_key_length(cipher);
    int ivlen = EVP_CIPHER_iv_length(cipher);
    if (keylen > 0 && ivlen > 0) {
        int rvalue = PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                                                  reinterpret_cast<const unsigned char*>(salt.data()),
                                                  salt.size(), i, dgst, keylen, key);
        if (rvalue) {
            rvalue = PKCS5_PBKDF2_HMAC(password.data(), password.size(),
                    key, keylen, i, dgst, ivlen, iv);
            if (rvalue) {
                return qMakePair(QByteArray(reinterpret_cast<const char*>(key), keylen), QByteArray(reinterpret_cast<const char *>(iv), ivlen));
            }
        }
    }
    return qMakePair(QByteArray(), QByteArray());
}


QByteArray CipherPrivate::addData(const char *data, int len)
{
    if (!context || !inited || hasError) {
        return QByteArray();
    }
    QByteArray out;
    out.resize(len + EVP_MAX_BLOCK_LENGTH);
    int outl = 0;
    int rvalue = EVP_CipherUpdate(context, reinterpret_cast<unsigned char *>(out.data()), &outl,
                                             reinterpret_cast<const unsigned char *>(data), len);
    if (rvalue) {
        out.resize(outl);
        return out;
    } else {
        hasError = true;
        return QByteArray();
    }
}


QByteArray CipherPrivate::finalData()
{
    if (!context || !inited || hasError) {
        return QByteArray();
    }
    QByteArray out;
    out.resize(1024 + EVP_MAX_BLOCK_LENGTH);
    int outl = 0;
    int rvalue = EVP_CipherFinal_ex(context, reinterpret_cast<unsigned char *>(out.data()), &outl);
    if (rvalue) {
        out.resize(outl);
        return out;
    } else {
        hasError = true;
        return QByteArray();
    }
}


bool CipherPrivate::setPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo, int i)
{
    QByteArray s;
    if (salt.isEmpty()) {
        s = randomBytes(32);
    } else {
        s = salt;
    }
    this->salt = s;
    const QPair<QByteArray, QByteArray> &t = PBKDF2_HMAC(password, s, hashAlgo, i);
    key = t.first;
    iv = t.second;
    if(key.isEmpty()) {
        return false;
    }
    return init();
}


bool CipherPrivate::setOpensslPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo, int i)
{
    QByteArray s;
    if (salt.isEmpty()) {
        s = randomBytes(8);
    } else {
        if (salt.size() == 8) {
            s = salt;
        } else {
            qWarning("setOpensslPassword() require the length of salt is 8.");
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
    if (!context) {
        return false;
    }
    int rvalue = EVP_CIPHER_CTX_set_padding(context, padding ? 1 : 0);
    if (rvalue == 1) {
        this->padding = padding;
        return true;
    } else {
        return false;
    }
}


Cipher::Cipher(Cipher::Algorithm alog, Cipher::Mode mode, Cipher::Operation operation)
    :d_ptr(new CipherPrivate(alog, mode, operation))
{
}


Cipher::~Cipher()
{
    delete d_ptr;
}


Cipher *Cipher::copy(Cipher::Operation operation)
{
    Q_D(Cipher);
    if (!isValid()) {
        return nullptr;
    }
    Cipher *newOne = new Cipher(d->algo, d->mode, operation);
    newOne->setKey(d->key);
    newOne->setInitialVector(d->iv);
    if (!d->padding) {
        newOne->setPadding(d->padding);
    }
    return newOne;
}


bool Cipher::isValid() const
{
    Q_D(const Cipher);
    return d->cipher && d->context && !d->hasError && d->inited;
}

bool Cipher::isStream() const
{
    Q_D(const Cipher);
    switch (d->algo) {
    case AES128:
    case AES192:
    case AES256:
    case DES:
    case DES2:
    case DES3:
    case Blowfish:
        switch (d->mode) {
        case ECB:
        case CBC:
            return false;
        case CFB:
        case OFB:
        case CTR:
        case OPENPGP:
            return true;
        }
    case Null:
    case CAST5:
    case Chacha20:
    case ChaCha20Poly1305:
        return true;
    }
    return false;
}


QByteArray Cipher::addData(const char *data, int len)
{
    Q_D(Cipher);
    return d->addData(data, len);
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


bool Cipher::setPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo, int i)
{
    Q_D(Cipher);
    return d->setPassword(password, salt, hashAlgo, i);
}


bool Cipher::setOpensslPassword(const QByteArray &password, const QByteArray &salt, const MessageDigest::Algorithm hashAlgo, int i)
{
    Q_D(Cipher);
    return d->setOpensslPassword(password, salt, hashAlgo, i);
}


QByteArray Cipher::saltHeader() const
{
    Q_D(const Cipher);
    if (d->salt.isEmpty()) {
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


QPair<QByteArray, QByteArray> Cipher::parseSalt(const QByteArray &header)
{
    if (header.startsWith("Salted_") && header.size() >= 15) {
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


bool Cipher::padding() const
{
    Q_D(const Cipher);
    return d->padding;
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


int Cipher::keySize() const
{
    Q_D(const Cipher);
    int keylen = EVP_CIPHER_key_length(d->cipher);
    return keylen;
}


int Cipher::ivSize() const
{
    Q_D(const Cipher);
    int ivlen = EVP_CIPHER_iv_length(d->cipher);
    return ivlen;
}


int Cipher::blockSize() const
{
    Q_D(const Cipher);
    int blockSize = EVP_CIPHER_block_size(d->cipher);
    return blockSize;
}


QTNETWORKNG_NAMESPACE_END
