#include <QtCore/qdebug.h>
#include <QtCore/qdatastream.h>
#include "../include/certificate.h"
#include "../include/openssl_symbols.h"
#include "../include/qasn1element.h"
#include "../include/crypto_p.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct X509Cleaner
{
    static inline void cleanup(openssl::X509 *x) { if(x) openssl::q_X509_free(x); }
};

struct CertificatePrivate: public QSharedData
{
    CertificatePrivate() {}
    CertificatePrivate(const CertificatePrivate &) = default;

    bool isNull() const;
    QDateTime effectiveDate() const;
    QDateTime expiryDate() const;
    bool isBlacklisted() const;
    bool isSelfSigned() const;
    QStringList issuerInfo(Certificate::SubjectInfo subject) const;
    QStringList issuerInfo(const QByteArray &attribute) const;
    QList<QByteArray> issuerInfoAttributes() const;
    PublicKey publicKey() const;
    QByteArray serialNumber() const;
    QStringList subjectInfo(Certificate::SubjectInfo subjec) const;
    QStringList subjectInfo(const QByteArray &attribute) const;
    QList<QByteArray> subjectInfoAttributes() const;
    QString toString() const;
    QByteArray version() const;

    QByteArray save(Ssl::EncodingFormat format) const;
    static Certificate load(const QByteArray &data, Ssl::EncodingFormat format);
    static Certificate generate(const PrivateKey &key, MessageDigest::Algorithm signAlgo,
                                      long serialNumber, const QDateTime &effectiveDate,
                                      const QDateTime &expiryDate, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes);
    static QByteArray subjectInfoToString(Certificate::SubjectInfo info);
    static inline bool setX509(Certificate *cert, openssl::X509 *x509);

    bool init(openssl::X509 *x509);
    bool qtParse();

    QSharedPointer<openssl::X509> x509;
    QMap<QByteArray, QString> issuerInfoMap;
    QMap<QByteArray, QString> subjectInfoMap;
    QByteArray versionString;
    QDateTime notValidBefore;
    QDateTime notValidAfter;
};


static QByteArray asn1ObjectId(openssl::ASN1_OBJECT *object)
{
    char buf[80]; // The openssl docs a buffer length of 80 should be more than enough
    openssl::q_OBJ_obj2txt(buf, sizeof(buf), object, 1); // the 1 says always use the oid not the long name

    return QByteArray(buf);
}

static QByteArray asn1ObjectName(openssl::ASN1_OBJECT *object)
{
    int nid = openssl::q_OBJ_obj2nid(object);
    if (nid != NID_undef)
        return QByteArray(openssl::q_OBJ_nid2sn(nid));

    return asn1ObjectId(object);
}

static QMap<QByteArray, QString> _q_mapFromX509Name(openssl::X509_NAME *name)
{
    QMap<QByteArray, QString> info;
    for (int i = 0; i < openssl::q_X509_NAME_entry_count(name); ++i) {
        openssl::X509_NAME_ENTRY *e = openssl::q_X509_NAME_get_entry(name, i);

        QByteArray name = asn1ObjectName(q_X509_NAME_ENTRY_get_object(e));
        unsigned char *data = 0;
        int size = openssl::q_ASN1_STRING_to_UTF8(&data, openssl::q_X509_NAME_ENTRY_get_data(e));
        info.insertMulti(name, QString::fromUtf8((char*)data, size));
        openssl::q_CRYPTO_free(data);
    }

    return info;
}

bool CertificatePrivate::init(openssl::X509 *x)
{
    if(!x)
        return false;
    this->x509.reset(x, openssl::q_X509_free);

    int parsed = 0; // 0 for never parsed, -1 for failed, and 1 for success.
    openssl::ASN1_TIME *t = openssl::q_X509_getm_notBefore(x);
    if(t) {
        notValidBefore = openssl::q_getTimeFromASN1(t);
    } else {
        parsed = qtParse() ? 1 : -1;
    }
    t = openssl::q_X509_getm_notAfter(x);
    if(t) {
        notValidAfter = openssl::q_getTimeFromASN1(t);
    } else if(parsed == 0) {
        parsed = qtParse() ? 1 : -1;
    }
    int version = qlonglong(openssl::q_X509_get_version(x));
    if(version >= 0) {
        versionString = QByteArray::number(version);
    } else if(parsed == 0){
        parsed = qtParse() ? 1 : -1;
    }

    issuerInfoMap = _q_mapFromX509Name(openssl::q_X509_get_issuer_name(x));
    subjectInfoMap = _q_mapFromX509Name(openssl::q_X509_get_subject_name(x));
    return parsed != -1;
}

bool CertificatePrivate::setX509(Certificate *cert, openssl::X509 *x)
{
    if(!x || !cert)
        return false;
    return cert->d->init(openssl::q_X509_dup(x));
}

bool openssl_setCertificate(Certificate *cert, openssl::X509 *x509)
{
    return CertificatePrivate::setX509(cert, x509);
}

bool CertificatePrivate::isNull() const
{
    return x509.isNull();
}

QDateTime CertificatePrivate::effectiveDate() const
{
    return notValidBefore;
}

QDateTime CertificatePrivate::expiryDate() const
{
    return notValidAfter;
}


// These certificates are known to be fraudulent and were created during the comodo
// compromise. See http://www.comodo.com/Comodo-Fraud-Incident-2011-03-23.html
static const char *const certificate_blacklist[] = {
    "04:7e:cb:e9:fc:a5:5f:7b:d0:9e:ae:36:e1:0c:ae:1e", "mail.google.com", // Comodo
    "f5:c8:6a:f3:61:62:f1:3a:64:f5:4f:6d:c9:58:7c:06", "www.google.com", // Comodo
    "d7:55:8f:da:f5:f1:10:5b:b2:13:28:2b:70:77:29:a3", "login.yahoo.com", // Comodo
    "39:2a:43:4f:0e:07:df:1f:8a:a3:05:de:34:e0:c2:29", "login.yahoo.com", // Comodo
    "3e:75:ce:d4:6b:69:30:21:21:88:30:ae:86:a8:2a:71", "login.yahoo.com", // Comodo
    "e9:02:8b:95:78:e4:15:dc:1a:71:0a:2b:88:15:44:47", "login.skype.com", // Comodo
    "92:39:d5:34:8f:40:d1:69:5a:74:54:70:e1:f2:3f:43", "addons.mozilla.org", // Comodo
    "b0:b7:13:3e:d0:96:f9:b5:6f:ae:91:c8:74:bd:3a:c0", "login.live.com", // Comodo
    "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0", "global trustee", // Comodo

    "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56", "*.google.com", // leaf certificate issued by DigiNotar
    "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c", "DigiNotar Root CA", // DigiNotar root
    "f1:4a:13:f4:87:2b:56:dc:39:df:84:ca:7a:a1:06:49", "DigiNotar Services CA", // DigiNotar intermediate signed by DigiNotar Root
    "36:16:71:55:43:42:1b:9d:e6:cb:a3:64:41:df:24:38", "DigiNotar Services 1024 CA", // DigiNotar intermediate signed by DigiNotar Root
    "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e", "DigiNotar Root CA G2", // other DigiNotar Root CA
    "a4:b6:ce:e3:2e:d3:35:46:26:3c:b3:55:3a:a8:92:21", "CertiID Enterprise Certificate Authority", // DigiNotar intermediate signed by "DigiNotar Root CA G2"
    "5b:d5:60:9c:64:17:68:cf:21:0e:35:fd:fb:05:ad:41", "DigiNotar Qualified CA", // DigiNotar intermediate signed by DigiNotar Root

    "46:9c:2c:b0",                                     "DigiNotar Services 1024 CA", // DigiNotar intermediate cross-signed by Entrust
    "07:27:10:0d",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:0f:f9",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:10:03",                                     "DigiNotar Cyber CA", // DigiNotar intermediate cross-signed by CyberTrust
    "01:31:69:b0",                                     "DigiNotar PKIoverheid CA Overheid en Bedrijven", // DigiNotar intermediate cross-signed by the Dutch government
    "01:31:34:bf",                                     "DigiNotar PKIoverheid CA Organisatie - G2", // DigiNotar intermediate cross-signed by the Dutch government
    "d6:d0:29:77:f1:49:fd:1a:83:f2:b9:ea:94:8c:5c:b4", "DigiNotar Extended Validation CA", // DigiNotar intermediate signed by DigiNotar EV Root
    "1e:7d:7a:53:3d:45:30:41:96:40:0f:71:48:1f:45:04", "DigiNotar Public CA 2025", // DigiNotar intermediate
//    "(has not been seen in the wild so far)", "DigiNotar Public CA - G2", // DigiNotar intermediate
//    "(has not been seen in the wild so far)", "Koninklijke Notariele Beroepsorganisatie CA", // compromised during DigiNotar breach
//    "(has not been seen in the wild so far)", "Stichting TTP Infos CA," // compromised during DigiNotar breach
    "46:9c:2c:af",                                     "DigiNotar Root CA", // DigiNotar intermediate cross-signed by Entrust
    "46:9c:3c:c9",                                     "DigiNotar Root CA", // DigiNotar intermediate cross-signed by Entrust

    "07:27:14:a9",                                     "Digisign Server ID (Enrich)", // (Malaysian) Digicert Sdn. Bhd. cross-signed by Verizon CyberTrust
    "4c:0e:63:6a",                                     "Digisign Server ID - (Enrich)", // (Malaysian) Digicert Sdn. Bhd. cross-signed by Entrust
    "72:03:21:05:c5:0c:08:57:3d:8e:a5:30:4e:fe:e8:b0", "UTN-USERFirst-Hardware", // comodogate test certificate
    "41",                                              "MD5 Collisions Inc. (http://www.phreedom.org/md5)", // http://www.phreedom.org/research/rogue-ca/

    "08:27",                                           "*.EGO.GOV.TR", // Turktrust mis-issued intermediate certificate
    "08:64",                                           "e-islem.kktcmerkezbankasi.org", // Turktrust mis-issued intermediate certificate

    "03:1d:a7",                                        "AC DG Tr\xC3\xA9sor SSL", // intermediate certificate linking back to ANSSI French National Security Agency
    "27:83",                                           "NIC Certifying Authority", // intermediate certificate from NIC India (2007)
    "27:92",                                           "NIC CA 2011", // intermediate certificate from NIC India (2011)
    "27:b1",                                           "NIC CA 2014", // intermediate certificate from NIC India (2014)
    0
};


bool CertificatePrivate::isBlacklisted() const
{
    if(x509.isNull())
        return false;
    for (int a = 0; certificate_blacklist[a] != 0; a++) {
        QString blacklistedCommonName = QString::fromUtf8(certificate_blacklist[(a+1)]);
        if (serialNumber() == certificate_blacklist[a++] &&
            (subjectInfo(Certificate::CommonName).contains(blacklistedCommonName) ||
             issuerInfo(Certificate::CommonName).contains(blacklistedCommonName)))
            return true;
    }
    return false;
}

bool CertificatePrivate::isSelfSigned() const
{
    if(x509.isNull())
        return false;
    return (openssl::q_X509_check_issued(x509.data(), x509.data()) == X509_V_OK);
}


QByteArray CertificatePrivate::subjectInfoToString(Certificate::SubjectInfo info)
{
    QByteArray str;
    switch (info) {
    case Certificate::Organization: str = QByteArray("O"); break;
    case Certificate::CommonName: str = QByteArray("CN"); break;
    case Certificate::LocalityName: str = QByteArray("L"); break;
    case Certificate::OrganizationalUnitName: str = QByteArray("OU"); break;
    case Certificate::CountryName: str = QByteArray("C"); break;
    case Certificate::StateOrProvinceName: str = QByteArray("ST"); break;
    case Certificate::DistinguishedNameQualifier: str = QByteArray("dnQualifier"); break;
    case Certificate::SerialNumber: str = QByteArray("serialNumber"); break;
    case Certificate::EmailAddress: str = QByteArray("emailAddress"); break;
    }
    return str;
}

QStringList CertificatePrivate::issuerInfo(Certificate::SubjectInfo subject) const
{
    if(x509.isNull())
        return QStringList();
    return issuerInfoMap.values(subjectInfoToString(subject));
}

QStringList CertificatePrivate::issuerInfo(const QByteArray &attribute) const
{
    if(x509.isNull())
        return QStringList();
    return issuerInfoMap.values(attribute);
}

QList<QByteArray> CertificatePrivate::issuerInfoAttributes() const
{
    if(x509.isNull())
        return QList<QByteArray>();
    return issuerInfoMap.uniqueKeys();
}

PublicKey CertificatePrivate::publicKey() const
{
    PublicKey key;
    if(!x509.isNull()) {
        openssl::EVP_PKEY *pkey = openssl::q_X509_get_pubkey(x509.data());
        if(pkey) {
            openssl_setPkey(&key, pkey, false);
        }
    }
    return key;
}

QByteArray CertificatePrivate::serialNumber() const
{
    openssl::ASN1_INTEGER *serialNumber = openssl::q_X509_get_serialNumber(x509.data());
    if(serialNumber) {
        qlonglong n = openssl::q_ASN1_INTEGER_get(serialNumber);
        if(n) {
            return QByteArray::number(n);
        }
    }
    return QByteArray();
}


QStringList CertificatePrivate::subjectInfo(Certificate::SubjectInfo subject) const
{
    return subjectInfoMap.values(subjectInfoToString(subject));
}

QStringList CertificatePrivate::subjectInfo(const QByteArray &attribute) const
{
    return subjectInfoMap.values(attribute);
}

QList<QByteArray> CertificatePrivate::subjectInfoAttributes() const
{
    return subjectInfoMap.uniqueKeys();
}

QByteArray CertificatePrivate::version() const
{
    return versionString;
}

struct BioCleaner
{
    static void inline cleanup(openssl::BIO *o) { if(o) openssl::q_BIO_free(o); }
};

QString CertificatePrivate::toString() const
{
    if(x509.isNull()) {
        return QString();
    }
    QByteArray result;
    QScopedPointer<openssl::BIO, BioCleaner> bio(openssl::q_BIO_new(openssl::q_BIO_s_mem()));
    if (bio.isNull())
        return QString();

    // FIXME I have got nothing.
    openssl::q_X509_print(bio.data(), x509.data());

    QVarLengthArray<char, 1024 * 64> data;
    int count = openssl::q_BIO_read(bio.data(), data.data(), data.size());
    if (count > 0) {
        result = QByteArray(data.data(), count);
    }
    return QString::fromLatin1(result);
}

QByteArray CertificatePrivate::save(Ssl::EncodingFormat format) const
{
    if(x509.isNull()) {
        return QByteArray();
    }

    if(format == Ssl::Pem) {
        QSharedPointer<openssl::BIO> bio(openssl::q_BIO_new(openssl::q_BIO_s_mem()), openssl::q_BIO_free);
        if(bio.isNull()) {
            return QByteArray();
        }
        int r = openssl::q_PEM_write_bio_X509(bio.data(), x509.data());
        if(r) {
            char *p = NULL;
            int size = openssl::q_BIO_get_mem_data(bio.data(), &p);
            if(size > 0 && p != NULL) {
                return QByteArray(p, size);
            }
        }
    } else if(format == Ssl::Der) {
        unsigned char *buf = NULL;
        int len = openssl::q_i2d_X509(x509.data(), &buf);
        if(len > 0) {
            return QByteArray((char*) buf, len);
        }
    }
    return QByteArray();
}


Certificate CertificatePrivate::load(const QByteArray &data, Ssl::EncodingFormat format)
{
    Certificate cert;
    if(format == Ssl::Pem) {
        QSharedPointer<openssl::BIO> bio(openssl::q_BIO_new_mem_buf(data.data(), data.size()), openssl::q_BIO_free);
        if(bio.isNull()) {
            return cert;
        }
        openssl::X509 *x = NULL;
        openssl::q_PEM_read_bio_X509(bio.data(), &x, NULL, NULL);
        if(x) {
            cert.d->init(x);
        }
    } else if (format == Ssl::Der) {
        const unsigned char *buf;
        buf = (const unsigned char *) data.constData();
        int len = data.size();
        openssl::X509 *x = openssl::q_d2i_X509(NULL, &buf, len);
        if(x) {
            cert.d->init(x);
        }
        return cert;
    }
    return cert;
}

static bool setIssuerInfos(openssl::X509 *x, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    openssl::X509_NAME *name = openssl::q_X509_get_issuer_name(x);
    if(!name) {
        return false;
    }
    QMap<Certificate::SubjectInfo, QByteArray> table = {
        {Certificate::Organization, "O" },
        {Certificate::CommonName, "CN" },
        {Certificate::LocalityName, "L" },
        {Certificate::OrganizationalUnitName, "OU" },
        {Certificate::CountryName, "C" },
        {Certificate::StateOrProvinceName, "ST" },
        {Certificate::DistinguishedNameQualifier, "dnQualifier" },
        {Certificate::SerialNumber, "serialNumber" },
//        {Certificate::EmailAddress, "emailAddress" },

    };
    bool success = true;
    for(QMap<Certificate::SubjectInfo, QByteArray>::const_iterator itor = table.constBegin(); itor != table.constEnd(); ++itor) {
        const QStringList &sl = subjectInfoes.values(itor.key());
        foreach(const QString &s, sl) {
            QByteArray bs = s.toUtf8();
            success = success && openssl::q_X509_NAME_add_entry_by_txt(name, itor.value().data(), MBSTRING_UTF8,
                                                                       (const unsigned char *)bs.constData(),
                                                                       bs.size(), -1, 0);
        }
    }
    if(!success) {
        return false;
    }
    int r = openssl::q_X509_set_issuer_name(x, name);
    return r;
}

static bool setSubjectInfos(openssl::X509 *x, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    openssl::X509_NAME *name = openssl::q_X509_get_subject_name(x);
    if(!name) {
        return false;
    }
    QMap<Certificate::SubjectInfo, QByteArray> table = {
        {Certificate::Organization, "O" },
        {Certificate::CommonName, "CN" },
        {Certificate::LocalityName, "L" },
        {Certificate::OrganizationalUnitName, "OU" },
        {Certificate::CountryName, "C" },
        {Certificate::StateOrProvinceName, "ST" },
        {Certificate::DistinguishedNameQualifier, "dnQualifier" },
        {Certificate::SerialNumber, "serialNumber" },
//        {Certificate::EmailAddress, "emailAddress" },

    };
    bool success = true;
    for(QMap<Certificate::SubjectInfo, QByteArray>::const_iterator itor = table.constBegin(); itor != table.constEnd(); ++itor) {
        const QStringList &sl = subjectInfoes.values(itor.key());
        foreach(const QString &s, sl) {
            QByteArray bs = s.toUtf8();
            success = success && openssl::q_X509_NAME_add_entry_by_txt(name, itor.value().data(), MBSTRING_UTF8,
                                                                       (const unsigned char *)bs.constData(),
                                                                       bs.size(), -1, 0);
        }
    }
    if(!success) {
        return false;
    }
    int r  = openssl::q_X509_set_subject_name(x, name);
    return r;
}

std::string toText(const QDateTime &t)
{
    return (t.toUTC().toString("yyyyMMddhhmms") + QStringLiteral("Z")).toStdString();
}

struct Asn1TimeCleaner
{
    static void inline cleanup(openssl::ASN1_TIME *t)
    {
        if(t) openssl::q_ASN1_STRING_free(t);
    }
};

Certificate CertificatePrivate::generate(const PrivateKey &key, MessageDigest::Algorithm signAlgo,
                                  long serialNumber, const QDateTime &effectiveDate,
                                  const QDateTime &expiryDate, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    Certificate cert;
    QScopedPointer<openssl::X509, X509Cleaner> x509(openssl::q_X509_new());
    if(x509.isNull()) {
        qDebug() << "can not allocate X509.";
        return cert;
    }
    int r = openssl::q_X509_set_version(x509.data(), 2);
    openssl::ASN1_INTEGER *i = openssl::q_X509_get_serialNumber(x509.data());
    if(!r || !i) {
        qDebug() << "can not set version and serial number.";
        return cert;
    }
    openssl::q_ASN1_INTEGER_set(i, serialNumber);
    openssl::q_X509_set_pubkey(x509.data(), static_cast<openssl::EVP_PKEY*>(key.handle()));
    if(!setSubjectInfos(x509.data(), subjectInfoes)) {
        qDebug() << "can not set subject infos.";
        return cert;
    }
    if(!setIssuerInfos(x509.data(), subjectInfoes)) {
        qDebug() << "can not set issuer infos.";
        return cert;
    }
    //FIXME set datetime
    QScopedPointer<openssl::ASN1_TIME, Asn1TimeCleaner> t(openssl::q_ASN1_TIME_new());
    if(!t.isNull()) {
        r = openssl::q_ASN1_TIME_set_string(t.data(), toText(effectiveDate).c_str());
        if(r) {
            r = openssl::q_X509_set_notBefore(x509.data(), t.data());
            if(!r) {
                qDebug() << "can not set effective date.";
            }
        } else {
            qDebug() << "invalid x509 effective date:" << effectiveDate;
        }
        r = openssl::q_ASN1_TIME_set_string(t.data(), toText(expiryDate).c_str());
        if(r) {
            r = openssl::q_X509_set_notAfter(x509.data(), t.data());
            if(!r) {
                qDebug() << "can not set expiry date";
            }
        } else {
            qDebug() << "invalid x509 expiry date:" << expiryDate;
        }
    }
    const openssl::EVP_MD *md = getOpenSSL_MD(signAlgo);
    if(!md) {
        qDebug() << "can not find md.";
        return cert;
    }
    r = openssl::q_X509_sign(x509.data(), static_cast<openssl::EVP_PKEY*>(key.handle()), md);
    if(!r) {
        qDebug() << "can not sign certificate.";
        return cert;
    }
    cert.d->init(x509.take());
    return cert;
}

inline char toHexLower(uint value)
{
    return "0123456789abcdef"[value & 0xF];
}

QByteArray toHex(const QByteArray &bs, char separator)
{
    if(bs.isEmpty()) {
        return QByteArray();
    }

    const int length = separator ? (bs.size() * 3 - 1) : (bs.size() * 2);
    QByteArray hex;
    hex.resize(length);
    char *hexData = hex.data();
    const uchar *data = (const uchar *)bs.data();
    for (int i = 0, o = 0; i < bs.size(); ++i) {
        hexData[o++] = toHexLower(data[i] >> 4);
        hexData[o++] = toHexLower(data[i] & 0xf);

        if ((separator) && (o < length))
            hexData[o++] = separator;
    }
    return hex;
}

static QByteArray colonSeparatedHex(const QByteArray &value)
{
    const int size = value.size();
    int i = 0;
    while (i < size && !value.at(i)) // skip leading zeros
       ++i;

    return toHex(value.mid(i), ':');
}

bool CertificatePrivate::qtParse()
{
    const QByteArray &data = save(Ssl::Der);
    QAsn1Element root;

    QDataStream dataStream(data);
    if (!root.read(dataStream) || root.type() != QAsn1Element::SequenceType) {
        return false;
    }

    QDataStream rootStream(root.value());
    QAsn1Element cert;
    if (!cert.read(rootStream) || cert.type() != QAsn1Element::SequenceType) {
        return false;
    }

    // version or serial number
    QAsn1Element elem;
    QDataStream certStream(cert.value());
    if (!elem.read(certStream)) {
        return false;
    }

    if (elem.type() == QAsn1Element::Context0Type) {
        QDataStream versionStream(elem.value());
        if (!elem.read(versionStream) || elem.type() != QAsn1Element::IntegerType) {
            return false;
        }

        versionString = QByteArray::number(elem.value().at(0) + 1);
        if (!elem.read(certStream)) {
            return false;
        }
    } else {
        versionString = QByteArray::number(1);
    }

    // serial number
    if (elem.type() != QAsn1Element::IntegerType) {
        return false;
    }
    QByteArray serialNumberString = colonSeparatedHex(elem.value());
    Q_UNUSED(serialNumberString);

    // algorithm ID
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    // issuer info
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    QByteArray issuerDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    Q_UNUSED(issuerDer);
//    issuerInfoMap = elem.toInfo();

    // validity period
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    QDataStream validityStream(elem.value());
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType)) {
        return false;
    }

    notValidBefore = elem.toDateTime();
    if (!elem.read(validityStream) || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType)) {
        return false;
    }

    notValidAfter = elem.toDateTime();

    // we don't care about other informations.
    /*
    // subject name
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    QByteArray subjectDer = data.mid(dataStream.device()->pos() - elem.value().length(), elem.value().length());
    subjectInfo = elem.toInfo();
    subjectMatchesIssuer = issuerDer == subjectDer;

    // public key
    qint64 keyStart = certStream.device()->pos();
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType)
        return false;

    publicKeyDerData.resize(certStream.device()->pos() - keyStart);
    QDataStream keyStream(elem.value());
    if (!elem.read(keyStream) || elem.type() != QAsn1Element::SequenceType)
        return false;


    // key algorithm
    if (!elem.read(elem.value()) || elem.type() != QAsn1Element::ObjectIdentifierType)
        return false;

    const QByteArray oid = elem.toObjectId();
    if (oid == RSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Rsa;
    else if (oid == DSA_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Dsa;
    else if (oid == EC_ENCRYPTION_OID)
        publicKeyAlgorithm = QSsl::Ec;
    else
        publicKeyAlgorithm = QSsl::Opaque;

    certStream.device()->seek(keyStart);
    certStream.readRawData(publicKeyDerData.data(), publicKeyDerData.size());

    // extensions
    while (elem.read(certStream)) {
        if (elem.type() == QAsn1Element::Context3Type) {
            if (elem.read(elem.value()) && elem.type() == QAsn1Element::SequenceType) {
                QDataStream extStream(elem.value());
                while (elem.read(extStream) && elem.type() == QAsn1Element::SequenceType) {
                    QSslCertificateExtension extension;
                    if (!parseExtension(elem.value(), &extension))
                        return false;
                    extensions << extension;

                    if (extension.oid() == QLatin1String("2.5.29.17")) {
                        // subjectAltName
                        QAsn1Element sanElem;
                        if (sanElem.read(extension.value().toByteArray()) && sanElem.type() == QAsn1Element::SequenceType) {
                            QDataStream nameStream(sanElem.value());
                            QAsn1Element nameElem;
                            while (nameElem.read(nameStream)) {
                                if (nameElem.type() == QAsn1Element::Rfc822NameType) {
                                    subjectAlternativeNames.insert(QSsl::EmailEntry, nameElem.toString());
                                } else if (nameElem.type() == QAsn1Element::DnsNameType) {
                                    subjectAlternativeNames.insert(QSsl::DnsEntry, nameElem.toString());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    derData = data.left(dataStream.device()->pos());
    null = false;
    */
    return true;
}


Certificate::Certificate()
    :d(new CertificatePrivate)
{
    initOpenSSL();
}

Certificate::Certificate(const Certificate &other)
    :d(other.d)
{
}

Certificate::Certificate(Certificate &&other)
    :d(0)
{
    qSwap(d, other.d);
}

Certificate::~Certificate()
{
}

Certificate &Certificate::operator=(const Certificate &other)
{
    d = other.d;
    return *this;
}

bool Certificate::isNull() const
{
    return d->isNull();
}

QByteArray Certificate::digest(MessageDigest::Algorithm algorithm) const
{
    return MessageDigest::hash(save(Ssl::Der), algorithm);
}

QDateTime Certificate::effectiveDate() const
{
    return d->effectiveDate();
}

QDateTime Certificate::expiryDate() const
{
    return d->expiryDate();
}

Qt::HANDLE Certificate::handle() const
{
    return static_cast<Qt::HANDLE>(d->x509.data());
}

bool Certificate::isBlacklisted() const
{
    return d->isBlacklisted();
}

bool Certificate::isSelfSigned() const
{
    return d->isSelfSigned();
}

QStringList Certificate::issuerInfo(SubjectInfo subject) const
{
    return d->issuerInfo(subject);
}

QStringList Certificate::issuerInfo(const QByteArray &attribute) const
{
    return d->issuerInfo(attribute);
}

QList<QByteArray> Certificate::issuerInfoAttributes() const
{
    return d->issuerInfoAttributes();
}

PublicKey Certificate::publicKey() const
{
    return d->publicKey();
}

QByteArray Certificate::serialNumber() const
{
    return d->serialNumber();
}

QStringList Certificate::subjectInfo(SubjectInfo subject) const
{
    return d->subjectInfo(subject);
}

QStringList Certificate::subjectInfo(const QByteArray &attribute) const
{
    return d->subjectInfo(attribute);
}

QList<QByteArray> Certificate::subjectInfoAttributes() const
{
    return d->subjectInfoAttributes();
}

QString Certificate::toString() const
{
    return d->toString();
}

QByteArray Certificate::version() const
{
    return d->version();
}


QByteArray Certificate::save(Ssl::EncodingFormat format) const
{
    return d->save(format);
}

Certificate Certificate::load(const QByteArray& data, Ssl::EncodingFormat format)
{
    return CertificatePrivate::load(data, format);
}

Certificate Certificate::generate(const PrivateKey &key, MessageDigest::Algorithm signAlgo,
                                  long serialNumber, const QDateTime &effectiveDate,
                                  const QDateTime &expiryDate, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    return CertificatePrivate::generate(key, signAlgo, serialNumber, effectiveDate, expiryDate, subjectInfoes);
}


bool Certificate::operator==(const Certificate &other) const
{
    if (d->x509 && other.d->x509)
        return openssl::q_X509_cmp(d->x509.data(), other.d->x509.data()) == 0;
    return false;
}

QDebug &operator<<(QDebug &debug, const Certificate &certificate)
{
    QDebugStateSaver saver(debug); Q_UNUSED(saver);
    debug.resetFormat().nospace();
    debug << "Certificate("
          << certificate.version()
          << ", " << certificate.serialNumber()
          << ", " << certificate.digest().toBase64()
          << ", " << certificate.issuerInfo(Certificate::Organization)
          << ", " << certificate.subjectInfo(Certificate::Organization)
          << ", " << certificate.effectiveDate()
          << ", " << certificate.expiryDate()
          << ')';
    return debug;
}

QDebug &operator<<(QDebug &debug, Certificate::SubjectInfo info)
{
    switch (info) {
    case Certificate::Organization: debug << "Organization"; break;
    case Certificate::CommonName: debug << "CommonName"; break;
    case Certificate::CountryName: debug << "CountryName"; break;
    case Certificate::LocalityName: debug << "LocalityName"; break;
    case Certificate::OrganizationalUnitName: debug << "OrganizationalUnitName"; break;
    case Certificate::StateOrProvinceName: debug << "StateOrProvinceName"; break;
    case Certificate::DistinguishedNameQualifier: debug << "DistinguishedNameQualifier"; break;
    case Certificate::SerialNumber: debug << "SerialNumber"; break;
    case Certificate::EmailAddress: debug << "EmailAddress"; break;
    }
    return debug;
}

uint qHash(const Certificate &key, uint seed)
{
    if (openssl::X509 * const x509 = key.d.constData()->x509.data()) {
        const openssl::EVP_MD *sha256 = openssl::q_EVP_sha256();
        if(sha256) {
            unsigned int len = 0;
            unsigned char md[EVP_MAX_MD_SIZE];
            openssl::q_X509_digest(x509, sha256, md, &len);
            return qHashBits(md, len, seed);
        }
    }
    return seed;
}

QTNETWORKNG_NAMESPACE_END
