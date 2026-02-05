#include <QtCore/qdebug.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qdatastream.h>
extern "C" {
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
}
#include "../include/certificate.h"
#include "../include/private/qasn1element.h"
#include "../include/private/crypto_p.h"
#include "debugger.h"

QTNG_LOGGER("qtng.certificate");

QTNETWORKNG_NAMESPACE_BEGIN

static QDateTime getTimeFromASN1(const ASN1_TIME *aTime)
{
    size_t lTimeLength = static_cast<size_t>(aTime->length);
    char *pString = reinterpret_cast<char *>(aTime->data);

    if (aTime->type == V_ASN1_UTCTIME) {

        char lBuffer[24];
        char *pBuffer = lBuffer;

        if ((lTimeLength < 11) || (lTimeLength > 17))
            return QDateTime();

        memcpy(pBuffer, pString, 10);
        pBuffer += 10;
        pString += 10;

        if ((*pString == 'Z') || (*pString == '-') || (*pString == '+')) {
            *pBuffer++ = '0';
            *pBuffer++ = '0';
        } else {
            *pBuffer++ = *pString++;
            *pBuffer++ = *pString++;
            // Skip any fractional seconds...
            if (*pString == '.') {
                pString++;
                while ((*pString >= '0') && (*pString <= '9'))
                    pString++;
            }
        }

        *pBuffer++ = 'Z';
        *pBuffer++ = '\0';

        time_t lSecondsFromUCT;
        if (*pString == 'Z') {
            lSecondsFromUCT = 0;
        } else {
            if ((*pString != '+') && (*pString != '-'))
                return QDateTime();

            lSecondsFromUCT = ((pString[1] - '0') * 10 + (pString[2] - '0')) * 60;
            lSecondsFromUCT += (pString[3] - '0') * 10 + (pString[4] - '0');
            lSecondsFromUCT *= 60;
            if (*pString == '-')
                lSecondsFromUCT = -lSecondsFromUCT;
        }

        tm lTime;
        lTime.tm_sec = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
        lTime.tm_min = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
        lTime.tm_hour = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
        lTime.tm_mday = ((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0');
        lTime.tm_mon = (((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0')) - 1;
        lTime.tm_year = ((lBuffer[0] - '0') * 10) + (lBuffer[1] - '0');
        if (lTime.tm_year < 50)
            lTime.tm_year += 100;  // RFC 2459

        QDate resDate(lTime.tm_year + 1900, lTime.tm_mon + 1, lTime.tm_mday);
        QTime resTime(lTime.tm_hour, lTime.tm_min, lTime.tm_sec);

        QDateTime result(resDate, resTime, Qt::UTC);
        result = result.addSecs(lSecondsFromUCT);
        return result;

    } else if (aTime->type == V_ASN1_GENERALIZEDTIME) {

        if (lTimeLength < 15)
            return QDateTime();  // hopefully never triggered

        // generalized time is always YYYYMMDDHHMMSSZ (RFC 2459, section 4.1.2.5.2)
        tm lTime;
        lTime.tm_sec = ((pString[12] - '0') * 10) + (pString[13] - '0');
        lTime.tm_min = ((pString[10] - '0') * 10) + (pString[11] - '0');
        lTime.tm_hour = ((pString[8] - '0') * 10) + (pString[9] - '0');
        lTime.tm_mday = ((pString[6] - '0') * 10) + (pString[7] - '0');
        lTime.tm_mon = (((pString[4] - '0') * 10) + (pString[5] - '0'));
        lTime.tm_year = ((pString[0] - '0') * 1000) + ((pString[1] - '0') * 100) + ((pString[2] - '0') * 10)
                + (pString[3] - '0');

        QDate resDate(lTime.tm_year, lTime.tm_mon, lTime.tm_mday);
        QTime resTime(lTime.tm_hour, lTime.tm_min, lTime.tm_sec);

        QDateTime result(resDate, resTime, Qt::UTC);
        return result;

    } else {
        qtng_warning << "unsupported date format detected";
        return QDateTime();
    }
}

struct X509Cleaner
{
    static inline void cleanup(X509 *x)
    {
        if (x)
            X509_free(x);
    }
};

class CertificatePrivate : public QSharedData
{
public:
    CertificatePrivate() { }
    CertificatePrivate(const CertificatePrivate &) = default;

    bool isNull() const;
    QDateTime effectiveDate() const;
    QDateTime expiryDate() const;
    bool isBlacklisted() const;
    PublicKey publicKey() const;
    QByteArray serialNumber() const;
    QStringList subjectInfo(Certificate::SubjectInfo subjec) const;
    QStringList subjectInfo(const QByteArray &attribute) const;
    QList<QByteArray> subjectInfoAttributes() const;
    QString toString() const;
    QByteArray version() const;

    bool isSelfSigned() const;
    QStringList issuerInfo(Certificate::SubjectInfo subject) const;
    QStringList issuerInfo(const QByteArray &attribute) const;
    QList<QByteArray> issuerInfoAttributes() const;

    QByteArray save(Ssl::EncodingFormat format) const;
    static Certificate load(const QByteArray &data, Ssl::EncodingFormat format);
    static Certificate generate(const PublicKey &publickey, const PrivateKey &caKey, MessageDigest::Algorithm signAlgo,
                                long serialNumber, const QDateTime &effectiveDate, const QDateTime &expiryDate,
                                const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes);
    static QByteArray subjectInfoToString(Certificate::SubjectInfo info);
    static inline bool setX509(Certificate *cert, X509 *x509);

    bool init(X509 *x509);
    bool qtParse();

    QSharedPointer<X509> x509;
    QMultiMap<QByteArray, QString> issuerInfoMap;
    QMultiMap<QByteArray, QString> subjectInfoMap;
    QByteArray versionString;
    QDateTime notValidBefore;
    QDateTime notValidAfter;
};

static QByteArray asn1ObjectId(ASN1_OBJECT *object)
{
    char buf[80];  // The openssl docs a buffer length of 80 should be more than enough
    OBJ_obj2txt(buf, sizeof(buf), object, 1);  // the 1 says always use the oid not the long name

    return QByteArray(buf);
}

static QByteArray asn1ObjectName(ASN1_OBJECT *object)
{
    int nid = OBJ_obj2nid(object);
    if (nid != NID_undef)
        return QByteArray(OBJ_nid2sn(nid));

    return asn1ObjectId(object);
}

static QMultiMap<QByteArray, QString> _mapFromX509Name(X509_NAME *name)
{
    QMultiMap<QByteArray, QString> info;
    for (int i = 0; i < X509_NAME_entry_count(name); ++i) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);

        QByteArray name = asn1ObjectName(X509_NAME_ENTRY_get_object(e));
        unsigned char *data = nullptr;
        int size = ASN1_STRING_to_UTF8(&data, X509_NAME_ENTRY_get_data(e));
        info.insert(name, QString::fromUtf8(static_cast<char *>(static_cast<void *>(data)), size));
#if LIBRESSL_VERSION_NUMBER >= 0x3090000fL
        CRYPTO_free(data, __FILE__, __LINE__);
#elif defined(LIBRESSL_VERSION_NUMBER)
        CRYPTO_free(data);
#else
        CRYPTO_free(data, __FILE__, __LINE__);
#endif
    }

    return info;
}

bool CertificatePrivate::init(X509 *x)
{
    if (!x)
        return false;
    this->x509.reset(x, X509_free);

    int parsed = 0;  // 0 for never parsed, -1 for failed, and 1 for success.
    ASN1_TIME *t = X509_getm_notBefore(x);
    if (t) {
        notValidBefore = getTimeFromASN1(t);
    } else {
        parsed = qtParse() ? 1 : -1;
    }
    t = X509_getm_notAfter(x);
    if (t) {
        notValidAfter = getTimeFromASN1(t);
    } else if (parsed == 0) {
        parsed = qtParse() ? 1 : -1;
    }
    qlonglong version = qlonglong(X509_get_version(x));
    if (version >= 0) {
        versionString = QByteArray::number(version);
    } else if (parsed == 0) {
        parsed = qtParse() ? 1 : -1;
    }

    issuerInfoMap = _mapFromX509Name(X509_get_issuer_name(x));
    subjectInfoMap = _mapFromX509Name(X509_get_subject_name(x));
    return parsed != -1;
}

bool CertificatePrivate::setX509(Certificate *cert, X509 *x)
{
    if (!x || !cert)
        return false;
    return cert->d->init(X509_dup(x));
}

bool openssl_setCertificate(Certificate *cert, X509 *x509)
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
static const char * const certificate_blacklist[] = {
    "04:7e:cb:e9:fc:a5:5f:7b:d0:9e:ae:36:e1:0c:ae:1e", "mail.google.com",  // Comodo
    "f5:c8:6a:f3:61:62:f1:3a:64:f5:4f:6d:c9:58:7c:06", "www.google.com",  // Comodo
    "d7:55:8f:da:f5:f1:10:5b:b2:13:28:2b:70:77:29:a3", "login.yahoo.com",  // Comodo
    "39:2a:43:4f:0e:07:df:1f:8a:a3:05:de:34:e0:c2:29", "login.yahoo.com",  // Comodo
    "3e:75:ce:d4:6b:69:30:21:21:88:30:ae:86:a8:2a:71", "login.yahoo.com",  // Comodo
    "e9:02:8b:95:78:e4:15:dc:1a:71:0a:2b:88:15:44:47", "login.skype.com",  // Comodo
    "92:39:d5:34:8f:40:d1:69:5a:74:54:70:e1:f2:3f:43", "addons.mozilla.org",  // Comodo
    "b0:b7:13:3e:d0:96:f9:b5:6f:ae:91:c8:74:bd:3a:c0", "login.live.com",  // Comodo
    "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0", "global trustee",  // Comodo

    "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56", "*.google.com",  // leaf certificate issued by DigiNotar
    "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c", "DigiNotar Root CA",  // DigiNotar root
    "f1:4a:13:f4:87:2b:56:dc:39:df:84:ca:7a:a1:06:49",
    "DigiNotar Services CA",  // DigiNotar intermediate signed by DigiNotar Root
    "36:16:71:55:43:42:1b:9d:e6:cb:a3:64:41:df:24:38",
    "DigiNotar Services 1024 CA",  // DigiNotar intermediate signed by DigiNotar Root
    "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e", "DigiNotar Root CA G2",  // other DigiNotar Root CA
    "a4:b6:ce:e3:2e:d3:35:46:26:3c:b3:55:3a:a8:92:21",
    "CertiID Enterprise Certificate Authority",  // DigiNotar intermediate signed by "DigiNotar Root CA G2"
    "5b:d5:60:9c:64:17:68:cf:21:0e:35:fd:fb:05:ad:41",
    "DigiNotar Qualified CA",  // DigiNotar intermediate signed by DigiNotar Root

    "46:9c:2c:b0", "DigiNotar Services 1024 CA",  // DigiNotar intermediate cross-signed by Entrust
    "07:27:10:0d", "DigiNotar Cyber CA",  // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:0f:f9", "DigiNotar Cyber CA",  // DigiNotar intermediate cross-signed by CyberTrust
    "07:27:10:03", "DigiNotar Cyber CA",  // DigiNotar intermediate cross-signed by CyberTrust
    "01:31:69:b0",
    "DigiNotar PKIoverheid CA Overheid en Bedrijven",  // DigiNotar intermediate cross-signed by the Dutch government
    "01:31:34:bf",
    "DigiNotar PKIoverheid CA Organisatie - G2",  // DigiNotar intermediate cross-signed by the Dutch government
    "d6:d0:29:77:f1:49:fd:1a:83:f2:b9:ea:94:8c:5c:b4",
    "DigiNotar Extended Validation CA",  // DigiNotar intermediate signed by DigiNotar EV Root
    "1e:7d:7a:53:3d:45:30:41:96:40:0f:71:48:1f:45:04", "DigiNotar Public CA 2025",  // DigiNotar intermediate
    //    "(has not been seen in the wild so far)", "DigiNotar Public CA - G2", // DigiNotar intermediate
    //    "(has not been seen in the wild so far)", "Koninklijke Notariele Beroepsorganisatie CA", // compromised during
    //    DigiNotar breach
    //    "(has not been seen in the wild so far)", "Stichting TTP Infos CA," // compromised during DigiNotar breach
    "46:9c:2c:af", "DigiNotar Root CA",  // DigiNotar intermediate cross-signed by Entrust
    "46:9c:3c:c9", "DigiNotar Root CA",  // DigiNotar intermediate cross-signed by Entrust

    "07:27:14:a9", "Digisign Server ID (Enrich)",  // (Malaysian) Digicert Sdn. Bhd. cross-signed by Verizon CyberTrust
    "4c:0e:63:6a", "Digisign Server ID - (Enrich)",  // (Malaysian) Digicert Sdn. Bhd. cross-signed by Entrust
    "72:03:21:05:c5:0c:08:57:3d:8e:a5:30:4e:fe:e8:b0", "UTN-USERFirst-Hardware",  // comodogate test certificate
    "41", "MD5 Collisions Inc. (http://www.phreedom.org/md5)",  // http://www.phreedom.org/research/rogue-ca/

    "08:27", "*.EGO.GOV.TR",  // Turktrust mis-issued intermediate certificate
    "08:64", "e-islem.kktcmerkezbankasi.org",  // Turktrust mis-issued intermediate certificate

    "03:1d:a7",
    "AC DG Tr\xC3\xA9sor SSL",  // intermediate certificate linking back to ANSSI French National Security Agency
    "27:83", "NIC Certifying Authority",  // intermediate certificate from NIC India (2007)
    "27:92", "NIC CA 2011",  // intermediate certificate from NIC India (2011)
    "27:b1", "NIC CA 2014",  // intermediate certificate from NIC India (2014)
    nullptr
};

bool CertificatePrivate::isBlacklisted() const
{
    if (x509.isNull())
        return false;
    for (int a = 0; certificate_blacklist[a] != nullptr; a++) {
        QString blacklistedCommonName = QString::fromUtf8(certificate_blacklist[(a + 1)]);
        if (serialNumber() == certificate_blacklist[a++]
            && (subjectInfo(Certificate::CommonName).contains(blacklistedCommonName)
                || issuerInfo(Certificate::CommonName).contains(blacklistedCommonName)))
            return true;
    }
    return false;
}

PublicKey CertificatePrivate::publicKey() const
{
    PublicKey key;
    if (!x509.isNull()) {
        EVP_PKEY *pkey = X509_get_pubkey(x509.data());
        if (pkey) {
            openssl_setPkey(&key, pkey, false);
        }
    }
    return key;
}

QByteArray CertificatePrivate::serialNumber() const
{
    if (x509.isNull()) {
        return QByteArray();
    }

    ASN1_INTEGER *serialNumber = X509_get_serialNumber(x509.data());
    if (!serialNumber) {
        return QByteArray();
    }

    long value = -1;
    if (serialNumber->length <= static_cast<int>(sizeof(long))
        && serialNumber->type == V_ASN1_INTEGER) {
        uint64_t u64 = 0;
        if (ASN1_INTEGER_get_uint64(&u64, serialNumber) && u64 <= LONG_MAX)
            value = static_cast<long>(u64);
    }

    if (value >= 0) {
        return QByteArray::number(static_cast<qlonglong>(value));
    }

    QByteArray result;
    if (serialNumber->type == V_ASN1_NEG_INTEGER) {
        result.append("(Negative) ");
    }

    for (int i = 0; i < serialNumber->length; ++i) {
        if (i > 0)
            result.append(':');
        const unsigned int byteValue = static_cast<unsigned int>(serialNumber->data[i]);
        result.append(QByteArray::number(byteValue, 16).rightJustified(2, '0'));
    }
    return result;
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

bool CertificatePrivate::isSelfSigned() const
{
    if (x509.isNull())
        return false;
    return (X509_check_issued(x509.data(), x509.data()) == X509_V_OK);
}

QByteArray CertificatePrivate::subjectInfoToString(Certificate::SubjectInfo info)
{
    QByteArray str;
    switch (info) {
    case Certificate::Organization:
        str = QByteArray("O");
        break;
    case Certificate::CommonName:
        str = QByteArray("CN");
        break;
    case Certificate::LocalityName:
        str = QByteArray("L");
        break;
    case Certificate::OrganizationalUnitName:
        str = QByteArray("OU");
        break;
    case Certificate::CountryName:
        str = QByteArray("C");
        break;
    case Certificate::StateOrProvinceName:
        str = QByteArray("ST");
        break;
    case Certificate::DistinguishedNameQualifier:
        str = QByteArray("dnQualifier");
        break;
    case Certificate::SerialNumber:
        str = QByteArray("serialNumber");
        break;
    case Certificate::EmailAddress:
        str = QByteArray("emailAddress");
        break;
    }
    return str;
}

QStringList CertificatePrivate::issuerInfo(Certificate::SubjectInfo subject) const
{
    if (x509.isNull())
        return QStringList();
    return issuerInfoMap.values(subjectInfoToString(subject));
}

QStringList CertificatePrivate::issuerInfo(const QByteArray &attribute) const
{
    if (x509.isNull())
        return QStringList();
    return issuerInfoMap.values(attribute);
}

QList<QByteArray> CertificatePrivate::issuerInfoAttributes() const
{
    if (x509.isNull())
        return QList<QByteArray>();
    return issuerInfoMap.uniqueKeys();
}

struct BioCleaner
{
    static void inline cleanup(BIO *o)
    {
        if (o)
            BIO_free(o);
    }
};

QString CertificatePrivate::toString() const
{
    if (x509.isNull()) {
        return QString();
    }
    QByteArray result(1024 * 64, Qt::Uninitialized);
    QScopedPointer<BIO, BioCleaner> bio(BIO_new(BIO_s_mem()));
    if (bio.isNull())
        return QString();

    // FIXME I have got nothing.
    X509_print(bio.data(), x509.data());

    int count = BIO_read(bio.data(), result.data(), result.size());
    if (count > 0) {
        result.resize(count);
    }
    return QString::fromLatin1(result);
}

QByteArray CertificatePrivate::save(Ssl::EncodingFormat format) const
{
    if (x509.isNull()) {
        return QByteArray();
    }

    if (format == Ssl::Pem) {
        QSharedPointer<BIO> bio(BIO_new(BIO_s_mem()), BIO_free);
        if (bio.isNull()) {
            return QByteArray();
        }
        int r = PEM_write_bio_X509(bio.data(), x509.data());
        if (r) {
            char *p = nullptr;
            long size = BIO_get_mem_data(bio.data(), &p);
            if (size > 0 && p != nullptr) {
                return QByteArray(p, static_cast<int>(size));
            }
        }
    } else if (format == Ssl::Der) {
        unsigned char *buf = nullptr;
        int len = i2d_X509(x509.data(), &buf);
        if (len > 0) {
            return QByteArray(static_cast<char *>(static_cast<void *>(buf)), len);
        }
    }
    return QByteArray();
}

Certificate CertificatePrivate::load(const QByteArray &data, Ssl::EncodingFormat format)
{
    Certificate cert;
    if (data.isEmpty()) {
        return cert;
    }
    if (format == Ssl::Pem) {
        QSharedPointer<BIO> bio(BIO_new_mem_buf(data.data(), data.size()), BIO_free);
        if (bio.isNull()) {
            return cert;
        }
        X509 *x = nullptr;
        PEM_read_bio_X509(bio.data(), &x, nullptr, nullptr);
        if (x) {
            cert.d->init(x);
        }
    } else if (format == Ssl::Der) {
        const unsigned char *buf;
        buf = reinterpret_cast<const unsigned char *>(data.constData());
        int len = data.size();
        X509 *x = d2i_X509(nullptr, &buf, len);
        if (x) {
            cert.d->init(x);
        }
        return cert;
    }
    return cert;
}

static bool setIssuerInfos(X509 *x, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    X509_NAME *name = X509_get_issuer_name(x);
    if (!name) {
        return false;
    }
    QMap<Certificate::SubjectInfo, QByteArray> table = {
        { Certificate::Organization, "O" },
        { Certificate::CommonName, "CN" },
        { Certificate::LocalityName, "L" },
        { Certificate::OrganizationalUnitName, "OU" },
        { Certificate::CountryName, "C" },
        { Certificate::StateOrProvinceName, "ST" },
        { Certificate::DistinguishedNameQualifier, "dnQualifier" },
        { Certificate::SerialNumber, "serialNumber" },
        //        {Certificate::EmailAddress, "emailAddress" },

    };
    bool success = true;
    for (QMap<Certificate::SubjectInfo, QByteArray>::const_iterator itor = table.constBegin(); itor != table.constEnd();
         ++itor) {
        const QStringList &sl = subjectInfoes.values(itor.key());
        for (const QString &s : sl) {
            QByteArray bs = s.toUtf8();
            success = success
                    && X509_NAME_add_entry_by_txt(name, itor.value().data(), MBSTRING_UTF8,
                                                  reinterpret_cast<const unsigned char *>(bs.constData()), bs.size(),
                                                  -1, 0);
        }
    }
    if (!success) {
        return false;
    }
    int r = X509_set_issuer_name(x, name);
    return r;
}

static bool setSubjectInfos(X509 *x, const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    X509_NAME *name = X509_get_subject_name(x);
    if (!name) {
        return false;
    }
    QMap<Certificate::SubjectInfo, QByteArray> table = {
        { Certificate::Organization, "O" },
        { Certificate::CommonName, "CN" },
        { Certificate::LocalityName, "L" },
        { Certificate::OrganizationalUnitName, "OU" },
        { Certificate::CountryName, "C" },
        { Certificate::StateOrProvinceName, "ST" },
        { Certificate::DistinguishedNameQualifier, "dnQualifier" },
        { Certificate::SerialNumber, "serialNumber" },
        //        {Certificate::EmailAddress, "emailAddress" },

    };
    bool success = true;
    for (QMap<Certificate::SubjectInfo, QByteArray>::const_iterator itor = table.constBegin(); itor != table.constEnd();
         ++itor) {
        const QStringList &sl = subjectInfoes.values(itor.key());
        for (const QString &s : sl) {
            QByteArray bs = s.toUtf8();
            success = success
                    && X509_NAME_add_entry_by_txt(name, itor.value().data(), MBSTRING_UTF8,
                                                  reinterpret_cast<const unsigned char *>(bs.constData()), bs.size(),
                                                  -1, 0);
        }
    }
    if (!success) {
        return false;
    }
    int r = X509_set_subject_name(x, name);
    return r;
}

struct Asn1TimeCleaner
{
    static void inline cleanup(ASN1_TIME *t)
    {
        if (t)
            ASN1_STRING_free(t);
    }
};

Certificate CertificatePrivate::generate(const PublicKey &publickey, const PrivateKey &caKey,
                                         MessageDigest::Algorithm signAlgo, long serialNumber,
                                         const QDateTime &effectiveDate, const QDateTime &expiryDate,
                                         const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    Certificate cert;
    QScopedPointer<X509, X509Cleaner> x509(X509_new());
    if (x509.isNull()) {
        qtng_debug << "can not allocate X509.";
        return cert;
    }
    int r = X509_set_version(x509.data(), 2);
    ASN1_INTEGER *i = X509_get_serialNumber(x509.data());
    if (!r || !i) {
        qtng_debug << "can not set version and serial number.";
        return cert;
    }
    ASN1_INTEGER_set(i, serialNumber);
    X509_set_pubkey(x509.data(), static_cast<EVP_PKEY *>(publickey.handle()));
    if (!setSubjectInfos(x509.data(), subjectInfoes)) {
        qtng_debug << "can not set subject infos.";
        return cert;
    }
    if (!setIssuerInfos(x509.data(), subjectInfoes)) {
        qtng_debug << "can not set issuer infos.";
        return cert;
    }
    QScopedPointer<ASN1_TIME, Asn1TimeCleaner> t(ASN1_TIME_new());
    if (!t.isNull()) {
        if (ASN1_TIME_set(t.data(), effectiveDate.toUTC().toTime_t())) {
            r = X509_set1_notBefore(x509.data(), t.data());
            if (!r) {
                qtng_debug << "can not set effective date.";
            }
        } else {
            qtng_debug << "invalid x509 effective date:" << effectiveDate;
        }
        if (ASN1_TIME_set(t.data(), expiryDate.toUTC().toTime_t())) {
            r = X509_set1_notAfter(x509.data(), t.data());
            if (!r) {
                qtng_debug << "can not set expiry date";
            }
        } else {
            qtng_debug << "invalid x509 expiry date:" << expiryDate;
        }
    }
    const EVP_MD *md = getOpenSSL_MD(signAlgo);
    if (!md) {
        qtng_debug << "can not find md.";
        return cert;
    }
    r = X509_sign(x509.data(), static_cast<EVP_PKEY *>(caKey.handle()), md);
    if (!r) {
        qtng_debug << "can not sign certificate.";
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
    if (bs.isEmpty()) {
        return QByteArray();
    }

    const int length = separator ? (bs.size() * 3 - 1) : (bs.size() * 2);
    QByteArray hex;
    hex.resize(length);
    char *hexData = hex.data();
    const uchar *data = reinterpret_cast<const uchar *>(bs.data());
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
    while (i < size && !value.at(i))  // skip leading zeros
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
    Q_UNUSED(serialNumberString)

    // algorithm ID
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    // issuer info
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    QByteArray issuerDer =
            data.mid(static_cast<int>(dataStream.device()->pos()) - elem.value().length(), elem.value().length());
    Q_UNUSED(issuerDer);
    //    issuerInfoMap = elem.toInfo();

    // validity period
    if (!elem.read(certStream) || elem.type() != QAsn1Element::SequenceType) {
        return false;
    }

    QDataStream validityStream(elem.value());
    if (!elem.read(validityStream)
        || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType)) {
        return false;
    }

    notValidBefore = elem.toDateTime();
    if (!elem.read(validityStream)
        || (elem.type() != QAsn1Element::UtcTimeType && elem.type() != QAsn1Element::GeneralizedTimeType)) {
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
                        if (sanElem.read(extension.value().toByteArray()) && sanElem.type() ==
    QAsn1Element::SequenceType) { QDataStream nameStream(sanElem.value()); QAsn1Element nameElem; while
    (nameElem.read(nameStream)) { if (nameElem.type() == QAsn1Element::Rfc822NameType) {
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
    : d(new CertificatePrivate)
{
    initOpenSSL();
}

Certificate::Certificate(const Certificate &other)
    : d(other.d)
{
    initOpenSSL();
}

Certificate::Certificate(Certificate &&other)
    : d(nullptr)
{
    qSwap(d, other.d);
}

Certificate::~Certificate()
{
    cleanupOpenSSL();
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
    const QByteArray &der = save(Ssl::Der);
    if (der.isEmpty()) {
        return QByteArray();
    }
    return MessageDigest::hash(der, algorithm);
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

Certificate Certificate::load(const QByteArray &data, Ssl::EncodingFormat format)
{
    return CertificatePrivate::load(data, format);
}

Certificate Certificate::generate(const PublicKey &publickey, const PrivateKey &caKey,
                                  MessageDigest::Algorithm signAlgo, long serialNumber, const QDateTime &effectiveDate,
                                  const QDateTime &expiryDate,
                                  const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
{
    return CertificatePrivate::generate(publickey, caKey, signAlgo, serialNumber, effectiveDate, expiryDate,
                                        subjectInfoes);
}

bool Certificate::operator==(const Certificate &other) const
{
    if (d->x509 && other.d->x509)
        return X509_cmp(d->x509.data(), other.d->x509.data()) == 0;
    return false;
}

uint qHash(const Certificate &key, uint seed)
{
    if (X509 * const x509 = key.d.constData()->x509.data()) {
        const EVP_MD *sha256 = EVP_sha256();
        if (sha256) {
            unsigned int len = 0;
            unsigned char md[EVP_MAX_MD_SIZE];
            X509_digest(x509, sha256, md, &len);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
            return qHashBits(md, len, seed);
#else
            return qHash(QByteArray(reinterpret_cast<const char *>(md), len), seed);
#endif
        }
    }
    return seed;
}

QDebug &operator<<(QDebug &debug, const Certificate &certificate)
{
    QDebugStateSaver saver(debug);
    Q_UNUSED(saver);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
    debug.resetFormat().nospace();
#else
    debug.nospace();
#endif
    debug << "Certificate(" << certificate.version() << ", " << certificate.serialNumber() << ", "
          << certificate.digest().toBase64() << ", " << certificate.issuerInfo(Certificate::Organization) << ", "
          << certificate.subjectInfo(Certificate::Organization) << ", " << certificate.effectiveDate() << ", "
          << certificate.expiryDate() << ')';
    return debug;
}

QDebug &operator<<(QDebug &debug, Certificate::SubjectInfo info)
{
    switch (info) {
    case Certificate::Organization:
        debug << "Organization";
        break;
    case Certificate::CommonName:
        debug << "CommonName";
        break;
    case Certificate::CountryName:
        debug << "CountryName";
        break;
    case Certificate::LocalityName:
        debug << "LocalityName";
        break;
    case Certificate::OrganizationalUnitName:
        debug << "OrganizationalUnitName";
        break;
    case Certificate::StateOrProvinceName:
        debug << "StateOrProvinceName";
        break;
    case Certificate::DistinguishedNameQualifier:
        debug << "DistinguishedNameQualifier";
        break;
    case Certificate::SerialNumber:
        debug << "SerialNumber";
        break;
    case Certificate::EmailAddress:
        debug << "EmailAddress";
        break;
    }
    return debug;
}

QTNETWORKNG_NAMESPACE_END
