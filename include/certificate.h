#ifndef QTNG_CERTIFICATE_H
#define QTNG_CERTIFICATE_H

#include <QtCore/qmap.h>
#include "md.h"
#include "pkey.h"

QTNETWORKNG_NAMESPACE_BEGIN

// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
class Certificate;
uint qHash(const Certificate &key, uint seed = 0);

class CertificatePrivate;
class Certificate
{
public:
    enum SubjectInfo {
        Organization = 0,
        CommonName = 1,
        LocalityName = 2,
        OrganizationalUnitName = 3,
        CountryName = 4,
        StateOrProvinceName = 5,
        DistinguishedNameQualifier = 6,
        SerialNumber = 7,
        EmailAddress = 8,
    };

    enum AlternativeNameEntryType {
        EmailEntry = 0,
        DnsEntry = 1,
    };
public:
    Certificate();
    Certificate(const Certificate &other);
    Certificate(Certificate &&other);
    virtual ~Certificate();
public:
    bool isBlacklisted() const;
    bool isNull() const;
    bool isValid() const { return !isNull() && !isBlacklisted(); }
    Qt::HANDLE handle() const;

    QByteArray digest(MessageDigest::Algorithm algorithm = MessageDigest::Sha256) const;
    QDateTime effectiveDate() const;
    QDateTime expiryDate() const;
    PublicKey publicKey() const;
    QByteArray serialNumber() const;
    QMultiMap<AlternativeNameEntryType, QString> subjectAlternativeNames() const;
    QStringList subjectInfo(SubjectInfo subject) const;
    QStringList subjectInfo(const QByteArray &attribute) const;
    QList<QByteArray> subjectInfoAttributes() const;
    QString toString() const;
    QByteArray version() const;

    bool isSelfSigned() const;
    QStringList issuerInfo(SubjectInfo subject) const;
    QStringList issuerInfo(const QByteArray &attribute) const;
    QList<QByteArray> issuerInfoAttributes() const;
public:
    inline void swap(Certificate &other) { qSwap(d, other.d); }
    Certificate &operator=(Certificate &&other)
    {
        swap(other);
        return *this;
    }
    Certificate &operator=(const Certificate &other);
    bool operator!=(const Certificate &other) const { return !(*this == other); }
    bool operator==(const Certificate &other) const;
public:
    static Certificate load(const QByteArray &data, Ssl::EncodingFormat format = Ssl::Pem);
    static Certificate generate(const PublicKey &publickey, const PrivateKey &caKey, MessageDigest::Algorithm signAlgo,
                                long serialNumber, const QDateTime &effectiveDate, const QDateTime &expiryDate,
                                const QMultiMap<SubjectInfo, QString> &subjectInfoes);
    static Certificate selfSign(const PrivateKey &key, MessageDigest::Algorithm signAlgo, long serialNumber,
                                const QDateTime &effectiveDate, const QDateTime &expiryDate,
                                const QMultiMap<Certificate::SubjectInfo, QString> &subjectInfoes)
    {
        return generate(key, key, signAlgo, serialNumber, effectiveDate, expiryDate, subjectInfoes);
    }

    QByteArray save(Ssl::EncodingFormat format = Ssl::Pem) const;
private:
    QSharedDataPointer<CertificatePrivate> d;
    friend class CertificatePrivate;
    friend uint qHash(const Certificate &key, uint seed);
};

class CertificateRequest
{
public:
    Certificate certificate() const;
};

QDebug &operator<<(QDebug &debug, const Certificate &certificate);
QDebug &operator<<(QDebug &debug, Certificate::SubjectInfo info);

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_CERTIFICATE_H
