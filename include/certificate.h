#ifndef QTNG_CERTIFICATE_H
#define QTNG_CERTIFICATE_H

#include "md.h"
#include "pkey.h"

QTNETWORKNG_NAMESPACE_BEGIN

class CertificateExtensionPrivate;
class CertificateExtension
{
public:
    CertificateExtension();
    CertificateExtension(const CertificateExtension& other);
    ~CertificateExtension();
public:
    bool isCritical() const;
    bool isSupported() const;
    QString name() const;
    QString oid() const;
    void swap(CertificateExtension &other);
    QVariant value() const;
    CertificateExtension &operator=(CertificateExtension &&other);
    CertificateExtension &operator=(const CertificateExtension &other);
private:
    CertificateExtensionPrivate * const d_ptr;
    Q_DECLARE_PRIVATE(CertificateExtension)
};


class CertificatePrivate;
class Certificate
{
public:
    enum SubjectInfo
    {
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

    enum AlternativeNameEntryType
    {
        EmailEntry = 0,
        DnsEntry = 1,
    };
public:
    explicit Certificate(const QByteArray &pem);
    virtual ~Certificate();
public:
    QByteArray digest(MessageDigest::Algorithm algorithm = MessageDigest::Sha256) const;
    QDateTime effectiveDate() const;
    QDateTime expiryDate() const;
    QList<CertificateExtension> extensions() const;
    Qt::HANDLE handle() const;
    bool isBlacklisted() const;
    bool isNull() const;
    bool isSelfSigned() const;
    QStringList issuerInfo(SubjectInfo subject) const;
    QStringList issuerInfo(const QByteArray &attribute) const;
    QList<QByteArray> issuerInfoAttributes() const;
    PublicKey publicKey() const;
    QByteArray serialNumber() const;
    QMultiMap<AlternativeNameEntryType, QString> subjectAlternativeNames() const;
    QStringList subjectInfo(SubjectInfo subject) const;
    QStringList subjectInfo(const QByteArray &attribute) const;
    QList<QByteArray> subjectInfoAttributes() const;
    QByteArray toDer() const;
    QByteArray toPem() const;
    QString toText() const;
    QByteArray version() const;
    bool operator!=(const Certificate &other) const;
    Certificate &operator=(Certificate &&other);
    Certificate &operator=(const Certificate &other);
    bool operator==(const Certificate &other) const;
private:
    CertificatePrivate * const d_ptr;
    Q_DECLARE_PRIVATE(Certificate)
};


class CertificateRequest
{
public:
    Certificate certificate() const;
};

QTNETWORKNG_NAMESPACE_END

#endif // QTNG_CERTIFICATE_H
