/****************************************************************************
**
** Copyright (C) 2014 Jeremy Lainé <jeremy.laine@m4x.org>
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "../include/private/qasn1element.h"
#include <QtCore/qdatastream.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qvector.h>
#include <QtCore/qdebug.h>

#include <locale>

QTNETWORKNG_NAMESPACE_BEGIN

typedef QMap<QByteArray, QByteArray> OidNameMap;
static OidNameMap createOidMap()
{
    OidNameMap oids;
    // used by unit tests
    oids.insert(oids.cend(), QByteArrayLiteral("0.9.2342.19200300.100.1.5"), QByteArrayLiteral("favouriteDrink"));
    oids.insert(oids.cend(), QByteArrayLiteral("1.2.840.113549.1.9.1"), QByteArrayLiteral("emailAddress"));
    oids.insert(oids.cend(), QByteArrayLiteral("1.3.6.1.5.5.7.1.1"), QByteArrayLiteral("authorityInfoAccess"));
    oids.insert(oids.cend(), QByteArrayLiteral("1.3.6.1.5.5.7.48.1"), QByteArrayLiteral("OCSP"));
    oids.insert(oids.cend(), QByteArrayLiteral("1.3.6.1.5.5.7.48.2"), QByteArrayLiteral("caIssuers"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.29.14"), QByteArrayLiteral("subjectKeyIdentifier"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.29.15"), QByteArrayLiteral("keyUsage"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.29.17"), QByteArrayLiteral("subjectAltName"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.29.19"), QByteArrayLiteral("basicConstraints"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.29.35"), QByteArrayLiteral("authorityKeyIdentifier"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.10"), QByteArrayLiteral("O"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.11"), QByteArrayLiteral("OU"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.12"), QByteArrayLiteral("title"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.13"), QByteArrayLiteral("description"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.17"), QByteArrayLiteral("postalCode"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.3"), QByteArrayLiteral("CN"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.4"), QByteArrayLiteral("SN"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.41"), QByteArrayLiteral("name"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.42"), QByteArrayLiteral("GN"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.43"), QByteArrayLiteral("initials"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.46"), QByteArrayLiteral("dnQualifier"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.5"), QByteArrayLiteral("serialNumber"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.6"), QByteArrayLiteral("C"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.7"), QByteArrayLiteral("L"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.8"), QByteArrayLiteral("ST"));
    oids.insert(oids.cend(), QByteArrayLiteral("2.5.4.9"), QByteArrayLiteral("street"));
    return oids;
}
Q_GLOBAL_STATIC_WITH_ARGS(OidNameMap, oidNameMap, (createOidMap()))

static bool stringToNonNegativeInt(const QByteArray &asnString, int *val)
{
    // Helper function for toDateTime(), which handles chunking of the original
    // string into smaller sub-components, so we expect the whole 'asnString' to
    // be a valid non-negative number.
    Q_ASSERT(val);

    // We want the C locale, as used by QByteArray; however, no leading sign is
    // allowed (which QByteArray would accept), so we have to check the data:
    const std::locale localeC;
    for (char v : asnString) {
        if (!std::isdigit(v, localeC))
            return false;
    }

    bool ok = false;
    *val = asnString.toInt(&ok);
    Q_ASSERT(ok && *val >= 0);
    return true;
}

QAsn1Element::QAsn1Element(quint8 type, const QByteArray &value)
    : mType(type)
    , mValue(value)
{
}

bool QAsn1Element::read(QDataStream &stream)
{
    // type
    quint8 tmpType;
    stream >> tmpType;
    if (!tmpType)
        return false;

    // length
    qint32 length = 0;
    quint8 first;
    stream >> first;
    if (first & 0x80) {
        // long form
        const quint8 bytes = (first & 0x7f);
        if (bytes > 7)
            return false;

        quint8 b;
        for (int i = 0; i < bytes; i++) {
            stream >> b;
            length = (length << 8) | b;
        }
    } else {
        // short form
        length = (first & 0x7f);
    }

    // value
    QByteArray tmpValue;
    tmpValue.resize(length);
    int count = stream.readRawData(tmpValue.data(), tmpValue.size());
    if (count != length)
        return false;

    mType = tmpType;
    mValue.swap(tmpValue);
    return true;
}

bool QAsn1Element::read(const QByteArray &data)
{
    QDataStream stream(data);
    return read(stream);
}

void QAsn1Element::write(QDataStream &stream) const
{
    // type
    stream << mType;

    // length
    qint64 length = mValue.size();
    if (length >= 128) {
        // long form
        quint8 encodedLength = 0x80;
        QByteArray ba;
        while (length) {
            ba.prepend(static_cast<char>(static_cast<quint8>(length & 0xff)));
            length >>= 8;
            encodedLength += 1;
        }
        stream << encodedLength;
        stream.writeRawData(ba.data(), ba.size());
    } else {
        // short form
        stream << quint8(length);
    }

    // value
    stream.writeRawData(mValue.data(), mValue.size());
}

QAsn1Element QAsn1Element::fromBool(bool val)
{
    const char negOne = std::numeric_limits<char>::is_signed ? -1 : 0xff;
    return QAsn1Element(QAsn1Element::BooleanType, QByteArray(1, val ? negOne : 0x00));
}

QAsn1Element QAsn1Element::fromInteger(unsigned int val)
{
    const char negOne = std::numeric_limits<char>::is_signed ? -1 : 0xff;
    QAsn1Element elem(QAsn1Element::IntegerType);
    while (val > 127) {
        elem.mValue.prepend(static_cast<char>(val) & negOne);
        val >>= 8;
    }
    elem.mValue.prepend(val & 0x7f);
    return elem;
}

QAsn1Element QAsn1Element::fromVector(const QVector<QAsn1Element> &items)
{
    QAsn1Element seq;
    seq.mType = SequenceType;
    QDataStream stream(&seq.mValue, QIODevice::WriteOnly);
    for (QVector<QAsn1Element>::const_iterator it = items.cbegin(), end = items.cend(); it != end; ++it)
        it->write(stream);
    return seq;
}

QAsn1Element QAsn1Element::fromObjectId(const QByteArray &id)
{
    QAsn1Element elem;
    elem.mType = ObjectIdentifierType;
    const QList<QByteArray> bits = id.split('.');
    Q_ASSERT(bits.size() > 2);
    elem.mValue += quint8((bits[0].toUInt() * 40 + bits[1].toUInt()));
    for (int i = 2; i < bits.size(); ++i) {
        char buffer[std::numeric_limits<unsigned int>::digits / 7 + 2];
        char *pBuffer = buffer + sizeof(buffer);
        *--pBuffer = '\0';
        unsigned int node = bits[i].toUInt();
        *--pBuffer = quint8((node & 0x7f));
        node >>= 7;
        while (node) {
            *--pBuffer = quint8(((node & 0x7f) | 0x80));
            node >>= 7;
        }
        elem.mValue += pBuffer;
    }
    return elem;
}

bool QAsn1Element::toBool(bool *ok) const
{
    if (*this == fromBool(true)) {
        if (ok)
            *ok = true;
        return true;
    } else if (*this == fromBool(false)) {
        if (ok)
            *ok = true;
        return false;
    } else {
        if (ok)
            *ok = false;
        return false;
    }
}

QDateTime QAsn1Element::toDateTime() const
{
    if (mValue.endsWith('Z')) {
        if (mType == UtcTimeType && mValue.size() == 13) {
            int year = 0;
            if (!stringToNonNegativeInt(mValue.mid(0, 2), &year))
                return QDateTime();
            // RFC 2459: YY represents a year in the range [1950, 2049]
            return QDateTime(
                    QDate(year < 50 ? 2000 + year : 1900 + year, mValue.mid(2, 2).toInt(), mValue.mid(4, 2).toInt()),
                    QTime(mValue.mid(6, 2).toInt(), mValue.mid(8, 2).toInt(), mValue.mid(10, 2).toInt()), Qt::UTC);
        } else if (mType == GeneralizedTimeType && mValue.size() == 15) {
            return QDateTime(QDate(mValue.mid(0, 4).toInt(), mValue.mid(4, 2).toInt(), mValue.mid(6, 2).toInt()),
                             QTime(mValue.mid(8, 2).toInt(), mValue.mid(10, 2).toInt(), mValue.mid(12, 2).toInt()),
                             Qt::UTC);
        }
    }
    return QDateTime();
}

QMultiMap<QByteArray, QString> QAsn1Element::toInfo() const
{
    QMultiMap<QByteArray, QString> info;
    QAsn1Element elem;
    QDataStream issuerStream(mValue);
    while (elem.read(issuerStream) && elem.mType == QAsn1Element::SetType) {
        QAsn1Element issuerElem;
        QDataStream setStream(elem.mValue);
        if (issuerElem.read(setStream) && issuerElem.mType == QAsn1Element::SequenceType) {
            QVector<QAsn1Element> elems = issuerElem.toVector();
            if (elems.size() == 2) {
                const QByteArray key = elems.front().toObjectName();
                if (!key.isEmpty())
                    info.insert(key, elems.back().toString());
            }
        }
    }
    return info;
}

qint64 QAsn1Element::toInteger(bool *ok) const
{
    if (mType != QAsn1Element::IntegerType || mValue.isEmpty()) {
        if (ok)
            *ok = false;
        return 0;
    }

    // NOTE: negative numbers are not handled
    if (mValue.at(0) & 0x80) {
        if (ok)
            *ok = false;
        return 0;
    }

    qint64 value = mValue.at(0) & 0x7f;
    for (int i = 1; i < mValue.size(); ++i)
        value = (value << 8) | quint8(mValue.at(i));

    if (ok)
        *ok = true;
    return value;
}

QVector<QAsn1Element> QAsn1Element::toVector() const
{
    QVector<QAsn1Element> items;
    if (mType == SequenceType) {
        QAsn1Element elem;
        QDataStream stream(mValue);
        while (elem.read(stream))
            items << elem;
    }
    return items;
}

QByteArray QAsn1Element::toObjectId() const
{
    QByteArray key;
    if (mType == ObjectIdentifierType && !mValue.isEmpty()) {
        quint8 b = mValue.at(0);
        key += QByteArray::number(b / 40) + '.' + QByteArray::number(b % 40);
        unsigned int val = 0;
        for (int i = 1; i < mValue.size(); ++i) {
            b = mValue.at(i);
            val = (val << 7) | (b & 0x7f);
            if (!(b & 0x80)) {
                key += '.' + QByteArray::number(val);
                val = 0;
            }
        }
    }
    return key;
}

QByteArray QAsn1Element::toObjectName() const
{
    QByteArray key = toObjectId();
    return oidNameMap->value(key, key);
}

QString QAsn1Element::toString() const
{
    // Detect embedded NULs and reject
    if (qstrlen(mValue) < uint(mValue.size()))
        return QString();

    if (mType == PrintableStringType || mType == TeletexStringType || mType == Rfc822NameType || mType == DnsNameType
        || mType == UniformResourceIdentifierType)
        return QString::fromLatin1(mValue, mValue.size());
    if (mType == Utf8StringType)
        return QString::fromUtf8(mValue, mValue.size());

    return QString();
}

QTNETWORKNG_NAMESPACE_END
