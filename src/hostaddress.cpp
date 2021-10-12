/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2017 Intel Corporation.
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

#include <QtCore/qshareddata.h>
#include <QtCore/qendian.h>
#include <QtCore/qlocale.h>
#include <QtCore/qchar.h>
#include <QtCore/qurl.h>
#include <QtCore/qdebug.h>
#include "../include/private/hostaddress_p.h"
#ifdef Q_OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <errno.h>
#endif


#if QT_VERSION < QT_VERSION_CHECK(5, 8, 0)
#define Q_FALLTHROUGH()
#endif


QTNETWORKNG_NAMESPACE_BEGIN

#ifdef Q_OS_WIN
static QAtomicInt refcount;
void initWinSock()
{
    if(refcount.fetchAndAddAcquire(1) > 0) {
        return;
    }
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        qDebug("WSAStartup failed with error: %d\n", err);
    }
}

void freeWinSock()
{
    if(refcount.fetchAndSubAcquire(1) > 0) {
        return;
    }
    WSACleanup();
}
#endif


typedef QVarLengthArray<char, 64> Buffer;
static const QChar *checkedToAscii(Buffer &buffer, const QChar *begin, const QChar *end);
static bool parseIp4(IPv4Address &address, const QChar *begin, const QChar *end);
static bool parseIp4Internal(IPv4Address &address, const char *ptr, bool acceptLeadingZero);
static const QChar *parseIp6(IPv6Address &address, const QChar *begin, const QChar *end);
static bool parseIp6(const QString &address, IPv6Address &addr, QString *scopeId);
static unsigned long long qstrtoull(const char * nptr, const char **endptr, int base, bool *ok);
static unsigned long long qt_strtoull(const char * nptr, char **endptr, int base);
static bool convertToIpv4(IPv4Address& a, const IPv6Address& a6, const HostAddress::ConversionMode mode);
static QString qulltoa(qulonglong l, int base, const QChar _zero);
static QString number(quint8 val, int base = 10);


unsigned long long qt_strtoull(const char * nptr, char **endptr, int base)
{
    const char *s;
    unsigned long long acc;
    char c;
    unsigned long long cutoff;
    int neg, any, cutlim;

    /*
     * See strtoq for comments as to the logic used.
     */
    s = nptr;
    do {
        c = *s++;
    } while (isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else {
        neg = 0;
        if (c == '+')
            c = *s++;
    }
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X') &&
        ((s[1] >= '0' && s[1] <= '9') ||
        (s[1] >= 'A' && s[1] <= 'F') ||
        (s[1] >= 'a' && s[1] <= 'f'))) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;
    acc = any = 0;
    if (base < 2 || base > 36)
        goto noconv;

    cutoff = ULLONG_MAX / base;
    cutlim = ULLONG_MAX % base;
    for ( ; ; c = *s++) {
        if (c >= '0' && c <= '9')
            c -= '0';
        else if (c >= 'A' && c <= 'Z')
            c -= 'A' - 10;
        else if (c >= 'a' && c <= 'z')
            c -= 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = ULLONG_MAX;
        errno = ERANGE;
    } else if (!any) {
noconv:
        errno = EINVAL;
    } else if (neg)
        acc = (unsigned long long) -(long long)acc;
    if (endptr != NULL)
                *endptr = const_cast<char *>(any ? s - 1 : nptr);
    return (acc);
}


static unsigned long long qstrtoull(const char * nptr, const char **endptr, int base, bool *ok)
{
    // strtoull accepts negative numbers. We don't.
    // Use a different variable so we pass the original nptr to strtoul
    // (we need that so endptr may be nptr in case of failure)
    const char *begin = nptr;
    while (isspace(*begin))
            ++begin;
    if (*begin == '-') {
        *ok = false;
        return 0;
    }

    *ok = true;
    errno = 0;
    char *endptr2 = nullptr;
    unsigned long long result = qt_strtoull(nptr, &endptr2, base);
    if (endptr)
        *endptr = endptr2;
    if ((result == 0 || result == (std::numeric_limits<unsigned long long>::max)())
            && (errno || endptr2 == nptr)) {
        *ok = false;
        return 0;
    }
    return result;
}


static const QChar *checkedToAscii(Buffer &buffer, const QChar *begin, const QChar *end)
{
    const ushort *const ubegin = reinterpret_cast<const ushort *>(begin);
    const ushort *const uend = reinterpret_cast<const ushort *>(end);
    const ushort *src = ubegin;

    buffer.resize(uend - ubegin + 1);
    char *dst = buffer.data();

    while (src != uend) {
        if (*src >= 0x7f)
            return reinterpret_cast<const QChar *>(src);
        *dst++ = *src++;
    }
    *dst = '\0';
    return nullptr;
}


static bool parseIp4(IPv4Address &address, const QChar *begin, const QChar *end)
{
    Q_ASSERT(begin != end);
    Buffer buffer;
    if (checkedToAscii(buffer, begin, end))
        return false;

    const char *ptr = buffer.data();
    return parseIp4Internal(address, ptr, true);
}


static bool parseIp4Internal(IPv4Address &address, const char *ptr, bool acceptLeadingZero)
{
    address = 0;
    int dotCount = 0;
    while (dotCount < 4) {
        if (!acceptLeadingZero && *ptr == '0' &&
                ptr[1] != '.' && ptr[1] != '\0')
            return false;

        const char *endptr;
        bool ok;
        quint64 ll = qstrtoull(ptr, &endptr, 0, &ok);
        quint32 x = ll;
        if (!ok || endptr == ptr || ll != x)
            return false;

        if (*endptr == '.' || dotCount == 3) {
            if (x & ~0xff)
                return false;
            address <<= 8;
        } else if (dotCount == 2) {
            if (x & ~0xffff)
                return false;
            address <<= 16;
        } else if (dotCount == 1) {
            if (x & ~0xffffff)
                return false;
            address <<= 24;
        }
        address |= x;

        if (dotCount == 3 && *endptr != '\0')
            return false;
        else if (dotCount == 3 || *endptr == '\0')
            return true;
        if (*endptr != '.')
            return false;

        ++dotCount;
        ptr = endptr + 1;
    }
    return false;
}


static const QChar *parseIp6(IPv6Address &address, const QChar *begin, const QChar *end)
{
    Q_ASSERT(begin != end);
    Buffer buffer;
    const QChar *ret = checkedToAscii(buffer, begin, end);
    if (ret)
        return ret;

    const char *ptr = buffer.data();

    // count the colons
    int colonCount = 0;
    int dotCount = 0;
    while (*ptr) {
        if (*ptr == ':')
            ++colonCount;
        if (*ptr == '.')
            ++dotCount;
        ++ptr;
    }
    // IPv4-in-IPv6 addresses are stricter in what they accept
    if (dotCount != 0 && dotCount != 3)
        return end;

    memset(&address, 0, sizeof address);
    if (colonCount == 2 && end - begin == 2) // "::"
        return nullptr;

    // if there's a double colon ("::"), this is how many zeroes it means
    int zeroWordsToFill;
    ptr = buffer.data();

    // there are two cases where 8 colons are allowed: at the ends
    // so test that before the colon-count test
    if ((ptr[0] == ':' && ptr[1] == ':') ||
            (ptr[end - begin - 2] == ':' && ptr[end - begin - 1] == ':')) {
        zeroWordsToFill = 9 - colonCount;
    } else if (colonCount < 2 || colonCount > 7) {
        return end;
    } else {
        zeroWordsToFill = 8 - colonCount;
    }
    if (dotCount)
        --zeroWordsToFill;

    int pos = 0;
    while (pos < 15) {
        if (*ptr == ':') {
            // empty field, we hope it's "::"
            if (zeroWordsToFill < 1)
                return begin + (ptr - buffer.data());
            if (pos == 0 || pos == colonCount * 2) {
                if (ptr[0] == '\0' || ptr[1] != ':')
                    return begin + (ptr - buffer.data());
                ++ptr;
            }
            pos += zeroWordsToFill * 2;
            zeroWordsToFill = 0;
            ++ptr;
            continue;
        }

        const char *endptr;
        bool ok;
        quint64 ll = qstrtoull(ptr, &endptr, 16, &ok);
        quint16 x = ll;

        // Reject malformed fields:
        // - failed to parse
        // - too many hex digits
        if (!ok || endptr > ptr + 4)
            return begin + (ptr - buffer.data());

        if (*endptr == '.') {
            // this could be an IPv4 address
            // it's only valid in the last element
            if (pos != 12)
                return begin + (ptr - buffer.data());

            IPv4Address ip4;
            if (!parseIp4Internal(ip4, ptr, false))
                return begin + (ptr - buffer.data());

            address[12] = ip4 >> 24;
            address[13] = ip4 >> 16;
            address[14] = ip4 >> 8;
            address[15] = ip4;
            return nullptr;
        }

        address[pos++] = x >> 8;
        address[pos++] = x & 0xff;

        if (*endptr == '\0')
            break;
        if (*endptr != ':')
            return begin + (endptr - buffer.data());
        ptr = endptr + 1;
    }
    return pos == 16 ? nullptr : end;
}

#if QT_VERSION < QT_VERSION_CHECK(5, 5, 0)

template <typename T>
inline T qFromUnaligned(const void *src)
{
    T dest;
    const size_t size = sizeof(T);
    memcpy(&dest, src, size);
    return dest;
}

#endif

/// parses v4-mapped addresses or the AnyIPv6 address and stores in \a a;
/// returns true if the address was one of those
static bool convertToIpv4(IPv4Address& a, const IPv6Address& a6, const HostAddress::ConversionMode mode)
{
    if (mode == HostAddress::StrictConversion)
        return false;

    const uchar *ptr = a6.c;
    if (qFromUnaligned<quint64>(ptr) != 0)
        return false;

    const quint32 mid = qFromBigEndian<quint32>(ptr + 8);
    if ((mid == 0xffff) && (mode & HostAddress::ConvertV4MappedToIPv4)) {
        a = qFromBigEndian<quint32>(ptr + 12);
        return true;
    }
    if (mid != 0)
        return false;

    const quint32 low = qFromBigEndian<quint32>(ptr + 12);
    if ((low == 0) && (mode & HostAddress::ConvertUnspecifiedAddress)) {
        a = 0;
        return true;
    }
    if ((low == 1) && (mode & HostAddress::ConvertLocalHost)) {
        a = INADDR_LOOPBACK;
        return true;
    }
    if ((low != 1) && (mode & HostAddress::ConvertV4CompatToIPv4)) {
        a = low;
        return true;
    }
    return false;
}


static QString qulltoa(qulonglong l, int base, const QChar _zero)
{
    ushort buff[65]; // length of MAX_ULLONG in base 2
    ushort *p = buff + 65;

    if (base != 10 || _zero.unicode() == '0') {
        while (l != 0) {
            int c = l % base;

            --p;

            if (c < 10)
                *p = '0' + c;
            else
                *p = c - 10 + 'a';

            l /= base;
        }
    }
    else {
        while (l != 0) {
            int c = l % base;

            *(--p) = _zero.unicode() + c;

            l /= base;
        }
    }

    return QString(reinterpret_cast<QChar *>(p), 65 - (p - buff));
}


static QString number(quint8 val, int base)
{
    QChar zero(0x30);
    return val ? qulltoa(val, base, zero) : zero;
}


static QChar toHex(uchar c)
{
    return QChar::fromLatin1("0123456789abcdef"[c & 0xF]);
}


static void IPAddresstoString(QString &appendTo, IPv4Address address)
{
    appendTo += QString::fromLatin1("%1.%2.%3.%4").arg(number(address >> 24, 10)).arg(number(address >> 16, 10)) \
                    .arg(number(address >> 8, 10)).arg(number(address, 10));
}


static void IPAddresstoString(QString &appendTo, const IPv6Address address)
{
    // the longest IPv6 address possible is:
    //   "1111:2222:3333:4444:5555:6666:255.255.255.255"
    // however, this function never generates that. The longest it does
    // generate without an IPv4 address is:
    //   "1111:2222:3333:4444:5555:6666:7777:8888"
    // and the longest with an IPv4 address is:
    //   "::ffff:255.255.255.255"
    static const int Ip6AddressMaxLen = sizeof "1111:2222:3333:4444:5555:6666:7777:8888";
    static const int Ip6WithIp4AddressMaxLen = sizeof "::ffff:255.255.255.255";

    // check for the special cases
    const quint64 zeroes[] = { 0, 0 };
    bool embeddedIp4 = false;

    // we consider embedded IPv4 for:
    //  ::ffff:x.x.x.x
    //  ::x.x.x.y  except if the x are 0 too
    if (memcmp(&address, zeroes, 10) == 0) {
        if (address[10] == 0xff && address[11] == 0xff) {
            embeddedIp4 = true;
        } else if (address[10] == 0 && address[11] == 0) {
            if (address[12] != 0 || address[13] != 0 || address[14] != 0) {
                embeddedIp4 = true;
            } else if (address[15] == 0) {
                appendTo.append(QLatin1String("::"));
                return;
            }
        }
    }

    // QString::reserve doesn't shrink, so it's fine to us
    appendTo.reserve(appendTo.size() +
                     (embeddedIp4 ? Ip6WithIp4AddressMaxLen : Ip6AddressMaxLen));

    // for finding where to place the "::"
    int zeroRunLength = 0; // in octets
    int zeroRunOffset = 0; // in octets
    for (int i = 0; i < 16; i += 2) {
        if (address[i] == 0 && address[i + 1] == 0) {
            // found a zero, scan forward to see how many more there are
            int j;
            for (j = i; j < 16; j += 2) {
                if (address[j] != 0 || address[j+1] != 0)
                    break;
            }

            if (j - i > zeroRunLength) {
                zeroRunLength = j - i;
                zeroRunOffset = i;
                i = j;
            }
        }
    }

    const QChar colon = u':';
    if (zeroRunLength < 4)
        zeroRunOffset = -1;
    else if (zeroRunOffset == 0)
        appendTo.append(colon);

    for (int i = 0; i < 16; i += 2) {
        if (i == zeroRunOffset) {
            appendTo.append(colon);
            i += zeroRunLength - 2;
            continue;
        }

        if (i == 12 && embeddedIp4) {
            IPv4Address ip4 = address[12] << 24 |
                              address[13] << 16 |
                              address[14] << 8 |
                              address[15];
            IPAddresstoString(appendTo, ip4);
            return;
        }

        if (address[i]) {
            if (address[i] >> 4) {
                appendTo.append(toHex(address[i] >> 4));
                appendTo.append(toHex(address[i] & 0xf));
                appendTo.append(toHex(address[i + 1] >> 4));
                appendTo.append(toHex(address[i + 1] & 0xf));
            } else if (address[i] & 0xf) {
                appendTo.append(toHex(address[i] & 0xf));
                appendTo.append(toHex(address[i + 1] >> 4));
                appendTo.append(toHex(address[i + 1] & 0xf));
            }
        } else if (address[i + 1] >> 4) {
            appendTo.append(toHex(address[i + 1] >> 4));
            appendTo.append(toHex(address[i + 1] & 0xf));
        } else {
            appendTo.append(toHex(address[i + 1] & 0xf));
        }

        if (i != 14)
            appendTo.append(colon);
    }
}


bool Netmask::setAddress(const HostAddress &address)
{
    static const quint8 zeroes[16] = { 0 };
    union {
        quint32 v4;
        quint8 v6[16];
    } ip;

    int netmask = 0;
    quint8 *ptr = ip.v6;
    quint8 *end;
    length = 255;

    if (address.protocol() == HostAddress::IPv4Protocol) {
        ip.v4 = qToBigEndian(address.toIPv4Address(nullptr));
        end = ptr + 4;
    } else if (address.protocol() == HostAddress::IPv6Protocol) {
        memcpy(ip.v6, address.toIPv6Address().c, 16);
        end = ptr + 16;
    } else {
        return false;
    }

    while (ptr < end) {
        switch (*ptr) {
        case 255:
            netmask += 8;
            ++ptr;
            continue;

        default:
            return false;       // invalid IP-style netmask

        case 254:
            ++netmask;
            Q_FALLTHROUGH();
        case 252:
            ++netmask;
            Q_FALLTHROUGH();
        case 248:
            ++netmask;
            Q_FALLTHROUGH();
        case 240:
            ++netmask;
            Q_FALLTHROUGH();
        case 224:
            ++netmask;
            Q_FALLTHROUGH();
        case 192:
            ++netmask;
            Q_FALLTHROUGH();
        case 128:
            ++netmask;
            Q_FALLTHROUGH();
        case 0:
            break;
        }
        break;
    }

    // confirm that the rest is only zeroes
    if (ptr < end && memcmp(ptr + 1, zeroes, end - ptr - 1) != 0)
        return false;

    length = netmask;
    return true;
}

static void clearBits(quint8 *where, int start, int end)
{
    Q_ASSERT(end == 32 || end == 128);
    if (start == end)
        return;

    // for the byte where 'start' is, clear the lower bits only
    quint8 bytemask = 256 - (1 << (8 - (start & 7)));
    where[start / 8] &= bytemask;

    // for the tail part, clear everything
    memset(where + (start + 7) / 8, 0, end / 8 - (start + 7) / 8);
}


HostAddress Netmask::address(HostAddress::NetworkLayerProtocol protocol) const
{
    if (length == 255 || protocol == HostAddress::AnyIPProtocol ||
            protocol == HostAddress::UnknownNetworkLayerProtocol) {
        return HostAddress();
    } else if (protocol == HostAddress::IPv4Protocol) {
        quint32 a;
        if (length == 0)
            a = 0;
        else if (length == 32)
            a = quint32(0xffffffff);
        else
            a = quint32(0xffffffff) >> (32 - length) << (32 - length);
        return HostAddress(a);
    } else {
        IPv6Address a6;
        memset(a6.c, 0xFF, sizeof(a6));
        clearBits(a6.c, length, 128);
        return HostAddress(a6);
    }
}


HostAddressPrivate::HostAddressPrivate()
    : ipv4(0)
    , protocol(HostAddress::UnknownNetworkLayerProtocol)
{
    memset(&ipv6, 0, sizeof(ipv6));
}


void HostAddressPrivate::setAddress(const IPv4Address ipv4_)
{
    ipv4 = ipv4_;
    protocol = HostAddress::IPv4Protocol;

    //create mapped address, except for a_ == 0 (any)
    ipv6.a6_64.c[0] = 0;
    if (ipv4) {
        ipv6.a6_32.c[2] = qToBigEndian(0xffff);
        ipv6.a6_32.c[3] = qToBigEndian(ipv4);
    } else {
        ipv6.a6_64.c[1] = 0;
    }
}


void HostAddressPrivate::setAddress(const IPv6Address ipv6_)
{
    protocol = HostAddress::IPv6Protocol;
    memcpy(&ipv6.a6, &ipv6_, sizeof(ipv6));
    ipv4 = 0;


    convertToIpv4(ipv4, ipv6.a6, HostAddress::ConversionMode(HostAddress::ConvertV4MappedToIPv4)
                  | HostAddress::ConversionMode(HostAddress::ConvertUnspecifiedAddress));
}


void HostAddressPrivate::clear()
{
    ipv4 = 0;
    protocol = HostAddress::UnknownNetworkLayerProtocol;
    memset(&ipv6, 0, sizeof(ipv6));
}

AddressClassification HostAddressPrivate::classify() const
{
    if (ipv4) {
            // This is an IPv4 address or an IPv6 v4-mapped address includes all
            // IPv6 v4-compat addresses, except for ::ffff:0.0.0.0 (because `a' is
            // zero). See setAddress(quint8*) below, which calls convertToIpv4(),
            // for details.
            // Source: RFC 5735
            if ((ipv4 & 0xff000000U) == 0x7f000000U)   // 127.0.0.0/8
                return LoopbackAddress;
            if ((ipv4 & 0xf0000000U) == 0xe0000000U)   // 224.0.0.0/4
                return MulticastAddress;
            if ((ipv4 & 0xffff0000U) == 0xa9fe0000U)   // 169.254.0.0/16
                return LinkLocalAddress;
            if ((ipv4 & 0xff000000U) == 0)             // 0.0.0.0/8 except 0.0.0.0 (handled below)
                return LocalNetAddress;
            if ((ipv4 & 0xf0000000U) == 0xf0000000U) { // 240.0.0.0/4
                if (ipv4 == 0xffffffffU)               // 255.255.255.255
                    return BroadcastAddress;
                return UnknownAddress;
            }

            // Not testing for PrivateNetworkAddress and TestNetworkAddress
            // since we don't need them yet.
            return GlobalAddress;
        }

        // As `a' is zero, this address is either ::ffff:0.0.0.0 or a non-v4-mapped IPv6 address.
        // Source: https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
        if (ipv6.a6_64.c[0]) {
            quint32 high16 = qFromBigEndian(ipv6.a6_32.c[0]) >> 16;
            switch (high16 >> 8) {
            case 0xff:                          // ff00::/8
                return MulticastAddress;
            case 0xfe:
                switch (high16 & 0xffc0) {
                case 0xfec0:                    // fec0::/10
                    return SiteLocalAddress;

                case 0xfe80:                    // fe80::/10
                    return LinkLocalAddress;

                default:                        // fe00::/9
                    return UnknownAddress;
                }
            case 0xfd:                          // fc00::/7
            case 0xfc:
                return UniqueLocalAddress;
            default:
                return GlobalAddress;
            }
        }

        quint64 low64 = qFromBigEndian(ipv6.a6_64.c[1]);
        if (low64 == 1)                             // ::1
            return LoopbackAddress;
        if (low64 >> 32 == 0xffff) {                // ::ffff:0.0.0.0/96
            Q_ASSERT(quint32(low64) == 0);
            return LocalNetAddress;
        }
        if (low64)                                  // not ::
            return GlobalAddress;

        if (protocol == HostAddress::UnknownNetworkLayerProtocol)
            return UnknownAddress;

        // only :: and 0.0.0.0 remain now
        return LocalNetAddress;
}


static bool parseIp6(const QString &address, IPv6Address &addr, QString *scopeId)
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)
    QStringRef tmp(&address);
#else
    QString tmp = address;
#endif
    int scopeIdPos = tmp.lastIndexOf(QLatin1Char('%'));
    if (scopeIdPos != -1) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)
        *scopeId = tmp.mid(scopeIdPos + 1).toString();
#else
        *scopeId = tmp.mid(scopeIdPos + 1);
#endif
        tmp.chop(tmp.size() - scopeIdPos);
    } else {
        scopeId->clear();
    }
    return parseIp6(addr, tmp.begin(), tmp.end()) == nullptr;
}


bool HostAddressPrivate::parse(const QString &ipString)
{
    protocol = HostAddress::UnknownNetworkLayerProtocol;
    QString simpleStr = ipString.simplified();
    if (simpleStr.isEmpty())
        return false;

    // All IPv6 addresses contain a ':', and may contain a '.'.
    if (simpleStr.contains(QLatin1Char(':'))) {
        IPv6Address maybeIp6;
        if (parseIp6(simpleStr, maybeIp6, &scopeId)) {
            setAddress(maybeIp6);
            return true;
        }
    }

    quint32 maybeIp4 = 0;
    if (parseIp4(maybeIp4, simpleStr.constBegin(), simpleStr.constEnd())) {
        setAddress(maybeIp4);
        return true;
    }

    return false;
}


HostAddress::HostAddress()
    : d(new HostAddressPrivate())
{

}


HostAddress::HostAddress(const HostAddress &copy)
    : d(copy.d)
{

}


HostAddress::HostAddress(HostAddress::SpecialAddress address)
    : d(new HostAddressPrivate())
{
    setAddress(address);
}


HostAddress::HostAddress(const QString &address)
    : d(new HostAddressPrivate())
{
    setAddress(address);
}


HostAddress::HostAddress(quint32 ip4Addr)
    : d(new HostAddressPrivate())
{
    setAddress(ip4Addr);
}


HostAddress::HostAddress(quint8 *ip6Addr)
    : d(new HostAddressPrivate())
{
    setAddress(ip6Addr);
}


HostAddress::HostAddress(const quint8 *ip6Addr)
    : d(new HostAddressPrivate())
{
    setAddress(ip6Addr);
}


HostAddress::HostAddress(const IPv6Address &ip6Addr)
    : d(new HostAddressPrivate())
{
    setAddress(ip6Addr);
}


HostAddress::HostAddress(const sockaddr *sockaddr)
    : d(new HostAddressPrivate())
{
    switch (sockaddr->sa_family) {
    case AF_INET: {
        setAddress(ntohl(((sockaddr_in *) sockaddr)->sin_addr.s_addr));
        break;
    }
    case AF_INET6: {
        sockaddr_in6 *sa6 = (sockaddr_in6 *) sockaddr;
        setAddress(sa6->sin6_addr.s6_addr);
        if (sa6->sin6_scope_id)
            setScopeId(QString::number(sa6->sin6_scope_id));
        break;
    }
    default:
        qWarning() << "Unknown address type when get hostname";
    }
}


HostAddress::~HostAddress()
{
}


HostAddress &HostAddress::operator=(const HostAddress &address)
{
    d = address.d;
    return *this;
}


HostAddress &HostAddress::operator=(SpecialAddress address)
{
    setAddress(address);
    return *this;
}


bool HostAddress::isEqual(const HostAddress &other, ConversionMode mode) const
{
    if (d == other.d)
        return true;

    if (d->protocol == IPv4Protocol) {
        switch (other.d->protocol) {
        case IPv4Protocol:
            return d->ipv4 == other.d->ipv4;
        case IPv6Protocol:
            quint32 a4;
            return convertToIpv4(a4, other.d->ipv6.a6, mode) && (a4 == d->ipv4);
        case AnyIPProtocol:
            return (mode & ConvertUnspecifiedAddress) && d->ipv4 == 0;
        case UnknownNetworkLayerProtocol:
            return false;
        }
    }

    if (d->protocol == IPv6Protocol) {
        switch (other.d->protocol) {
        case IPv4Protocol:
            quint32 a4;
            return convertToIpv4(a4, d->ipv6.a6, mode) && (a4 == other.d->ipv4);
        case IPv6Protocol:
            return memcmp(&d->ipv6, &other.d->ipv6, sizeof(IPv6Address)) == 0;
        case AnyIPProtocol:
            return (mode & ConvertUnspecifiedAddress)
                && (other.d->ipv6.a6_64.c[0] == 0) && (other.d->ipv6.a6_64.c[1] == 0);
        case UnknownNetworkLayerProtocol:
            return false;
        }
    }

    if ((d->protocol == HostAddress::AnyIPProtocol)
        && (mode & HostAddress::ConvertUnspecifiedAddress)) {
        switch (other.d->protocol) {
        case IPv4Protocol:
            return other.d->ipv4 == 0;
        case IPv6Protocol:
            return (other.d->ipv6.a6_64.c[0] == 0) && (other.d->ipv6.a6_64.c[1] == 0);
        default:
            break;
        }
    }

    return d->protocol == other.d->protocol;
}


bool HostAddress::operator ==(const HostAddress &other) const
{
    return d == other.d || isEqual(other, StrictConversion);
}


bool HostAddress::operator ==(SpecialAddress other) const
{
    quint32 ip4 = INADDR_ANY;
    switch (other) {
    case Null:
        return d->protocol == UnknownNetworkLayerProtocol;

    case Broadcast:
        ip4 = INADDR_BROADCAST;
        break;

    case LocalHost:
        ip4 = INADDR_LOOPBACK;
        break;

    case Any:
        return d->protocol == AnyIPProtocol;

    case AnyIPv4:
        break;

    case LocalHostIPv6:
    case AnyIPv6:
        if (d->protocol == IPv6Protocol) {
            quint64 second = quint8(other == LocalHostIPv6);  // 1 for localhost, 0 for any
            return d->ipv6.a6_64.c[0] == 0 && d->ipv6.a6_64.c[1] == qToBigEndian(second);
        }
        return false;
    }

    // common IPv4 part
    return d->protocol == IPv4Protocol && d->ipv4 == ip4;
}


void HostAddress::swap(HostAddress &other) noexcept
{
    d.swap(other.d);
}


void HostAddress::clear()
{
    d.detach();
    d->clear();
}


void HostAddress::setAddress(const IPv4Address ipv4)
{
    d.detach();
    d->setAddress(ipv4);
}


void HostAddress::setAddress(const IPv6Address &ipv6)
{
    d.detach();
    d->setAddress(ipv6);
}


void HostAddress::setAddress(const quint8* ipv6)
{
    IPv6Address ip;
    memcpy(&ip, ipv6, sizeof(ip));

    d.detach();
    d->setAddress(ip);
}


bool HostAddress::setAddress(const QString &ipString)
{
    d.detach();
    return d->parse(ipString);
}


void HostAddress::setAddress(HostAddress::SpecialAddress address)
{
    clear();

    IPv6Address ip6;
    memset(&ip6, 0, sizeof ip6);
    quint32 ip4 = INADDR_ANY;

    switch (address) {
    case Null:
        return;

    case Broadcast:
        ip4 = INADDR_BROADCAST;
        break;
    case LocalHost:
        ip4 = INADDR_LOOPBACK;
        break;
    case AnyIPv4:
        break;

    case LocalHostIPv6:
        ip6[15] = 1;
        Q_FALLTHROUGH();
    case AnyIPv6:
        d->setAddress(ip6);
        return;
    case Any:
        d->protocol = AnyIPProtocol;
        return;
    }

    // common IPv4 part
    d->setAddress(ip4);
}


bool HostAddress::isNull() const
{
    return d->protocol == HostAddress::UnknownNetworkLayerProtocol;
}


HostAddress::NetworkLayerProtocol HostAddress::protocol() const
{
    return HostAddress::NetworkLayerProtocol(d->protocol);
}


IPv4Address HostAddress::toIPv4Address(bool *ok) const
{
    quint32 dummy;
    if (ok)
        *ok = d->protocol == HostAddress::IPv4Protocol || d->protocol == HostAddress::AnyIPProtocol
              || (d->protocol == HostAddress::IPv6Protocol
                  && convertToIpv4(dummy, d->ipv6.a6, HostAddress::ConversionMode(HostAddress::ConvertV4MappedToIPv4)
                                                                | HostAddress::ConversionMode(HostAddress::ConvertUnspecifiedAddress)));
    return d->ipv4;
}


IPv6Address HostAddress::toIPv6Address() const
{
    return d->ipv6.a6;
}


bool HostAddress::isInSubnet(const HostAddress &subnet, int netmask) const
{
    if (subnet.protocol() != d->protocol || netmask < 0)
        return false;

    union {
        quint32 ip;
        quint8 data[4];
    } ip4, net4;
    const quint8 *ip;
    const quint8 *net;
    if (d->protocol == HostAddress::IPv4Protocol) {
        if (netmask > 32)
            netmask = 32;
        ip4.ip = qToBigEndian(d->ipv4);
        net4.ip = qToBigEndian(subnet.d->ipv4);
        ip = ip4.data;
        net = net4.data;
    } else if (d->protocol == HostAddress::IPv6Protocol) {
        if (netmask > 128)
            netmask = 128;
        ip = d->ipv6.a6.c;
        net = subnet.d->ipv6.a6.c;
    } else {
        return false;
    }

    if (netmask >= 8 && memcmp(ip, net, netmask / 8) != 0)
        return false;
    if ((netmask & 7) == 0)
        return true;

    // compare the last octet now
    quint8 bytemask = 256 - (1 << (8 - (netmask & 7)));
    quint8 ipbyte = ip[netmask / 8];
    quint8 netbyte = net[netmask / 8];
    return (ipbyte & bytemask) == (netbyte & bytemask);
}


bool HostAddress::isInSubnet(const QPair<HostAddress, int> &subnet) const
{
    return isInSubnet(subnet.first, subnet.second);
}


QPair<HostAddress, int> HostAddress::parseSubnet(const QString &subnet)
{
    // We support subnets in the form:
    //   ddd.ddd.ddd.ddd/nn
    //   ddd.ddd.ddd/nn
    //   ddd.ddd/nn
    //   ddd/nn
    //   ddd.ddd.ddd.
    //   ddd.ddd.ddd
    //   ddd.ddd.
    //   ddd.ddd
    //   ddd.
    //   ddd
    //   <ipv6-address>/nn
    //
    //  where nn can be an IPv4-style netmask for the IPv4 forms

    const QPair<HostAddress, int> invalid = qMakePair(HostAddress(), -1);
    if (subnet.isEmpty())
        return invalid;

    int slash = subnet.indexOf(QLatin1Char('/'));
    QString netStr(subnet);
    if (slash != -1)
        netStr.truncate(slash);

    int netmask = -1;
    bool isIpv6 = netStr.contains(QLatin1Char(':'));

    if (slash != -1) {
        // is the netmask given in IP-form or in bit-count form?
        if (!isIpv6 && subnet.indexOf(QLatin1Char('.'), slash + 1) != -1) {
            // IP-style, convert it to bit-count form
            HostAddress mask;
            Netmask parser;
            if (!mask.setAddress(subnet.mid(slash + 1)))
                return invalid;
            if (!parser.setAddress(mask))
                return invalid;
            netmask = parser.prefixLength();
        } else {
            bool ok;
            netmask = subnet.midRef(slash + 1).toUInt(&ok);
            if (!ok)
                return invalid;     // failed to parse the subnet
        }
    }

    if (isIpv6) {
        // looks like it's an IPv6 address
        if (netmask > 128)
            return invalid;     // invalid netmask
        if (netmask < 0)
            netmask = 128;

        HostAddress net;
        if (!net.setAddress(netStr))
            return invalid;     // failed to parse the IP

        clearBits(net.d->ipv6.a6.c, netmask, 128);
        return qMakePair(net, netmask);
    }

    if (netmask > 32)
        return invalid;         // invalid netmask

    // parse the address manually
    QStringList parts = netStr.split(QLatin1Char('.'));
    if (parts.isEmpty() || parts.count() > 4)
        return invalid;         // invalid IPv4 address

    if (parts.last().isEmpty())
        parts.removeLast();

    quint32 addr = 0;
    for (int i = 0; i < parts.count(); ++i) {
        bool ok;
        uint byteValue = parts.at(i).toUInt(&ok);
        if (!ok || byteValue > 255)
            return invalid;     // invalid IPv4 address

        addr <<= 8;
        addr += byteValue;
    }
    addr <<= 8 * (4 - parts.count());
    if (netmask == -1) {
        netmask = 8 * parts.count();
    } else if (netmask == 0) {
        // special case here
        // x86's instructions "shr" and "shl" do not operate when
        // their argument is 32, so the code below doesn't work as expected
        addr = 0;
    } else if (netmask != 32) {
        // clear remaining bits
        quint32 mask = quint32(0xffffffff) >> (32 - netmask) << (32 - netmask);
        addr &= mask;
    }

    return qMakePair(HostAddress(addr), netmask);
}


bool HostAddress::isLoopback() const
{
    return d->classify() == LoopbackAddress;
}


bool HostAddress::isGlobal() const
{
    return d->classify() & GlobalAddress;   // GlobalAddress is a bit
}

bool HostAddress::isLinkLocal() const
{
    return d->classify() == LinkLocalAddress;
}


bool HostAddress::isSiteLocal() const
{
    return d->classify() == SiteLocalAddress;
}

bool HostAddress::isUniqueLocalUnicast() const
{
    return d->classify() == UniqueLocalAddress;
}


bool HostAddress::isMulticast() const
{
    return d->classify() == MulticastAddress;
}


bool HostAddress::isBroadcast() const
{
    return d->classify() == BroadcastAddress;
}


QString HostAddress::toString() const
{
    QString s;
    if (d->protocol == HostAddress::IPv4Protocol
        || d->protocol == HostAddress::AnyIPProtocol) {
        quint32 i = toIPv4Address(nullptr);
        IPAddresstoString(s, i);
    } else if (d->protocol == HostAddress::IPv6Protocol) {
        IPAddresstoString(s, d->ipv6.a6);
        if (!d->scopeId.isEmpty())
            s.append(QLatin1Char('%') + d->scopeId);
    }
    return s;
}


QString HostAddress::scopeId() const
{
    return (d->protocol == IPv6Protocol) ? d->scopeId : QString();
}


void HostAddress::setScopeId(const QString &id)
{
    d.detach();
    if (d->protocol == IPv6Protocol)
        d->scopeId = id;
}


QList<HostAddress> HostAddress::getHostAddressByName(const QString &hostName)
{
    // IDN support
    QByteArray aceHostname = QUrl::toAce(hostName);
    if (aceHostname.isEmpty()) {
        return QList<HostAddress>();
    }

#ifdef Q_OS_WIN
    initWinSock();
#endif

    addrinfo *res = nullptr;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
#ifdef Q_ADDRCONFIG
    hints.ai_flags = Q_ADDRCONFIG;
#endif

    int result = getaddrinfo(aceHostname.constData(), nullptr, &hints, &res);
# ifdef Q_ADDRCONFIG
    if (result == EAI_BADFLAGS) {
        // if the lookup failed with AI_ADDRCONFIG set, try again without it
        hints.ai_flags = 0;
        result = getaddrinfo(aceHostname.constData(), nullptr, &hints, &res);
    }
# endif

    QList<HostAddress> addresses;
    if (result == 0) {
        addrinfo *node = res;

        while (node) {
            switch (node->ai_family) {
            case AF_INET: {
                HostAddress addr;
                addr.setAddress(ntohl(((sockaddr_in *) node->ai_addr)->sin_addr.s_addr));
                if (!addresses.contains(addr))
                    addresses.append(addr);
                break;
            }
            case AF_INET6: {
                HostAddress addr;
                sockaddr_in6 *sa6 = (sockaddr_in6 *) node->ai_addr;
                addr.setAddress(sa6->sin6_addr.s6_addr);
                if (sa6->sin6_scope_id)
                    addr.setScopeId(QString::number(sa6->sin6_scope_id));
                if (!addresses.contains(addr))
                    addresses.append(addr);
                break;
            }
            default:
                qWarning() << "Unknown address type when get hostname";
            }
            node = node->ai_next;
        }
        if (addresses.isEmpty()) {
            qWarning() << "Unknown address type when get hostname";
        }
        freeaddrinfo(res);
    }
#ifdef Q_OS_WIN
    freeWinSock();
#endif
    return addresses;
}

uint qHash(const HostAddress &key, uint seed) noexcept
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 4, 0))
    return qHashBits(key.d->ipv6.a6.c, 16, seed);
#else
    return qHash(QByteArray(reinterpret_cast<const char*>(key.d->ipv6.a6.c), 16), seed);
#endif
}

QTNETWORKNG_NAMESPACE_END


QDebug operator<<(QDebug out, const QTNETWORKNG_NAMESPACE::HostAddress &t)
{
    return out << t.toString();
}
