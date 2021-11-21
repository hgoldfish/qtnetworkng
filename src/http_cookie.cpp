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

#include <QtCore/qlocale.h>
#include <QtCore/qregularexpression.h>
#include <QtCore/qdebug.h>
#include "../include/hostaddress.h"
#include "../include/http_cookie.h"

QTNETWORKNG_NAMESPACE_BEGIN


class HttpCookiePrivate: public QSharedData
{
public:
    HttpCookiePrivate();
    static QList<HttpCookie> parseSetCookieHeaderLine(const QByteArray &cookieString);
public:
    QDateTime expirationDate;
    QString domain;
    QString path;
    QString comment;
    QByteArray name;
    QByteArray value;
    HttpCookie::SameSite sameSite;
    bool secure;
    bool httpOnly;
};


class HttpCookieJarPrivate
{
public:
    QList<HttpCookie> allCookies;
};


HttpCookiePrivate::HttpCookiePrivate()
    : sameSite(HttpCookie::SameSite::Default)
    , secure(false)
    , httpOnly(false)
{

}


static inline bool isLWS(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}


static int nextNonWhitespace(const QByteArray &text, int from)
{
    // RFC 2616 defines linear whitespace as:
    //  LWS = [CRLF] 1*( SP | HT )
    // We ignore the fact that CRLF must come as a pair at this point
    // It's an invalid HTTP header if that happens.
    while (from < text.length()) {
        if (isLWS(text.at(from))) {
            ++from;
        } else {
            return from;        // non-whitespace
        }
    }

    // reached the end
    return text.length();
}


HttpCookie::HttpCookie(const QByteArray &name, const QByteArray &value)
    : d(new HttpCookiePrivate())
{
    qRegisterMetaType<HttpCookie>();
    qRegisterMetaType<QList<HttpCookie> >();

    d->name = name;
    d->value = value;
}


HttpCookie::HttpCookie(const HttpCookie &other)
    : d(other.d) {}


HttpCookie::~HttpCookie()
{
    d = nullptr;
}


HttpCookie &HttpCookie::operator=(const HttpCookie &other)
{
    d = other.d;
    return *this;
}


bool HttpCookie::operator==(const HttpCookie &other) const
{
    if (d == other.d) {
        return true;
    }
    return d->name == other.d->name &&
        d->value == other.d->value &&
        d->expirationDate.toUTC() == other.d->expirationDate.toUTC() &&
        d->domain == other.d->domain &&
        d->path == other.d->path &&
        d->secure == other.d->secure &&
        d->comment == other.d->comment &&
        d->sameSite == other.d->sameSite;
}


bool HttpCookie::hasSameIdentifier(const HttpCookie &other) const
{
    return d->name == other.d->name && d->domain == other.d->domain && d->path == other.d->path;
}


bool HttpCookie::isSecure() const
{
    return d->secure;
}


void HttpCookie::setSecure(bool enable)
{
    d->secure = enable;
}


HttpCookie::SameSite HttpCookie::sameSitePolicy() const
{
    return d->sameSite;
}


void HttpCookie::setSameSitePolicy(HttpCookie::SameSite sameSite)
{
    d->sameSite = sameSite;
}


bool HttpCookie::isHttpOnly() const
{
    return d->httpOnly;
}


void HttpCookie::setHttpOnly(bool enable)
{
    d->httpOnly = enable;
}


bool HttpCookie::isSessionCookie() const
{
    return !d->expirationDate.isValid();
}


QDateTime HttpCookie::expirationDate() const
{
    return d->expirationDate;
}


void HttpCookie::setExpirationDate(const QDateTime &date)
{
    d->expirationDate = date;
}


QString HttpCookie::domain() const
{
    return d->domain;
}


void HttpCookie::setDomain(const QString &domain)
{
    d->domain = domain;
}


QString HttpCookie::path() const
{
    return d->path;
}


void HttpCookie::setPath(const QString &path)
{
    d->path = path;
}


QByteArray HttpCookie::name() const
{
    return d->name;
}


void HttpCookie::setName(const QByteArray &cookieName)
{
    d->name = cookieName;
}


QByteArray HttpCookie::value() const
{
    return d->value;
}


void HttpCookie::setValue(const QByteArray &value)
{
    d->value = value;
}


static QPair<QByteArray, QByteArray> nextField(const QByteArray &text, int &position, bool isNameValue)
{
    // format is one of:
    //    (1)  token
    //    (2)  token = token
    //    (3)  token = quoted-string
    const int length = text.length();
    position = nextNonWhitespace(text, position);

    int semiColonPosition = text.indexOf(';', position);
    if (semiColonPosition < 0)
        semiColonPosition = length; //no ';' means take everything to end of string

    int equalsPosition = text.indexOf('=', position);
    if (equalsPosition < 0 || equalsPosition > semiColonPosition) {
        if (isNameValue)
            return qMakePair(QByteArray(), QByteArray()); //'=' is required for name-value-pair (RFC6265 section 5.2, rule 2)
        equalsPosition = semiColonPosition; //no '=' means there is an attribute-name but no attribute-value
    }

    QByteArray first = text.mid(position, equalsPosition - position).trimmed();
    QByteArray second;
    int secondLength = semiColonPosition - equalsPosition - 1;
    if (secondLength > 0)
        second = text.mid(equalsPosition + 1, secondLength).trimmed();

    position = semiColonPosition;
    return qMakePair(first, second);
}


namespace {
QByteArray sameSiteToRawString(HttpCookie::SameSite samesite)
{
    switch (samesite) {
    case HttpCookie::SameSite::None:
        return QByteArrayLiteral("None");
    case HttpCookie::SameSite::Lax:
        return QByteArrayLiteral("Lax");
    case HttpCookie::SameSite::Strict:
        return QByteArrayLiteral("Strict");
    case HttpCookie::SameSite::Default:
        break;
    }
    return QByteArray();
}


HttpCookie::SameSite sameSiteFromRawString(QByteArray str)
{
    str = str.toLower();
    if (str == QByteArrayLiteral("none"))
        return HttpCookie::SameSite::None;
    if (str == QByteArrayLiteral("lax"))
        return HttpCookie::SameSite::Lax;
    if (str == QByteArrayLiteral("strict"))
        return HttpCookie::SameSite::Strict;
    return HttpCookie::SameSite::Default;
}
} // namespace


QByteArray HttpCookie::toRawForm(RawForm form) const
{
    QByteArray result;
    if (d->name.isEmpty())
        return result;          // not a valid cookie

    result = d->name;
    result += '=';
    result += d->value;

    if (form == Full) {
        // same as above, but encoding everything back
        if (isSecure())
            result += "; secure";
        if (isHttpOnly())
            result += "; HttpOnly";
        if (d->sameSite != SameSite::Default) {
            result += "; SameSite=";
            result += sameSiteToRawString(d->sameSite);
        }
        if (!isSessionCookie()) {
            result += "; expires=";
            result += QLocale::c().toString(d->expirationDate.toUTC(),
                                            QLatin1String("ddd, dd-MMM-yyyy hh:mm:ss 'GMT")).toLatin1();
        }
        if (!d->domain.isEmpty()) {
            result += "; domain=";
            if (d->domain.startsWith(QLatin1Char('.'))) {
                result += '.';
                result += QUrl::toAce(d->domain.mid(1));
            } else {
                HostAddress hostAddr(d->domain);
                if (hostAddr.protocol() == HostAddress::IPv6Protocol) {
                    result += '[';
                    result += d->domain.toUtf8();
                    result += ']';
                } else {
                    result += QUrl::toAce(d->domain);
                }
            }
        }
        if (!d->path.isEmpty()) {
            result += "; path=";
            result += d->path.toUtf8();
        }
    }
    return result;
}

static const char zones[] =
    "pst\0" // -8
    "pdt\0"
    "mst\0" // -7
    "mdt\0"
    "cst\0" // -6
    "cdt\0"
    "est\0" // -5
    "edt\0"
    "ast\0" // -4
    "nst\0" // -3
    "gmt\0" // 0
    "utc\0"
    "bst\0"
    "met\0" // 1
    "eet\0" // 2
    "jst\0" // 9
    "\0";
static const int zoneOffsets[] = {-8, -8, -7, -7, -6, -6, -5, -5, -4, -3, 0, 0, 0, 1, 2, 9 };

static const char months[] =
    "jan\0"
    "feb\0"
    "mar\0"
    "apr\0"
    "may\0"
    "jun\0"
    "jul\0"
    "aug\0"
    "sep\0"
    "oct\0"
    "nov\0"
    "dec\0"
    "\0";

static inline bool isNumber(char s)
{ return s >= '0' && s <= '9'; }

static inline bool isTerminator(char c)
{ return c == '\n' || c == '\r'; }

static inline bool isValueSeparator(char c)
{ return isTerminator(c) || c == ';'; }

static inline bool isWhitespace(char c)
{ return c == ' '  || c == '\t'; }


static bool checkStaticArray(int &val, const QByteArray &dateString, int at, const char *array, int size)
{
    if (dateString[at] < 'a' || dateString[at] > 'z')
        return false;
    if (val == -1 && dateString.length() >= at + 3) {
        int j = 0;
        int i = 0;
        while (i <= size) {
            const char *str = array + i;
            if (str[0] == dateString[at]
                && str[1] == dateString[at + 1]
                && str[2] == dateString[at + 2]) {
                val = j;
                return true;
            }
            i += int(strlen(str)) + 1;
            ++j;
        }
    }
    return false;
}

//#define PARSEDATESTRINGDEBUG

#define ADAY   1
#define AMONTH 2
#define AYEAR  4

/*
    Parse all the date formats that Firefox can.

    The official format is:
    expires=ddd(d)?, dd-MMM-yyyy hh:mm:ss GMT

    But browsers have been supporting a very wide range of date
    strings. To work on many sites we need to support more then
    just the official date format.

    For reference see Firefox's PR_ParseTimeStringToExplodedTime in
    prtime.c. The Firefox date parser is coded in a very complex way
    and is slightly over ~700 lines long.  While this implementation
    will be slightly slower for the non standard dates it is smaller,
    more readable, and maintainable.

    Or in their own words:
        "} // else what the hell is this."
*/
static QDateTime parseDateString(const QByteArray &dateString)
{
    QTime time;
    // placeholders for values when we are not sure it is a year, month or day
    int unknown[3] = {-1, -1, -1};
    int month = -1;
    int day = -1;
    int year = -1;
    int zoneOffset = -1;

    // hour:minute:second.ms pm
    QRegularExpression timeRx(QLatin1String("(\\d{1,2}):(\\d{1,2})(:(\\d{1,2})|)(\\.(\\d{1,3})|)((\\s{0,}(am|pm))|)"));

    int at = 0;
    while (at < dateString.length()) {
#ifdef PARSEDATESTRINGDEBUG
        qtng_debug << dateString.mid(at);
#endif
        bool isNum = isNumber(dateString[at]);

        // Month
        if (!isNum
            && checkStaticArray(month, dateString, at, months, sizeof(months)- 1)) {
            ++month;
#ifdef PARSEDATESTRINGDEBUG
            qtng_debug << "Month:" << month;
#endif
            at += 3;
            continue;
        }
        // Zone
        if (!isNum
            && zoneOffset == -1
            && checkStaticArray(zoneOffset, dateString, at, zones, sizeof(zones)- 1)) {
            int sign = (at >= 0 && dateString[at - 1] == '-') ? -1 : 1;
            zoneOffset = sign * zoneOffsets[zoneOffset] * 60 * 60;
#ifdef PARSEDATESTRINGDEBUG
            qtng_debug << "Zone:" << month;
#endif
            at += 3;
            continue;
        }
        // Zone offset
        if (!isNum
            && (zoneOffset == -1 || zoneOffset == 0) // Can only go after gmt
            && (dateString[at] == '+' || dateString[at] == '-')
            && (at == 0
                || isWhitespace(dateString[at - 1])
                || dateString[at - 1] == ','
                || (at >= 3
                    && (dateString[at - 3] == 'g')
                    && (dateString[at - 2] == 'm')
                    && (dateString[at - 1] == 't')))) {

            int end = 1;
            while (end < 5 && dateString.length() > at+end
                   && dateString[at + end] >= '0' && dateString[at + end] <= '9')
                ++end;
            int minutes = 0;
            int hours = 0;
            switch (end - 1) {
            case 4:
                minutes = atoi(dateString.mid(at + 3, 2).constData());
#if QT_VERSION >= QT_VERSION_CHECK(5, 8, 0)
                Q_FALLTHROUGH();
#endif
            case 2:
                hours = atoi(dateString.mid(at + 1, 2).constData());
                break;
            case 1:
                hours = atoi(dateString.mid(at + 1, 1).constData());
                break;
            default:
                at += end;
                continue;
            }
            if (end != 1) {
                int sign = dateString[at] == '-' ? -1 : 1;
                zoneOffset = sign * ((minutes * 60) + (hours * 60 * 60));
#ifdef PARSEDATESTRINGDEBUG
                qtng_debug << "Zone offset:" << zoneOffset << hours << minutes;
#endif
                at += end;
                continue;
            }
        }

        // Time
        if (isNum && time.isNull()
            && dateString.length() >= at + 3
            && (dateString[at + 2] == ':' || dateString[at + 1] == ':')) {
            // While the date can be found all over the string the format
            // for the time is set and a nice regexp can be used.
            QRegularExpressionMatch match;
            int pos = QString::fromLatin1(dateString).indexOf(timeRx, at, &match);
            if (pos != -1) {
                QStringList list = match.capturedTexts();
                int h = match.captured(1).toInt();
                int m = match.captured(2).toInt();
                int s = match.captured(4).toInt();
                int ms = match.captured(6).toInt();
                QString ampm = match.captured(9);
                if (h < 12 && !ampm.isEmpty())
                    if (ampm == QLatin1String("pm"))
                        h += 12;
                time = QTime(h, m, s, ms);
#ifdef PARSEDATESTRINGDEBUG
                qtng_debug << "Time:" << list << timeRx.matchedLength();
#endif
                at += match.capturedLength();
                continue;
            }
        }

        // 4 digit Year
        if (isNum
            && year == -1
            && dateString.length() > at + 3) {
            if (isNumber(dateString[at + 1])
                && isNumber(dateString[at + 2])
                && isNumber(dateString[at + 3])) {
                year = atoi(dateString.mid(at, 4).constData());
                at += 4;
#ifdef PARSEDATESTRINGDEBUG
                qtng_debug << "Year:" << year;
#endif
                continue;
            }
        }

        // a one or two digit number
        // Could be month, day or year
        if (isNum) {
            int length = 1;
            if (dateString.length() > at + 1
                && isNumber(dateString[at + 1]))
                ++length;
            int x = atoi(dateString.mid(at, length).constData());
            if (year == -1 && (x > 31 || x == 0)) {
                year = x;
            } else {
                if (unknown[0] == -1) unknown[0] = x;
                else if (unknown[1] == -1) unknown[1] = x;
                else if (unknown[2] == -1) unknown[2] = x;
            }
            at += length;
#ifdef PARSEDATESTRINGDEBUG
            qtng_debug << "Saving" << x;
#endif
            continue;
        }

        // Unknown character, typically a weekday such as 'Mon'
        ++at;
    }

    // Once we are done parsing the string take the digits in unknown
    // and determine which is the unknown year/month/day

    int couldBe[3] = { 0, 0, 0 };
    int unknownCount = 3;
    for (int i = 0; i < unknownCount; ++i) {
        if (unknown[i] == -1) {
            couldBe[i] = ADAY | AYEAR | AMONTH;
            unknownCount = i;
            continue;
        }

        if (unknown[i] >= 1)
            couldBe[i] = ADAY;

        if (month == -1 && unknown[i] >= 1 && unknown[i] <= 12)
            couldBe[i] |= AMONTH;

        if (year == -1)
            couldBe[i] |= AYEAR;
    }

    // For any possible day make sure one of the values that could be a month
    // can contain that day.
    // For any possible month make sure one of the values that can be a
    // day that month can have.
    // Example: 31 11 06
    // 31 can't be a day because 11 and 6 don't have 31 days
    for (int i = 0; i < unknownCount; ++i) {
        int currentValue = unknown[i];
        bool findMatchingMonth = couldBe[i] & ADAY && currentValue >= 29;
        bool findMatchingDay = couldBe[i] & AMONTH;
        if (!findMatchingMonth || !findMatchingDay)
            continue;
        for (int j = 0; j < 3; ++j) {
            if (j == i)
                continue;
            for (int k = 0; k < 2; ++k) {
                if (k == 0 && !(findMatchingMonth && (couldBe[j] & AMONTH)))
                    continue;
                else if (k == 1 && !(findMatchingDay && (couldBe[j] & ADAY)))
                    continue;
                int m = currentValue;
                int d = unknown[j];
                if (k == 0)
                    qSwap(m, d);
                if (m == -1) m = month;
                bool found = true;
                switch(m) {
                    case 2:
                        // When we get 29 and the year ends up having only 28
                        // See date.isValid below
                        // Example: 29 23 Feb
                        if (d <= 29)
                            found = false;
                        break;
                    case 4: case 6: case 9: case 11:
                        if (d <= 30)
                            found = false;
                        break;
                    default:
                        if (d > 0 && d <= 31)
                            found = false;
                }
                if (k == 0) findMatchingMonth = found;
                else if (k == 1) findMatchingDay = found;
            }
        }
        if (findMatchingMonth)
            couldBe[i] &= ~ADAY;
        if (findMatchingDay)
            couldBe[i] &= ~AMONTH;
    }

    // First set the year/month/day that have been deduced
    // and reduce the set as we go along to deduce more
    for (int i = 0; i < unknownCount; ++i) {
        int unset = 0;
        for (int j = 0; j < 3; ++j) {
            if (couldBe[j] == ADAY && day == -1) {
                day = unknown[j];
                unset |= ADAY;
            } else if (couldBe[j] == AMONTH && month == -1) {
                month = unknown[j];
                unset |= AMONTH;
            } else if (couldBe[j] == AYEAR && year == -1) {
                year = unknown[j];
                unset |= AYEAR;
            } else {
                // common case
                break;
            }
            couldBe[j] &= ~unset;
        }
    }

    // Now fallback to a standardized order to fill in the rest with
    for (int i = 0; i < unknownCount; ++i) {
        if (couldBe[i] & AMONTH && month == -1) month = unknown[i];
        else if (couldBe[i] & ADAY && day == -1) day = unknown[i];
        else if (couldBe[i] & AYEAR && year == -1) year = unknown[i];
    }
#ifdef PARSEDATESTRINGDEBUG
        qtng_debug << "Final set" << year << month << day;
#endif

    if (year == -1 || month == -1 || day == -1) {
#ifdef PARSEDATESTRINGDEBUG
        qtng_debug << "Parser failure" << year << month << day;
#endif
        return QDateTime();
    }

    // Y2k behavior
    int y2k = 0;
    if (year < 70)
        y2k = 2000;
    else if (year < 100)
        y2k = 1900;

    QDate date(year + y2k, month, day);

    // When we were given a bad cookie that when parsed
    // set the day to 29 and the year to one that doesn't
    // have the 29th of Feb rather then adding the extra
    // complicated checking earlier just swap here.
    // Example: 29 23 Feb
    if (!date.isValid())
        date = QDate(day + y2k, month, year);

    QDateTime dateTime(date, time, Qt::UTC);

    if (zoneOffset != -1) {
        dateTime = dateTime.addSecs(zoneOffset);
    }
    if (!dateTime.isValid())
        return QDateTime();
    return dateTime;
}


QList<HttpCookie> HttpCookie::parseCookies(const QByteArray &cookieString)
{
    // cookieString can be a number of set-cookie header strings joined together
    // by \n, parse each line separately.
    QList<HttpCookie> cookies;
    QList<QByteArray> list = cookieString.split('\n');
    for (int a = 0; a < list.size(); a++) {
        cookies << HttpCookiePrivate::parseSetCookieHeaderLine(list.at(a));
    }
    return cookies;
}


QList<HttpCookie> HttpCookiePrivate::parseSetCookieHeaderLine(const QByteArray &cookieString)
{
    // According to http://wp.netscape.com/newsref/std/cookie_spec.html,<
    // the Set-Cookie response header is of the format:
    //
    //   Set-Cookie: NAME=VALUE; expires=DATE; path=PATH; domain=DOMAIN_NAME; secure
    //
    // where only the NAME=VALUE part is mandatory
    //
    // We do not support RFC 2965 Set-Cookie2-style cookies

    QList<HttpCookie> result;
    const QDateTime now = QDateTime::currentDateTimeUtc();

    int position = 0;
    const int length = cookieString.length();
    while (position < length) {
        HttpCookie cookie;

        // The first part is always the "NAME=VALUE" part
        QPair<QByteArray,QByteArray> field = nextField(cookieString, position, true);
        if (field.first.isEmpty())
            // parsing error
            break;
        cookie.setName(field.first);
        cookie.setValue(field.second);

        position = nextNonWhitespace(cookieString, position);
        while (position < length) {
            switch (cookieString.at(position++)) {
            case ';':
                // new field in the cookie
                field = nextField(cookieString, position, false);
                field.first = field.first.toLower(); // everything but the NAME=VALUE is case-insensitive

                if (field.first == "expires") {
                    position -= field.second.length();
                    int end;
                    for (end = position; end < length; ++end)
                        if (isValueSeparator(cookieString.at(end)))
                            break;

                    QByteArray dateString = cookieString.mid(position, end - position).trimmed();
                    position = end;
                    QDateTime dt = parseDateString(dateString.toLower());
                    if (dt.isValid())
                        cookie.setExpirationDate(dt);
                    //if unparsed, ignore the attribute but not the whole cookie (RFC6265 section 5.2.1)
                } else if (field.first == "domain") {
                    QByteArray rawDomain = field.second;
                    //empty domain should be ignored (RFC6265 section 5.2.3)
                    if (!rawDomain.isEmpty()) {
                        QString maybeLeadingDot;
                        if (rawDomain.startsWith('.')) {
                            maybeLeadingDot = QLatin1Char('.');
                            rawDomain = rawDomain.mid(1);
                        }

                        //IDN domains are required by RFC6265, accepting utf8 as well doesn't break any test cases.
                        QString normalizedDomain = QUrl::fromAce(QUrl::toAce(QString::fromUtf8(rawDomain)));
                        if (!normalizedDomain.isEmpty()) {
                            cookie.setDomain(maybeLeadingDot + normalizedDomain);
                        } else {
                            //Normalization fails for malformed domains, e.g. "..example.org", reject the cookie now
                            //rather than accepting it but never sending it due to domain match failure, as the
                            //strict reading of RFC6265 would indicate.
                            return result;
                        }
                    }
                } else if (field.first == "max-age") {
                    bool ok = false;
                    int secs = field.second.toInt(&ok);
                    if (ok) {
                        if (secs <= 0) {
                            //earliest representable time (RFC6265 section 5.2.2)
                            cookie.setExpirationDate(QDateTime::fromMSecsSinceEpoch(0));
                        } else {
                            cookie.setExpirationDate(now.addSecs(secs));
                        }
                    }
                    //if unparsed, ignore the attribute but not the whole cookie (RFC6265 section 5.2.2)
                } else if (field.first == "path") {
                    if (field.second.startsWith('/')) {
                        // ### we should treat cookie paths as an octet sequence internally
                        // However RFC6265 says we should assume UTF-8 for presentation as a string
                        cookie.setPath(QString::fromUtf8(field.second));
                    } else {
                        // if the path doesn't start with '/' then set the default path (RFC6265 section 5.2.4)
                        // and also IETF test case path0030 which has valid and empty path in the same cookie
                        cookie.setPath(QString());
                    }
                } else if (field.first == "secure") {
                    cookie.setSecure(true);
                } else if (field.first == "httponly") {
                    cookie.setHttpOnly(true);
                } else if (field.first == "samesite") {
                    cookie.setSameSitePolicy(sameSiteFromRawString(field.second));
                } else {
                    // ignore unknown fields in the cookie (RFC6265 section 5.2, rule 6)
                }

                position = nextNonWhitespace(cookieString, position);
            }
        }

        if (!cookie.name().isEmpty())
            result += cookie;
    }

    return result;
}


void HttpCookie::normalize(const QUrl &url)
{
    // don't do path checking. See QTBUG-5815
    if (d->path.isEmpty()) {
        QString pathAndFileName = url.path();
        QString defaultPath = pathAndFileName.left(pathAndFileName.lastIndexOf(QLatin1Char('/'))+1);
        if (defaultPath.isEmpty())
            defaultPath = QLatin1Char('/');
        d->path = defaultPath;
    }

    if (d->domain.isEmpty()) {
        d->domain = url.host();
    } else {
        HostAddress hostAddress(d->domain);
        if (hostAddress.protocol() != HostAddress::IPv4Protocol
                && hostAddress.protocol() != HostAddress::IPv6Protocol
                && !d->domain.startsWith(QLatin1Char('.'))) {
            // Ensure the domain starts with a dot if its field was not empty
            // in the HTTP header. There are some servers that forget the
            // leading dot and this is actually forbidden according to RFC 2109,
            // but all browsers accept it anyway so we do that as well.
            d->domain.prepend(QLatin1Char('.'));
        }
    }
}


HttpCookieJar::HttpCookieJar()
    : d_ptr(new HttpCookieJarPrivate())
{
}


HttpCookieJar::~HttpCookieJar()
{
    delete d_ptr;
}


QList<HttpCookie> HttpCookieJar::allCookies() const
{
    return d_func()->allCookies;
}


void HttpCookieJar::setAllCookies(const QList<HttpCookie> &cookieList)
{
    Q_D(HttpCookieJar);
    d->allCookies = cookieList;
}


static inline bool isParentPath(const QString &path, const QString &reference)
{
    if ((path.isEmpty() && reference == QLatin1String("/")) || path.startsWith(reference)) {
        //The cookie-path and the request-path are identical.
        if (path.length() == reference.length())
            return true;
        //The cookie-path is a prefix of the request-path, and the last
        //character of the cookie-path is %x2F ("/").
        if (reference.endsWith(u'/'))
            return true;
        //The cookie-path is a prefix of the request-path, and the first
        //character of the request-path that is not included in the cookie-
        //path is a %x2F ("/") character.
        if (path.at(reference.length()) == u'/')
            return true;
    }
    return false;
}


static inline bool isParentDomain(const QString &domain, const QString &reference)
{
    if (!reference.startsWith(QLatin1Char('.')))
        return domain == reference;

    return domain.endsWith(reference) || domain == reference.mid(1);
}


bool HttpCookieJar::setCookiesFromUrl(const QList<HttpCookie> &cookieList,
                                          const QUrl &url)
{
    bool added = false;
    for (HttpCookie cookie : cookieList) {
        cookie.normalize(url);
        if (validateCookie(cookie, url) && insertCookie(cookie))
            added = true;
    }
    return added;
}


static bool qIsEffectiveTLD(const QString &domain)
{
    // provide minimal checking by not accepting cookies on real TLDs
    return !domain.contains(QLatin1Char('.'));
}


QList<HttpCookie> HttpCookieJar::cookiesForUrl(const QUrl &url) const
{
//     \b Warning! This is only a dumb implementation!
//     It does NOT follow all of the recommendations from
//     http://wp.netscape.com/newsref/std/cookie_spec.html
//     It does not implement a very good cross-domain verification yet.

    Q_D(const HttpCookieJar);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QList<HttpCookie> result;
    bool isEncrypted = url.scheme() == QLatin1String("https");

    // scan our cookies for something that matches
    QList<HttpCookie>::ConstIterator it = d->allCookies.constBegin(),
                                        end = d->allCookies.constEnd();
    for ( ; it != end; ++it) {
        if (!isParentDomain(url.host(), it->domain()))
            continue;
        if (!isParentPath(url.path(), it->path()))
            continue;
        if (!(*it).isSessionCookie() && (*it).expirationDate() < now)
            continue;
        if ((*it).isSecure() && !isEncrypted)
            continue;

        QString domain = it->domain();
        if (domain.startsWith(QLatin1Char('.'))) /// Qt6?: remove when compliant with RFC6265
            domain = domain.mid(1);
        if (!domain.contains(QLatin1Char('.')) && url.host() != domain)
            continue;

        // insert this cookie into result, sorted by path
        QList<HttpCookie>::Iterator insertIt = result.begin();
        while (insertIt != result.end()) {
            if (insertIt->path().length() < it->path().length()) {
                // insert here
                insertIt = result.insert(insertIt, *it);
                break;
            } else {
                ++insertIt;
            }
        }

        // this is the shortest path yet, just append
        if (insertIt == result.end())
            result += *it;
    }

    return result;
}


bool HttpCookieJar::insertCookie(const HttpCookie &cookie)
{
    Q_D(HttpCookieJar);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    bool isDeletion = !cookie.isSessionCookie() &&
                      cookie.expirationDate() < now;

    deleteCookie(cookie);

    if (!isDeletion) {
        d->allCookies += cookie;
        return true;
    }
    return false;
}


bool HttpCookieJar::updateCookie(const HttpCookie &cookie)
{
    if (deleteCookie(cookie))
        return insertCookie(cookie);
    return false;
}


bool HttpCookieJar::deleteCookie(const HttpCookie &cookie)
{
    Q_D(HttpCookieJar);
    QList<HttpCookie>::Iterator it;
    for (it = d->allCookies.begin(); it != d->allCookies.end(); ++it) {
        if (it->hasSameIdentifier(cookie)) {
            d->allCookies.erase(it);
            return true;
        }
    }
    return false;
}


bool HttpCookieJar::validateCookie(const HttpCookie &cookie, const QUrl &url) const
{
    QString domain = cookie.domain();
    const QString host = url.host();
    if (!isParentDomain(domain, host) && !isParentDomain(host, domain))
        return false; // not accepted

    if (domain.startsWith(QLatin1Char('.')))
        domain = domain.mid(1);

    // We shouldn't reject if:
    // "[...] the domain-attribute is identical to the canonicalized request-host"
    // https://tools.ietf.org/html/rfc6265#section-5.3 step 5
    if (host == domain)
        return true;
    // the check for effective TLDs makes the "embedded dot" rule from RFC 2109 section 4.3.2
    // redundant; the "leading dot" rule has been relaxed anyway, see HttpCookie::normalize()
    // we remove the leading dot for this check if it's present
    // Normally defined in qtldurl_p.h, but uses fall-back in this file when topleveldomain isn't
    // configured:
    return !qIsEffectiveTLD(domain);
}


QTNETWORKNG_NAMESPACE_END


QT_BEGIN_NAMESPACE
#ifndef QT_NO_DEBUG_STREAM
QDebug operator<<(QDebug s, const QTNETWORKNG_NAMESPACE::HttpCookie &cookie)
{
    QDebugStateSaver saver(s);
    s.resetFormat().nospace();
    s << "HttpCookie(" << cookie.toRawForm(QTNETWORKNG_NAMESPACE::HttpCookie::Full) << ')';
    return s;
}
#endif
QT_END_NAMESPACE
