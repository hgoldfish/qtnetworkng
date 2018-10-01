#include <QtCore/qlocale.h>
#include "../include/http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

void HeaderOperationMixin::setContentLength(qint64 contentLength)
{
    setHeader(QStringLiteral("Content-Length"), QString::number(contentLength).toLatin1());
}

qint32 HeaderOperationMixin::getContentLength() const
{
    bool ok;
    QByteArray s = header(QStringLiteral("Content-Length"));
    qint32 l = s.toInt(&ok);
    if(ok) {
        if (l >= 0) {
            return l;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

void HeaderOperationMixin::setContentType(const QString &contentType)
{
    setHeader(QStringLiteral("Content-Type"), contentType.toUtf8());
}

QString HeaderOperationMixin::getContentType() const
{
    return QString::fromUtf8(header(QStringLiteral("Content-Type"), "text/plain"));
}

QUrl HeaderOperationMixin::getLocation() const
{
    const QByteArray &value = header(QStringLiteral("Location"));
    if(value.isEmpty()) {
        return QUrl();
    }
    QUrl result = QUrl::fromEncoded(value, QUrl::StrictMode);
    if (result.isValid()) {
        return result;
    } else {
        return QUrl();
    }
}

void HeaderOperationMixin::setLocation(const QUrl &url)
{
    setHeader(QStringLiteral("Location"), url.toEncoded(QUrl::FullyEncoded));
}

// Fast month string to int conversion. This code
// assumes that the Month name is correct and that
// the string is at least three chars long.
static int name_to_month(const char* month_str)
{
    switch (month_str[0]) {
    case 'J':
        switch (month_str[1]) {
        case 'a':
            return 1;
        case 'u':
            switch (month_str[2] ) {
            case 'n':
                return 6;
            case 'l':
                return 7;
            }
        }
        break;
    case 'F':
        return 2;
    case 'M':
        switch (month_str[2] ) {
        case 'r':
            return 3;
        case 'y':
            return 5;
        }
        break;
    case 'A':
        switch (month_str[1]) {
        case 'p':
            return 4;
        case 'u':
            return 8;
        }
        break;
    case 'O':
        return 10;
    case 'S':
        return 9;
    case 'N':
        return 11;
    case 'D':
        return 12;
    }

    return 0;
}

QDateTime HeaderOperationMixin::fromHttpDate(const QByteArray &value)
{
    // HTTP dates have three possible formats:
    //  RFC 1123/822      -   ddd, dd MMM yyyy hh:mm:ss "GMT"
    //  RFC 850           -   dddd, dd-MMM-yy hh:mm:ss "GMT"
    //  ANSI C's asctime  -   ddd MMM d hh:mm:ss yyyy
    // We only handle them exactly. If they deviate, we bail out.

    int pos = value.indexOf(',');
    QDateTime dt;
#ifndef QT_NO_DATESTRING
    if (pos == -1) {
        // no comma -> asctime(3) format
        dt = QDateTime::fromString(QString::fromLatin1(value), Qt::TextDate);
    } else {
        // Use sscanf over QLocal/QDateTimeParser for speed reasons. See the
        // Qt WebKit performance benchmarks to get an idea.
        if (pos == 3) {
            char month_name[4];
            int day, year, hour, minute, second;
#ifdef Q_CC_MSVC
            // Use secure version to avoid compiler warning
            if (sscanf_s(value.constData(), "%*3s, %d %3s %d %d:%d:%d 'GMT'", &day, month_name, 4, &year, &hour, &minute, &second) == 6)
#else
            // The POSIX secure mode is %ms (which allocates memory), too bleeding edge for now
            // In any case this is already safe as field width is specified.
            if (sscanf(value.constData(), "%*3s, %d %3s %d %d:%d:%d 'GMT'", &day, month_name, &year, &hour, &minute, &second) == 6)
#endif
                dt = QDateTime(QDate(year, name_to_month(month_name), day), QTime(hour, minute, second));
        } else {
            QLocale c = QLocale::c();
            // eat the weekday, the comma and the space following it
            QString sansWeekday = QString::fromLatin1(value.constData() + pos + 2);
            // must be RFC 850 date
            dt = c.toDateTime(sansWeekday, QLatin1String("dd-MMM-yy hh:mm:ss 'GMT'"));
        }
    }
#endif // QT_NO_DATESTRING

    if (dt.isValid())
        dt.setTimeSpec(Qt::UTC);
    return dt;
}

QByteArray HeaderOperationMixin::toHttpDate(const QDateTime &dt)
{
    return QLocale::c().toString(dt, QLatin1String("ddd, dd MMM yyyy hh:mm:ss 'GMT'"))
        .toLatin1();
}

QDateTime HeaderOperationMixin::getLastModified() const
{
    const QByteArray &value = header(QStringLiteral("Last-Modified"));
    if(value.isEmpty()) {
        return QDateTime();
    }
    return fromHttpDate(value);
}

void HeaderOperationMixin::setLastModified(const QDateTime &lastModified)
{
    setHeader(QStringLiteral("Last-Modified"), toHttpDate(lastModified));
}


void HeaderOperationMixin::setModifiedSince(const QDateTime &modifiedSince)
{
    setHeader(QStringLiteral("Modified-Since"), toHttpDate(modifiedSince));
}

QDateTime HeaderOperationMixin::getModifedSince() const
{
    const QByteArray &value = header(QStringLiteral("Modified-Since"));
    if(value.isEmpty()) {
        return QDateTime();
    }
    return fromHttpDate(value);
}


static QStringList knownHeaders = {
    QStringLiteral("Content-Type"),
    QStringLiteral("Content-Length"),
    QStringLiteral("Content-Encoding"),
    QStringLiteral("Transfer-Encoding"),
    QStringLiteral("Location"),
    QStringLiteral("Last-Modified"),
    QStringLiteral("Cookie"),
    QStringLiteral("Set-Cookie"),
    QStringLiteral("Content-Disposition"),
    QStringLiteral("Server"),
    QStringLiteral("User-Agent"),
    QStringLiteral("Accept"),
    QStringLiteral("Accept-Language"),
    QStringLiteral("Accept-Encoding"),
    QStringLiteral("DNT"),
    QStringLiteral("Connection"),
    QStringLiteral("Pragma"),
    QStringLiteral("Cache-Control"),
    QStringLiteral("Date"),
    QStringLiteral("Allow"),
    QStringLiteral("Vary"),
    QStringLiteral("X-Frame-Options"),
    QStringLiteral("MIME-Version"),
};

QString normalizeHeaderName(const QString &headerName) {
    foreach(const QString &goodName, knownHeaders) {
        if(headerName.compare(goodName, Qt::CaseInsensitive) == 0) {
            return goodName;
        }
    }
    return headerName;
}

bool HeaderOperationMixin::hasHeader(const QString &headerName) const
{
    for(int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

bool HeaderOperationMixin::removeHeader(const QString &headerName)
{
    for(int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            headers.removeAt(i);
            return true;
        }
    }
    return false;
}

void HeaderOperationMixin::setHeader(const QString &name, const QByteArray &value)
{
    removeHeader(name);
    addHeader(name, value);
}

void HeaderOperationMixin::addHeader(const QString &name, const QByteArray &value)
{
    headers.append(HttpHeader(normalizeHeaderName(name), value));
}

QByteArray HeaderOperationMixin::header(const QString &headerName, const QByteArray &defaultValue) const
{
    for(int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return header.value;
        }
    }
    return defaultValue;
}

QByteArrayList HeaderOperationMixin::multiHeader(const QString &headerName) const
{
    QByteArrayList l;
    for(int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            l.append(header.value);
        }
    }
    return l;
}

void HeaderOperationMixin::setHeaders(const QMap<QString, QByteArray> headers)
{
    this->headers.clear();
    for(QMap<QString, QByteArray>::const_iterator itor = headers.constBegin(); itor != headers.constEnd(); ++itor) {
        this->headers.append(HttpHeader(normalizeHeaderName(itor.key()), itor.value()));
    }
}

QTNETWORKNG_NAMESPACE_END
