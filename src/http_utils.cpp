#include <QtCore/qlocale.h>
#include "../include/http_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN


QDataStream &operator >>(QDataStream &ds, HttpHeader &header)
{
    ds >> header.name >> header.value;
    return ds;
}


QDataStream &operator <<(QDataStream &ds, const HttpHeader &header)
{
    ds << header.name << header.value;
    return ds;
}


bool toMessage(HttpStatus status, QString *shortMessage, QString *longMessage)
{
    switch (status) {
    case Continue:
        *shortMessage = QStringLiteral("Continue");
        if (longMessage) *longMessage = QStringLiteral("Request received, please continue");
        return true;
    case SwitchProtocol:
        *shortMessage = QStringLiteral("Switching Protocols");
        if (longMessage) *longMessage = QStringLiteral("Switching to new protocol; obey Upgrade header");
        return true;
    case Processing:
        *shortMessage = QStringLiteral("Processing");
        if (longMessage) *longMessage = QStringLiteral("Processing");
        return true;
    case OK:
        *shortMessage = QStringLiteral("OK");
        if (longMessage) *longMessage = QStringLiteral("Request fulfilled, document follows");
        return true;
    case Created:
        *shortMessage = QStringLiteral("Created");
        if (longMessage) *longMessage = QStringLiteral("Document created, URL follows");
        return true;
    case Accepted:
        *shortMessage = QStringLiteral("Accepted");
        if (longMessage) *longMessage = QStringLiteral("Request accepted, processing continues off-line");
        return true;
    case NonAuthoritative:
        *shortMessage = QStringLiteral("Non-Authoritative Information");
        if (longMessage) *longMessage = QStringLiteral("Request fulfilled from cache");
        return true;
    case NoContent:
        *shortMessage = QStringLiteral("No Content");
        if (longMessage) *longMessage = QStringLiteral("Request fulfilled, nothing follows");
        return true;
    case ResetContent:
        *shortMessage = QStringLiteral("Reset Content");
        *longMessage = QStringLiteral("Clear input form for further input");
        return true;
    case PartialContent:
        *shortMessage = QStringLiteral("Partial Content");
        *longMessage = QStringLiteral("Partial content follows");
        return true;
    case MultiStatus:
        *shortMessage = QStringLiteral("Multi-Status");
        if (longMessage) *longMessage = QStringLiteral("Multi-Status");
        return true;
    case AlreadyReported:
        *shortMessage = QStringLiteral("Already Reported");
        if (longMessage) *longMessage = QStringLiteral("Already Reported");
        return true;
    case IMUsed:
        *shortMessage = QStringLiteral("IM Used");
        if (longMessage) *longMessage = QStringLiteral("IM Used");
        return true;
    case MultipleChoices:
        *shortMessage = QStringLiteral("Multiple Choices");
        if (longMessage) *longMessage = QStringLiteral("Object has several resources -- see URI list");
        return true;
    case MovedPermanently:
        *shortMessage = QStringLiteral("Moved Permanently");
        if (longMessage) *longMessage = QStringLiteral("Object moved permanently -- see URI list");
        return true;
    case Found:
        *shortMessage = QStringLiteral("Found");
        if (longMessage) *longMessage = QStringLiteral("Object moved temporarily -- see URI list");
        return true;
    case SeeOther:
        *shortMessage = QStringLiteral("See Other");
        if (longMessage) *longMessage = QStringLiteral("Object moved -- see Method and URL list");
        return true;
    case NotModified:
        *shortMessage = QStringLiteral("Not Modified");
        if (longMessage) *longMessage = QStringLiteral("Document has not changed since given time");
        return true;
    case UseProxy:
        *shortMessage = QStringLiteral("Use Proxy");
        if (longMessage) *longMessage = QStringLiteral("You must use proxy specified in Location to access this resource");
        return true;
    case TemporaryRedirect:
        *shortMessage = QStringLiteral("Temporary Redirect");
        if (longMessage) *longMessage = QStringLiteral("Object moved temporarily -- see URI list");
        return true;
    case PermanentRedirect:
        *shortMessage = QStringLiteral("Permanent Redirect");
        if (longMessage) *longMessage = QStringLiteral("Object moved temporarily -- see URI list");
        return true;
    case BadRequest:
        *shortMessage = QStringLiteral("Bad Request");
        if (longMessage) *longMessage = QStringLiteral("Bad request syntax or unsupported method");
        return true;
    case Unauthorized:
        *shortMessage = QStringLiteral("Unauthorized");
        if (longMessage) *longMessage = QStringLiteral("No permission -- see authorization schemes");
        return true;
    case PaymentRequired:
        *shortMessage = QStringLiteral("Payment Required");
        if (longMessage) *longMessage = QStringLiteral("No payment -- see charging schemes");
        return true;
    case Forbidden:
        *shortMessage = QStringLiteral("Forbidden");
        if (longMessage) *longMessage = QStringLiteral("Request forbidden -- authorization will not help");
        return true;
    case NotFound:
        *shortMessage = QStringLiteral("Not Found");
        if (longMessage) *longMessage = QStringLiteral("Nothing matches the given URI");
        return true;
    case MethodNotAllowed:
        *shortMessage = QStringLiteral("Method Not Allowed");
        if (longMessage) *longMessage = QStringLiteral("Specified method is invalid for this resource");
        return true;
    case NotAcceptable:
        *shortMessage = QStringLiteral("Not Acceptable");
        if (longMessage) *longMessage = QStringLiteral("URI not available in preferred format");
        return true;
    case ProxyAuthenticationRequired:
        *shortMessage = QStringLiteral("Proxy Authentication Required");
        if (longMessage) *longMessage = QStringLiteral("You must authenticate with this proxy before proceeding");
        return true;
    case RequestTimeout:
        *shortMessage = QStringLiteral("Request Timeout");
        if (longMessage) *longMessage = QStringLiteral("Request timed out; try again later");
        return true;
    case Conflict:
        *shortMessage = QStringLiteral("Conflict");
        if (longMessage) *longMessage = QStringLiteral("Request conflict");
        return true;
    case Gone:
        *shortMessage = QStringLiteral("Gone");
        if (longMessage) *longMessage = QStringLiteral("URI no longer exists and has been permanently removed");
        return true;
    case LengthRequired:
        *shortMessage = QStringLiteral("Length Required");
        if (longMessage) *longMessage = QStringLiteral("Client must specify Content-Length");
        return true;
    case PreconditionFailed:
        *shortMessage = QStringLiteral("Precondition Failed");
        if (longMessage) *longMessage = QStringLiteral("Precondition in headers is false");
        return true;
    case RequestEntityTooLarge:
        *shortMessage = QStringLiteral("Request Entity Too Large");
        if (longMessage) *longMessage = QStringLiteral("Entity is too large");
        return true;
    case RequestURITooLong:
        *shortMessage = QStringLiteral("Request-URI Too Long");
        if (longMessage) *longMessage = QStringLiteral("URI is too long");
        return true;
    case UnsupportedMediaType:
        *shortMessage = QStringLiteral("Unsupported Media Type");
        if (longMessage) *longMessage = QStringLiteral("Entity body in unsupported format");
        return true;
    case RequestedRangeNotSatisfiable:
        *shortMessage = QStringLiteral("Requested Range Not Satisfiable");
        if (longMessage) *longMessage = QStringLiteral("Cannot satisfy request range");
        return true;
    case ExpectationFailed:
        *shortMessage = QStringLiteral("Expectation Failed");
        if (longMessage) *longMessage = QStringLiteral("Expect condition could not be satisfied");
        return true;
    case ImaTeaport:
        *shortMessage = QStringLiteral("I'm A Teapot");
        if (longMessage) *longMessage = QStringLiteral("Maybe be short and stout");
        return true;
    case UnprocessableEntity:
        *shortMessage = QStringLiteral("Unprocessable Entity");
        if (longMessage) *longMessage = QStringLiteral("Unprocessable Entity");
        return true;
    case Locked:
        *shortMessage = QStringLiteral("Locked");
        if (longMessage) *longMessage = QStringLiteral("Locked");
        return true;
    case FailedDependency:
        *shortMessage = QStringLiteral("Failed Dependency");
        if (longMessage) *longMessage = QStringLiteral("Failed Dependency");
        return true;
    case UpgradeRequired:
        *shortMessage = QStringLiteral("Upgrade Required");
        if (longMessage) *longMessage = QStringLiteral("Upgrade Required");
        return true;
    case PreconditionRequired:
        *shortMessage = QStringLiteral("Precondition Required");
        if (longMessage) *longMessage = QStringLiteral("The origin server requires the request to be conditional");
        return true;
    case TooManyRequests:
        *shortMessage = QStringLiteral("Too Many Requests");
        if (longMessage) *longMessage = QStringLiteral("The user has sent too many requests in a given amount of time (\"rate limiting\"");
        return true;
    case RequestHeaderFieldsTooLarge:
        *shortMessage = QStringLiteral("Request Header Fields Too Large");
        if (longMessage) *longMessage = QStringLiteral("The server is unwilling to process the request because its header fields are too large");
        return true;
    case InternalServerError:
        *shortMessage = QStringLiteral("Internal Server Error");
        if (longMessage) *longMessage = QStringLiteral("Server got itself in trouble");
        return true;
    case NotImplemented:
        *shortMessage = QStringLiteral("Not Implemented");
        if (longMessage) *longMessage = QStringLiteral("Server does not support this operation");
        return true;
    case BadGateway:
        *shortMessage = QStringLiteral("Bad Gateway");
        if (longMessage) *longMessage = QStringLiteral("Invalid responses from another server/proxy");
        return true;
    case ServiceUnavailable:
        *shortMessage = QStringLiteral("Service Unavailable");
        if (longMessage) *longMessage = QStringLiteral("The server cannot process the request due to a high load");
        return true;
    case GatewayTimeout:
        *shortMessage = QStringLiteral("Gateway Timeout");
        if (longMessage) *longMessage = QStringLiteral("The gateway server did not receive a timely response");
        return true;
    case HTTPVersionNotSupported:
        *shortMessage = QStringLiteral("HTTP Version Not Supported");
        if (longMessage) *longMessage = QStringLiteral("Cannot fulfill request");
        return true;
    case VariantAlsoNegotiates:
        *shortMessage = QStringLiteral("Variant Also Negotiates");
        if (longMessage) *longMessage = QStringLiteral("Variant Also Negotiates");
        return true;
    case InsufficientStorage:
        *shortMessage = QStringLiteral("Insufficient Storage");
        if (longMessage) *longMessage = QStringLiteral("Insufficient Storage");
        return true;
    case LoopDetected:
        *shortMessage = QStringLiteral("Loop Detected");
        if (longMessage) *longMessage = QStringLiteral("Loop Detected");
        return true;
    case NotExtended:
        *shortMessage = QStringLiteral("Not Extended");
        if (longMessage) *longMessage = QStringLiteral("Not Extended");
        return true;
    case NetworkAuthenticationRequired:
        *shortMessage = QStringLiteral("Network Authentication Required");
        if (longMessage) *longMessage = QStringLiteral("The client needs to authenticate to gain network access");
        return true;
    }
    return false;
}


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
    QStringLiteral("Host"),
};


QString normalizeHeaderName(const QString &headerName) {
    for (const QString &goodName: knownHeaders) {
        if(headerName.compare(goodName, Qt::CaseInsensitive) == 0) {
            return goodName;
        }
    }
    return headerName;
}


bool HeaderOperationMixin::hasHeader(const QString &headerName) const
{
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}


bool HeaderOperationMixin::removeHeader(const QString &headerName)
{
    for (int i = 0; i < headers.size(); ++i) {
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


void HeaderOperationMixin::addHeader(const HttpHeader &header)
{
    headers.append(header);
}


QByteArray HeaderOperationMixin::header(const QString &headerName, const QByteArray &defaultValue) const
{
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if (header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            return header.value;
        }
    }
    return defaultValue;
}


inline QString HeaderOperationMixin::toString(KnownHeader knownHeader)
{
    switch (knownHeader) {
    case ContentTypeHeader:
        return QStringLiteral("Content-Type");
    case ContentLengthHeader:
        return QStringLiteral("Content-Length");
    case ContentEncodingHeader:
        return QStringLiteral("Content-Encoding");
    case TransferEncodingHeader:
        return QStringLiteral("Transfer-Encoding");
    case LocationHeader:
        return QStringLiteral("Location");
    case LastModifiedHeader:
        return QStringLiteral("Last-Modified");
    case CookieHeader:
        return QStringLiteral("Cookie");
    case SetCookieHeader:
        return QStringLiteral("Set-Cookie");
    case ContentDispositionHeader:
        return QStringLiteral("Content-Disposition");
    case UserAgentHeader:
        return QStringLiteral("User-Agent");
    case AcceptHeader:
        return QStringLiteral("Accept");
    case AcceptLanguageHeader:
        return QStringLiteral("Accept-Language");
    case AcceptEncodingHeader:
        return QStringLiteral("Accept-Encoding");
    case PragmaHeader:
        return QStringLiteral("Pragma");
    case CacheControlHeader:
        return QStringLiteral("Cache-Control");
    case DateHeader:
        return QStringLiteral("Date");
    case AllowHeader:
        return QStringLiteral("Allow");
    case VaryHeader:
        return QStringLiteral("Vary");
    case FrameOptionsHeader:
        return QStringLiteral("X-Frame-Options");
    case MIMEVersionHeader:
        return QStringLiteral("MIME-Version");
    case ServerHeader:
        return QStringLiteral("Server");
    case ConnectionHeader:
        return QStringLiteral("Connection");
    case UpgradeHeader:
        return QStringLiteral("Upgrade");
    case HostHeader:
        return QStringLiteral("Host");
    }
    return QString();
}


QByteArray HeaderOperationMixin::header(KnownHeader knownHeader, const QByteArray &defaultValue) const
{
    return header(toString(knownHeader), defaultValue);
}


#if QT_VERSION >= QT_VERSION_CHECK(5, 4, 0)
#define QBYTEARRAYLIST QByteArrayList
#else
#define QBYTEARRAYLIST QList<QByteArray>
#endif

QBYTEARRAYLIST HeaderOperationMixin::multiHeader(const QString &headerName) const
{
    QBYTEARRAYLIST l;
    for (int i = 0; i < headers.size(); ++i) {
        const HttpHeader &header = headers.at(i);
        if(header.name.compare(headerName, Qt::CaseInsensitive) == 0) {
            l.append(header.value);
        }
    }
    return l;
}


QBYTEARRAYLIST HeaderOperationMixin::multiHeader(KnownHeader header) const
{
    return multiHeader(toString(header));
}


void HeaderOperationMixin::setHeaders(const QMap<QString, QByteArray> headers)
{
    this->headers.clear();
    for (QMap<QString, QByteArray>::const_iterator itor = headers.constBegin(); itor != headers.constEnd(); ++itor) {
        this->headers.append(HttpHeader(normalizeHeaderName(itor.key()), itor.value()));
    }
}


QByteArray HeaderSplitter::nextLine(HeaderSplitter::Error *error)
{
    const int MaxLineLength = 1024 * 64;
    QByteArray line;
    bool expectingLineBreak = false;

    for (int i = 0; i < MaxLineLength; ++i) {
        if (buf.isEmpty()) {
            buf = connection->recv(1024);
            if (buf.isEmpty()) {
                *error = HeaderSplitter::ConnectionError;
                return QByteArray();
            }
        }
        int j = 0;
        for (; j < buf.size() && j < MaxLineLength; ++j) {
            char c = buf.at(j);
            if (c == '\n') {
//                if(!expectingLineBreak) {
//                    *error = HeaderSplitter::EncodingError;
//                    return QByteArray();
//                }
                buf.remove(0, j + 1);
                if (buf.size() > MaxLineLength) {
                    *error = HeaderSplitter::LineTooLong;
                    return QByteArray();
                } else {
                    *error = HeaderSplitter::NoError;
                    return line;
                }
            } else if (c == '\r') {
                if (expectingLineBreak) {
                    *error = HeaderSplitter::EncodingError;
                    return QByteArray();
                }
                expectingLineBreak = true;
            } else {
                if (expectingLineBreak) {
                    *error = HeaderSplitter::EncodingError;
                    return QByteArray();
                }
                line.append(c);
            }
        }
        buf.remove(0, j + 1);
    }
    *error = HeaderSplitter::ExhausedMaxLine;
    return QByteArray();
}


HttpHeader HeaderSplitter::nextHeader(Error *error)
{
    const QByteArray &line = nextLine(error);
    if (*error != HeaderSplitter::NoError) {
        return HttpHeader();
    }
    if (line.isEmpty()) {
        *error = HeaderSplitter::NoError;
        return HttpHeader();
    }
    if (debugLevel > 2) {
        qDebug() << "receiving data:" << line;
    }
    QBYTEARRAYLIST headerParts = splitBytes(line, ':', 1);
    if(headerParts.size() != 2) {
        *error = HeaderSplitter::EncodingError;
        return HttpHeader();
    }
    QString headerName = QString::fromUtf8(headerParts[0]).trimmed();
    QByteArray headerValue = headerParts[1].trimmed();
    *error = HeaderSplitter::NoError;
    return HttpHeader(headerName, headerValue);
}


QList<HttpHeader> HeaderSplitter::headers(int maxHeaders, Error *error)
{
    QList<HttpHeader> headers;
    for (int i = 0; i < maxHeaders; ++i) {
        const HttpHeader &header = nextHeader(error);
        if (header.isValid()) {
            headers.append(header);
        } else {
            if (*error != HeaderSplitter::NoError) {
                return QList<HttpHeader>();
            } else {
                return headers;
            }
        }
    }
    *error = HeaderSplitter::ExhausedMaxLine;
    return QList<HttpHeader>();
}


QList<QByteArray> splitBytes(const QByteArray &bs, char sep, int maxSplit)
{
    QList<QByteArray> tokens;
    QByteArray token;
    for (int i = 0; i < bs.size(); ++i) {
        char c = bs.at(i);
        if(c == sep && (maxSplit < 0 || tokens.size() < maxSplit)) {
            tokens.append(token);
            token.clear();
        } else {
            token.append(c);
        }
    }
    if(!token.isEmpty()) {
        tokens.append(token);
    }
    return tokens;
}


QByteArray ChunkedBlockReader::nextBlock(qint64 leftBytes, ChunkedBlockReader::Error *error)
{
    const int MaxLineLength = 6; // ffff\r\n
    QByteArray numBytes;
    bool expectingLineBreak = false;
    while(buf.size() < MaxLineLength && !buf.contains('\n')) {
        buf.append(connection->recv(1024 * 8)); // most server send the header at one tcp block.
    }
    if(buf.size() < 3) { // 0\r\n
        *error = ChunkedBlockReader::ChunkedEncodingError;
        return QByteArray();
    }

    bool ok = false;
    for (int i = 0; i < buf.size() && i < MaxLineLength; ++i) {
        char c = buf.at(i);
        if (expectingLineBreak) {
            if (c == '\n') {
                buf.remove(0, i + 1);
                ok = true;
                break;
            } else {
                *error = ChunkedBlockReader::ChunkedEncodingError;
                return QByteArray();
            }
        } else {
            if (c == '\n') {
                *error = ChunkedBlockReader::ChunkedEncodingError;
                return QByteArray();
            } else if (c == '\r') {
                expectingLineBreak = true;
            } else {
                numBytes.append(c);
            }
        }
    }
    if(!ok) {
        *error = ChunkedBlockReader::ChunkedEncodingError;
        return QByteArray();
    }

    qint32 bytesToRead = numBytes.toInt(&ok, 16);
    if(!ok) {
        if(debugLevel > 0) {
            qDebug() << "got invalid chunked bytes:" << numBytes;
        }
        *error = ChunkedBlockReader::ChunkedEncodingError;
        return QByteArray();
    }

    if(bytesToRead > leftBytes || bytesToRead < 0) {
        *error = ChunkedBlockReader::UnrewindableBodyError;
        return QByteArray();
    }

    while(buf.size() < bytesToRead + 2) {
        const QByteArray t = connection->recv(1024 * 8);
        if(t.isEmpty()) {
            *error = ChunkedBlockReader::ConnectionError;
            return QByteArray();
        }
        buf.append(t);
    }

    const QByteArray &result = buf.mid(0, bytesToRead);
    buf.remove(0, bytesToRead + 2);

    if(bytesToRead == 0 && !buf.isEmpty() && debugLevel > 0) {
        qDebug() << "bytesToRead == 0 but some bytes left.";
    }

    *error = ChunkedBlockReader::NoError;
    return result;
}

QTNETWORKNG_NAMESPACE_END
