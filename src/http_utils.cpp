#include <QtCore/qlocale.h>
#include "../include/http_utils.h"
#include "debugger.h"

QTNG_LOGGER("qtng.http")

QTNETWORKNG_NAMESPACE_BEGIN

QDataStream &operator>>(QDataStream &ds, HttpHeader &header)
{
    ds >> header.name >> header.value;
    return ds;
}

QDataStream &operator<<(QDataStream &ds, const HttpHeader &header)
{
    ds << header.name << header.value;
    return ds;
}

bool toMessage(HttpStatus status, QString *shortMessage, QString *longMessage)
{
    switch (status) {
    case Continue:
        *shortMessage = QString::fromLatin1("Continue");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request received, please continue");
        return true;
    case SwitchProtocol:
        *shortMessage = QString::fromLatin1("Switching Protocols");
        if (longMessage)
            *longMessage = QString::fromLatin1("Switching to new protocol; obey Upgrade header");
        return true;
    case Processing:
        *shortMessage = QString::fromLatin1("Processing");
        if (longMessage)
            *longMessage = QString::fromLatin1("Processing");
        return true;
    case OK:
        *shortMessage = QString::fromLatin1("OK");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request fulfilled, document follows");
        return true;
    case Created:
        *shortMessage = QString::fromLatin1("Created");
        if (longMessage)
            *longMessage = QString::fromLatin1("Document created, URL follows");
        return true;
    case Accepted:
        *shortMessage = QString::fromLatin1("Accepted");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request accepted, processing continues off-line");
        return true;
    case NonAuthoritative:
        *shortMessage = QString::fromLatin1("Non-Authoritative Information");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request fulfilled from cache");
        return true;
    case NoContent:
        *shortMessage = QString::fromLatin1("No Content");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request fulfilled, nothing follows");
        return true;
    case ResetContent:
        *shortMessage = QString::fromLatin1("Reset Content");
        if (longMessage)
            *longMessage = QString::fromLatin1("Clear input form for further input");
        return true;
    case PartialContent:
        *shortMessage = QString::fromLatin1("Partial Content");
        if (longMessage)
            *longMessage = QString::fromLatin1("Partial content follows");
        return true;
    case MultiStatus:
        *shortMessage = QString::fromLatin1("Multi-Status");
        if (longMessage)
            *longMessage = QString::fromLatin1("Multi-Status");
        return true;
    case AlreadyReported:
        *shortMessage = QString::fromLatin1("Already Reported");
        if (longMessage)
            *longMessage = QString::fromLatin1("Already Reported");
        return true;
    case IMUsed:
        *shortMessage = QString::fromLatin1("IM Used");
        if (longMessage)
            *longMessage = QString::fromLatin1("IM Used");
        return true;
    case MultipleChoices:
        *shortMessage = QString::fromLatin1("Multiple Choices");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object has several resources -- see URI list");
        return true;
    case MovedPermanently:
        *shortMessage = QString::fromLatin1("Moved Permanently");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object moved permanently -- see URI list");
        return true;
    case Found:
        *shortMessage = QString::fromLatin1("Found");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object moved temporarily -- see URI list");
        return true;
    case SeeOther:
        *shortMessage = QString::fromLatin1("See Other");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object moved -- see Method and URL list");
        return true;
    case NotModified:
        *shortMessage = QString::fromLatin1("Not Modified");
        if (longMessage)
            *longMessage = QString::fromLatin1("Document has not changed since given time");
        return true;
    case UseProxy:
        *shortMessage = QString::fromLatin1("Use Proxy");
        if (longMessage)
            *longMessage = QString::fromLatin1("You must use proxy specified in Location to access this resource");
        return true;
    case TemporaryRedirect:
        *shortMessage = QString::fromLatin1("Temporary Redirect");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object moved temporarily -- see URI list");
        return true;
    case PermanentRedirect:
        *shortMessage = QString::fromLatin1("Permanent Redirect");
        if (longMessage)
            *longMessage = QString::fromLatin1("Object moved temporarily -- see URI list");
        return true;
    case BadRequest:
        *shortMessage = QString::fromLatin1("Bad Request");
        if (longMessage)
            *longMessage = QString::fromLatin1("Bad request syntax or unsupported method");
        return true;
    case Unauthorized:
        *shortMessage = QString::fromLatin1("Unauthorized");
        if (longMessage)
            *longMessage = QString::fromLatin1("No permission -- see authorization schemes");
        return true;
    case PaymentRequired:
        *shortMessage = QString::fromLatin1("Payment Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("No payment -- see charging schemes");
        return true;
    case Forbidden:
        *shortMessage = QString::fromLatin1("Forbidden");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request forbidden -- authorization will not help");
        return true;
    case NotFound:
        *shortMessage = QString::fromLatin1("Not Found");
        if (longMessage)
            *longMessage = QString::fromLatin1("Nothing matches the given URI");
        return true;
    case MethodNotAllowed:
        *shortMessage = QString::fromLatin1("Method Not Allowed");
        if (longMessage)
            *longMessage = QString::fromLatin1("Specified method is invalid for this resource");
        return true;
    case NotAcceptable:
        *shortMessage = QString::fromLatin1("Not Acceptable");
        if (longMessage)
            *longMessage = QString::fromLatin1("URI not available in preferred format");
        return true;
    case ProxyAuthenticationRequired:
        *shortMessage = QString::fromLatin1("Proxy Authentication Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("You must authenticate with this proxy before proceeding");
        return true;
    case RequestTimeout:
        *shortMessage = QString::fromLatin1("Request Timeout");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request timed out; try again later");
        return true;
    case Conflict:
        *shortMessage = QString::fromLatin1("Conflict");
        if (longMessage)
            *longMessage = QString::fromLatin1("Request conflict");
        return true;
    case Gone:
        *shortMessage = QString::fromLatin1("Gone");
        if (longMessage)
            *longMessage = QString::fromLatin1("URI no longer exists and has been permanently removed");
        return true;
    case LengthRequired:
        *shortMessage = QString::fromLatin1("Length Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("Client must specify Content-Length");
        return true;
    case PreconditionFailed:
        *shortMessage = QString::fromLatin1("Precondition Failed");
        if (longMessage)
            *longMessage = QString::fromLatin1("Precondition in headers is false");
        return true;
    case RequestEntityTooLarge:
        *shortMessage = QString::fromLatin1("Request Entity Too Large");
        if (longMessage)
            *longMessage = QString::fromLatin1("Entity is too large");
        return true;
    case RequestURITooLong:
        *shortMessage = QString::fromLatin1("Request-URI Too Long");
        if (longMessage)
            *longMessage = QString::fromLatin1("URI is too long");
        return true;
    case UnsupportedMediaType:
        *shortMessage = QString::fromLatin1("Unsupported Media Type");
        if (longMessage)
            *longMessage = QString::fromLatin1("Entity body in unsupported format");
        return true;
    case RequestedRangeNotSatisfiable:
        *shortMessage = QString::fromLatin1("Requested Range Not Satisfiable");
        if (longMessage)
            *longMessage = QString::fromLatin1("Cannot satisfy request range");
        return true;
    case ExpectationFailed:
        *shortMessage = QString::fromLatin1("Expectation Failed");
        if (longMessage)
            *longMessage = QString::fromLatin1("Expect condition could not be satisfied");
        return true;
    case ImaTeapot:
        *shortMessage = QString::fromLatin1("I'm A Teapot");
        if (longMessage)
            *longMessage = QString::fromLatin1("Maybe be short and stout");
        return true;
    case UnprocessableEntity:
        *shortMessage = QString::fromLatin1("Unprocessable Entity");
        if (longMessage)
            *longMessage = QString::fromLatin1("Unprocessable Entity");
        return true;
    case Locked:
        *shortMessage = QString::fromLatin1("Locked");
        if (longMessage)
            *longMessage = QString::fromLatin1("Locked");
        return true;
    case FailedDependency:
        *shortMessage = QString::fromLatin1("Failed Dependency");
        if (longMessage)
            *longMessage = QString::fromLatin1("Failed Dependency");
        return true;
    case UpgradeRequired:
        *shortMessage = QString::fromLatin1("Upgrade Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("Upgrade Required");
        return true;
    case PreconditionRequired:
        *shortMessage = QString::fromLatin1("Precondition Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("The origin server requires the request to be conditional");
        return true;
    case TooManyRequests:
        *shortMessage = QString::fromLatin1("Too Many Requests");
        if (longMessage)
            *longMessage = QString::fromLatin1(
                    "The user has sent too many requests in a given amount of time (\"rate limiting\"");
        return true;
    case RequestHeaderFieldsTooLarge:
        *shortMessage = QString::fromLatin1("Request Header Fields Too Large");
        if (longMessage)
            *longMessage = QString::fromLatin1(
                    "The server is unwilling to process the request because its header fields are too large");
        return true;
    case InternalServerError:
        *shortMessage = QString::fromLatin1("Internal Server Error");
        if (longMessage)
            *longMessage = QString::fromLatin1("Server got itself in trouble");
        return true;
    case NotImplemented:
        *shortMessage = QString::fromLatin1("Not Implemented");
        if (longMessage)
            *longMessage = QString::fromLatin1("Server does not support this operation");
        return true;
    case BadGateway:
        *shortMessage = QString::fromLatin1("Bad Gateway");
        if (longMessage)
            *longMessage = QString::fromLatin1("Invalid responses from another server/proxy");
        return true;
    case ServiceUnavailable:
        *shortMessage = QString::fromLatin1("Service Unavailable");
        if (longMessage)
            *longMessage = QString::fromLatin1("The server cannot process the request due to a high load");
        return true;
    case GatewayTimeout:
        *shortMessage = QString::fromLatin1("Gateway Timeout");
        if (longMessage)
            *longMessage = QString::fromLatin1("The gateway server did not receive a timely response");
        return true;
    case HTTPVersionNotSupported:
        *shortMessage = QString::fromLatin1("HTTP Version Not Supported");
        if (longMessage)
            *longMessage = QString::fromLatin1("Cannot fulfill request");
        return true;
    case VariantAlsoNegotiates:
        *shortMessage = QString::fromLatin1("Variant Also Negotiates");
        if (longMessage)
            *longMessage = QString::fromLatin1("Variant Also Negotiates");
        return true;
    case InsufficientStorage:
        *shortMessage = QString::fromLatin1("Insufficient Storage");
        if (longMessage)
            *longMessage = QString::fromLatin1("Insufficient Storage");
        return true;
    case LoopDetected:
        *shortMessage = QString::fromLatin1("Loop Detected");
        if (longMessage)
            *longMessage = QString::fromLatin1("Loop Detected");
        return true;
    case NotExtended:
        *shortMessage = QString::fromLatin1("Not Extended");
        if (longMessage)
            *longMessage = QString::fromLatin1("Not Extended");
        return true;
    case NetworkAuthenticationRequired:
        *shortMessage = QString::fromLatin1("Network Authentication Required");
        if (longMessage)
            *longMessage = QString::fromLatin1("The client needs to authenticate to gain network access");
        return true;
    }
    return false;
}

// Fast month string to int conversion. This code
// assumes that the Month name is correct and that
// the string is at least three chars long.
static int name_to_month(const char *month_str)
{
    switch (month_str[0]) {
    case 'J':
        switch (month_str[1]) {
        case 'a':
            return 1;
        case 'u':
            switch (month_str[2]) {
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
        switch (month_str[2]) {
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

QDateTime fromHttpDate(const QByteArray &value)
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
#  ifdef Q_CC_MSVC
            // Use secure version to avoid compiler warning
            if (sscanf_s(value.constData(), "%*3s, %d %3s %d %d:%d:%d 'GMT'", &day, month_name, 4, &year, &hour,
                         &minute, &second)
                == 6)
#  else
            // The POSIX secure mode is %ms (which allocates memory), too bleeding edge for now
            // In any case this is already safe as field width is specified.
            if (sscanf(value.constData(), "%*3s, %d %3s %d %d:%d:%d 'GMT'", &day, month_name, &year, &hour, &minute,
                       &second)
                == 6)
#  endif
                dt = QDateTime(QDate(year, name_to_month(month_name), day), QTime(hour, minute, second));
        } else {
            QLocale c = QLocale::c();
            // eat the weekday, the comma and the space following it
            QString sansWeekday = QString::fromLatin1(value.constData() + pos + 2);
            // must be RFC 850 date
            dt = c.toDateTime(sansWeekday, QLatin1String("dd-MMM-yy hh:mm:ss 'GMT'"));
        }
    }
#endif  // QT_NO_DATESTRING

    if (dt.isValid())
        dt.setTimeSpec(Qt::UTC);
    return dt;
}

QByteArray toHttpDate(const QDateTime &dt)
{
    return QLocale::c().toString(dt, QLatin1String("ddd, dd MMM yyyy hh:mm:ss 'GMT'")).toLatin1();
}

static QStringList knownHeaders = {
    QString::fromLatin1("Content-Type"),
    QString::fromLatin1("Content-Length"),
    QString::fromLatin1("Content-Encoding"),
    QString::fromLatin1("Transfer-Encoding"),
    QString::fromLatin1("Location"),
    QString::fromLatin1("Last-Modified"),
    QString::fromLatin1("Cookie"),
    QString::fromLatin1("Set-Cookie"),
    QString::fromLatin1("Content-Disposition"),
    QString::fromLatin1("Server"),
    QString::fromLatin1("User-Agent"),
    QString::fromLatin1("Accept"),
    QString::fromLatin1("Accept-Language"),
    QString::fromLatin1("Accept-Encoding"),
    QString::fromLatin1("DNT"),
    QString::fromLatin1("Connection"),
    QString::fromLatin1("Pragma"),
    QString::fromLatin1("Cache-Control"),
    QString::fromLatin1("Date"),
    QString::fromLatin1("Allow"),
    QString::fromLatin1("Vary"),
    QString::fromLatin1("X-Frame-Options"),
    QString::fromLatin1("MIME-Version"),
    QString::fromLatin1("Host"),
};

QString normalizeHeaderName(const QString &headerName)
{
    for (const QString &goodName : knownHeaders) {
        if (headerName.compare(goodName, Qt::CaseInsensitive) == 0) {
            return goodName;
        }
    }
    return headerName;
}

QString toString(KnownHeader knownHeader)
{
    switch (knownHeader) {
    case ContentTypeHeader:
        return QString::fromLatin1("Content-Type");
    case ContentLengthHeader:
        return QString::fromLatin1("Content-Length");
    case ContentEncodingHeader:
        return QString::fromLatin1("Content-Encoding");
    case TransferEncodingHeader:
        return QString::fromLatin1("Transfer-Encoding");
    case LocationHeader:
        return QString::fromLatin1("Location");
    case LastModifiedHeader:
        return QString::fromLatin1("Last-Modified");
    case CookieHeader:
        return QString::fromLatin1("Cookie");
    case SetCookieHeader:
        return QString::fromLatin1("Set-Cookie");
    case ContentDispositionHeader:
        return QString::fromLatin1("Content-Disposition");
    case UserAgentHeader:
        return QString::fromLatin1("User-Agent");
    case AcceptHeader:
        return QString::fromLatin1("Accept");
    case AcceptLanguageHeader:
        return QString::fromLatin1("Accept-Language");
    case AcceptEncodingHeader:
        return QString::fromLatin1("Accept-Encoding");
    case PragmaHeader:
        return QString::fromLatin1("Pragma");
    case CacheControlHeader:
        return QString::fromLatin1("Cache-Control");
    case DateHeader:
        return QString::fromLatin1("Date");
    case AllowHeader:
        return QString::fromLatin1("Allow");
    case VaryHeader:
        return QString::fromLatin1("Vary");
    case FrameOptionsHeader:
        return QString::fromLatin1("X-Frame-Options");
    case MIMEVersionHeader:
        return QString::fromLatin1("MIME-Version");
    case ServerHeader:
        return QString::fromLatin1("Server");
    case ConnectionHeader:
        return QString::fromLatin1("Connection");
    case UpgradeHeader:
        return QString::fromLatin1("Upgrade");
    case HostHeader:
        return QString::fromLatin1("Host");
    }
    return QString();
}

QByteArray HeaderSplitter::nextLine(HeaderSplitter::Error *error)
{
    const int MaxLineLength = 1024 * 64;
    QByteArray line;
    bool expectingLineBreak = false;

    while (true) {
        if (buf.isEmpty()) {
            buf = connection->recv(1024);
            if (buf.isEmpty()) {
                *error = HeaderSplitter::ConnectionError;
                return QByteArray();
            }
        }
        int j = 0;
        for (; j < buf.size(); ++j) {
            char c = buf.at(j);
            if (c == '\n') {
                buf.remove(0, j + 1);
                *error = HeaderSplitter::NoError;
                return line;
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
                if (line.size() > MaxLineLength) {
                    *error = HeaderSplitter::LineTooLong;
                    return QByteArray();
                }
            }
        }
        buf.clear();
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
        qtng_debug << "receiving data:" << line;
    }
    QList<QByteArray> headerParts = splitBytes(line, ':', 1);
    if (headerParts.size() != 2) {
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
        if (c == sep && (maxSplit < 0 || tokens.size() < maxSplit)) {
            tokens.append(token);
            token.clear();
        } else {
            token.append(c);
        }
    }
    if (!token.isEmpty()) {
        tokens.append(token);
    }
    return tokens;
}

QByteArray ChunkedBlockReader::nextBlock(qint64 leftBytes, ChunkedBlockReader::Error *error)
{
    const int MaxLineLength = 6;  // ffff\r\n
    QByteArray numBytes;
    bool expectingLineBreak = false;
    while (buf.size() < MaxLineLength && !buf.contains('\n')) {
        const QByteArray &t = connection->recv(1024 * 8);
        if (t.isEmpty()) {
            break;
        }
        buf.append(t);  // most server send the header at one tcp block.
    }
    if (buf.size() < 3) {  // 0\r\n
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
    if (!ok) {
        *error = ChunkedBlockReader::ChunkedEncodingError;
        return QByteArray();
    }
    qint32 bytesToRead = numBytes.toInt(&ok, 16);
    if (!ok) {
        if (debugLevel > 0) {
            qtng_debug << "got invalid chunked bytes:" << numBytes;
        }
        *error = ChunkedBlockReader::ChunkedEncodingError;
        return QByteArray();
    }

    if (bytesToRead > leftBytes || bytesToRead < 0) {
        *error = ChunkedBlockReader::UnrewindableBodyError;
        return QByteArray();
    }

    while (buf.size() < bytesToRead + 2) {
        const QByteArray t = connection->recv(1024 * 8);
        if (t.isEmpty()) {
            *error = ChunkedBlockReader::ConnectionError;
            return QByteArray();
        }
        buf.append(t);
    }

    const QByteArray &result = buf.mid(0, bytesToRead);
    buf.remove(0, bytesToRead + 2);

    if (bytesToRead == 0 && !buf.isEmpty() && debugLevel > 0) {
        qtng_debug << "bytesToRead == 0 but some bytes left.";
    }

    *error = ChunkedBlockReader::NoError;
    return result;
}

PlainBodyFile::PlainBodyFile(qint64 contentLength, const QByteArray &partialBody, QSharedPointer<SocketLike> stream)
    : contentLength(contentLength)
    , stream(stream)
    , partialBody(partialBody)
    , count(0)
{
}

qint32 PlainBodyFile::read(char *data, qint32 size)
{
    if (!partialBody.isEmpty()) {
        qint32 t = qMin(size, partialBody.size());
        memcpy(data, partialBody.constData(), t);
        partialBody.remove(0, t);
        count += t;
        return t;
    }
    if (contentLength >= 0) {
        if (count >= contentLength) {
            return 0;
        }
        qint64 leftBytes = contentLength - count;
        qint32 bs = stream->recv(data, qMin<qint64>(size, leftBytes));
        if (bs > 0) {
            count += bs;
        }
        return bs;
    } else {
        return stream->recv(data, size);
    }
}

ChunkedBodyFile::ChunkedBodyFile(qint64 maxBodySize, const QByteArray &partialBody, QSharedPointer<SocketLike> stream)
    : reader(stream, partialBody)
    , error(ChunkedBlockReader::NoError)
    , maxBodySize(maxBodySize)
    , count(0)
    , eof(false)
{
}

qint32 ChunkedBodyFile::read(char *data, qint32 size)
{
    while (buf.size() < size && !eof) {
        qint64 leftBytes;
        if (maxBodySize >= 0) {
            leftBytes = maxBodySize - count;
            if (leftBytes <= 0) {
                break;
            }
        } else {
            leftBytes = INT_MAX;
        }
        const QByteArray &block = reader.nextBlock(leftBytes, &error);
        if (error != ChunkedBlockReader::NoError) {
            return -1;
        }
        if (block.isEmpty()) {
            eof = true;
            break;
        }
        count += block.size();
        buf.append(block);
    }
    qint32 bytesToRead = qMin(buf.size(), size);
    memcpy(data, buf.constData(), bytesToRead);
    buf.remove(0, bytesToRead);
    return bytesToRead;
}

ChunkedWriter::~ChunkedWriter()
{
    close();
}

qint32 ChunkedWriter::write(const char *data, qint32 size)
{
    // the chunked block can not greater than 0xffff!
    qint64 sent = 0;
    while (sent < size) {
        qint64 blockSize = qMin<qint64>(0xffff, size - sent);
        QByteArray buf;
        buf.reserve(size + 32);
        buf.append(QByteArray::number(blockSize, 16));
        buf.append("\r\n", 2);
        if (data) {
            buf.append(data + sent, blockSize);
        }
        buf.append("\r\n", 2);

        qint32 writtenBytes = stream->write(buf);
        if (writtenBytes != buf.size()) {
            return -1;
        }
        sent += blockSize;
    }
    return size;
}

void ChunkedWriter::close()
{
    stream->write("0\r\n\r\n", 5);
}

QTNETWORKNG_NAMESPACE_END
