#include <QtCore/qdatetime.h>
#include <QtCore/qendian.h>
#include <QtCore/qscopeguard.h>
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
#include <QtCore/qrandom.h>
#endif
#if __ARM_NEON
#include <arm_neon.h>
#elif __SSE2__
#include <emmintrin.h>
#endif
#include "../include/http.h"
#include "../include/websocket.h"
#include "../include/coroutine_utils.h"
#include "../include/socket_utils.h"
#include "../include/random.h"
#include "debugger.h"

QTNG_LOGGER("qtng.websocket");
#define DEBUG_PROTOCOL 1

QTNETWORKNG_NAMESPACE_BEGIN

class WebSocketConfigurationPrivate
{
public:
    WebSocketConfigurationPrivate();
public:
    QStringList protocols;
    quint64 keepaliveInterval;
    quint64 keepaliveTimeout;
    quint32 sendingQueueCapacity;
    quint32 receivingQueueCapacity;
    qint32 maxPayloadSize;
    qint32 outgoingSize;
};

class PacketToRead
{
public:
    PacketToRead()
        : type(WebSocketConnection::Unknown)
    {
    }

    PacketToRead(WebSocketConnection::FrameType type, const QByteArray &payload)
        : type(type)
        , payload(payload)
    {
    }
public:
    WebSocketConnection::FrameType type;
    QByteArray payload;
public:
    inline bool isValid() const { return type != WebSocketConnection::Unknown; }
};

class PacketToWrite
{
public:
    PacketToWrite()
        : type(WebSocketConnection::Unknown)
    {
    }
    PacketToWrite(const QByteArray &data, QSharedPointer<ValueEvent<bool>> done)
        : type(WebSocketConnection::Binary)
        , payload(data)
        , done(done)
    {
    }
    PacketToWrite(const QString &text, QSharedPointer<ValueEvent<bool>> done)
        : type(WebSocketConnection::Text)
        , done(done)
    {
        payload = text.toUtf8();
    }
public:
    WebSocketConnection::FrameType type;
    QByteArray payload;
    QSharedPointer<ValueEvent<bool>> done;
public:
    inline bool isValid() const
    {
        return !payload.isEmpty() && (type == WebSocketConnection::Binary || type == WebSocketConnection::Text);
    }
};

enum FrameType {
    ContinuationFrame = 0x0,
    TextFrame = 0x1,
    BinaryFrame = 0x2,
    CloseFrame = 0x8,
    PingFrame = 0x9,
    PongFrame = 0xa
};

class WebSocketFrame
{
public:
    WebSocketFrame();
public:
    quint8 fin : 1;
    quint8 rsv1 : 1;
    quint8 rsv2 : 1;
    quint8 rsv3 : 1;
    quint8 opcode : 4;
    quint32 maskkey;
    QByteArray payload;
public:
    // parse the header and returns the payload size.
    // if the header is valid, it will be removed from the buf
    qint64 feedHeader(char *packet, int &packetSize);

    // apply mask to payload and copy to src[offset: len]. this function also decode payload using mask
    void applyMaskTo(char *dst, int offset, int dst_max_len) const;

    // make frame packet.
    QByteArray toByteArray() const;
public:
    inline bool isValid() const { return !rsv1 && !rsv2 && !rsv3 && !payload.isEmpty(); }
};

class WebSocketConnectionPrivate
{
public:
    WebSocketConnectionPrivate(QSharedPointer<SocketLike> connection, const QByteArray &headBytes, WebSocketConnection::Side side,
                               const WebSocketConfiguration &config, WebSocketConnection *q);
    ~WebSocketConnectionPrivate();
public:
    void doSend();
    void doReceive(const QByteArray &headBytes);
    void doKeepalive();
    void setErrorCode(int errorCode, const QString &errorString);
    void abort(int errorCode);
    bool close();
private:
    QByteArray makeClosePayload(int closeCode, const QString &closeReason);
    QPair<int, QString> parseClosePayload(const QByteArray &payload);
    WebSocketFrame makeControlFrame(FrameType type);
    QVector<WebSocketFrame> fragmentFrame(const PacketToWrite &writingPacket, const int blockSize);
    quint32 makeMaskkey();
    bool recvBytes(QByteArray &buf, int &usedSize);
    bool sendBytes(const QByteArray &packet);
public:
    CoroutineGroup *operations;
    HttpResponse response;
    QSharedPointer<SocketLike> const connection;
    QByteArray id;
    Queue<PacketToRead> receivingQueue;
    Queue<PacketToWrite> sendingQueue;
    Lock writeLock;
    WebSocketConnection::State state;
    WebSocketConnection::Side side;
    int debugLevel;
    qint32 maxPayloadSize;
    qint32 outgoingSize;
    qint64 lastActiveTimestamp;
    qint64 lastKeepaliveTimestamp;
    qint64 keepaliveTimeout;
    qint64 keepaliveInterval;
    QString errorString;
    int errorCode;
    bool mustMask;
private:
    WebSocketConnection * const q_ptr;
    Q_DECLARE_PUBLIC(WebSocketConnection);
};

void setWebSocketConnectionPrivateResponse(WebSocketConnectionPrivate *d, HttpResponse response)
{
    d->response = response;
}

WebSocketConfigurationPrivate::WebSocketConfigurationPrivate()
    : keepaliveInterval(5 * 1000)
    , keepaliveTimeout(60 * 1000)
    , sendingQueueCapacity(256)
    , receivingQueueCapacity(256)
    , maxPayloadSize(INT32_MAX)
    , outgoingSize(1024 * 64)
{
}

WebSocketConfiguration::WebSocketConfiguration()
    : d_ptr(new WebSocketConfigurationPrivate())
{
}

WebSocketConfiguration::~WebSocketConfiguration()
{
    delete d_ptr;
}

void WebSocketConfiguration::setKeepaliveInterval(float keepaliveInterval)
{
    Q_D(WebSocketConfiguration);
    d->keepaliveInterval = static_cast<qint64>(keepaliveInterval * 1000);
    if (d->keepaliveInterval < 200) {
        d->keepaliveInterval = 200;
    }
}

float WebSocketConfiguration::keepaliveInterval() const
{
    Q_D(const WebSocketConfiguration);
    return static_cast<float>(d->keepaliveInterval) / 1000.0f;
}

void WebSocketConfiguration::setKeepaliveTimeout(float timeout)
{
    Q_D(WebSocketConfiguration);
    if (timeout > 0) {
        d->keepaliveTimeout = static_cast<qint64>(timeout * 1000);
        if (d->keepaliveTimeout < 1000) {
            d->keepaliveTimeout = 1000;
        }
    }
}

float WebSocketConfiguration::keepaliveTimeout() const
{
    Q_D(const WebSocketConfiguration);
    return static_cast<float>(d->keepaliveTimeout) / 1000.0f;
}

quint32 WebSocketConfiguration::sendingQueueCapacity() const
{
    Q_D(const WebSocketConfiguration);
    return d->sendingQueueCapacity;
}

void WebSocketConfiguration::setSendingQueueCapacity(quint32 capacity)
{
    Q_D(WebSocketConfiguration);
    Q_ASSERT(capacity != 0);
    d->sendingQueueCapacity = capacity;
}

quint32 WebSocketConfiguration::receivingQueueCapacity() const
{
    Q_D(const WebSocketConfiguration);
    return d->receivingQueueCapacity;
}

void WebSocketConfiguration::setReceivingQueueCapacity(quint32 capacity)
{
    Q_D(WebSocketConfiguration);
    Q_ASSERT(capacity > 0);
    d->receivingQueueCapacity = capacity;
}

qint32 WebSocketConfiguration::maxPayloadSize() const
{
    Q_D(const WebSocketConfiguration);
    return d->maxPayloadSize;
}

void WebSocketConfiguration::setMaxPayloadSize(qint32 size)
{
    Q_D(WebSocketConfiguration);
    if (size >= 1024 && size <= INT32_MAX) {
        d->maxPayloadSize = size;
    }
}

QStringList WebSocketConfiguration::protocols() const
{
    Q_D(const WebSocketConfiguration);
    return d->protocols;
}

void WebSocketConfiguration::setProtocols(const QStringList &protocols)
{
    Q_D(WebSocketConfiguration);
    d->protocols = protocols;
}

void WebSocketConfiguration::setOutgoingSize(qint32 size)
{
    Q_D(WebSocketConfiguration);
    d->outgoingSize = size;
}

qint32 WebSocketConfiguration::outgoingSize() const
{
    Q_D(const WebSocketConfiguration);
    return d->outgoingSize;
}

WebSocketFrame::WebSocketFrame()
    : fin(0)
    , rsv1(0)
    , rsv2(0)
    , rsv3(0)
    , opcode(0)
    , maskkey(0)
{
}

qint64 WebSocketFrame::feedHeader(char *packet, int &packetSize)
{
    Q_ASSERT(packetSize >= 2);
    // the qFromBigEndian<>() only accept uchar* in the earlier version of Qt.
    uchar *upacket = reinterpret_cast<uchar *>(packet);
    unsigned char b0 = upacket[0];
    unsigned char b1 = upacket[1];

    fin = (b0 & 0x80) >> 7;
    rsv1 = (b0 & 0x40) >> 6;
    rsv2 = (b0 & 0x20) >> 5;
    rsv3 = (b0 & 0x10) >> 4;
    opcode = b0 & 0x0f;

    bool has_mask = b1 & 0x80;
    int len = b1 & 0x7f;
    maskkey = 0;

    int headerSize = 2;
    if (len <= 125) {
        // pass
    } else if (len == 126) {
        if (packetSize >= headerSize + 2) {
            len = qFromBigEndian<quint16>(upacket + headerSize);
            headerSize += 2;
        } else {
            return -1;
        }
    } else {
        Q_ASSERT(len == 127);
        if (packetSize >= headerSize + 8) {
            len = qFromBigEndian<quint64>(upacket + headerSize);
            headerSize += 8;
        } else {
            return -1;
        }
    }
    if (has_mask) {
        if (packetSize >= headerSize + 4) {
            maskkey = qFromBigEndian<quint32>(upacket + headerSize);
            headerSize += 4;
        } else {
            return -1;
        }
    }
    memmove(packet, packet + headerSize, packetSize - headerSize);
    packetSize -= headerSize;
    return len;
}

// the length of dst must larger than offset + size!
void WebSocketFrame::applyMaskTo(char *dst, int offset, int size) const
{
    int i = offset;
    int j = 0;
    if (size < payload.size()) {
        qtng_warning << "applyMaskTo() got an dest buffer which is too small.";
    }
    const char *src = payload.constData();
    uchar maskbuf[4];
    qToBigEndian<quint32>(maskkey, maskbuf);
    int last = offset + qMin(size, payload.size());
    // XOR the remainder of the input byte by byte.
    for (; i < last; ++i, ++j) {
        dst[i] = src[j] ^ maskbuf[j % 4];
    }
}

/*
// the length of dst must larger than offset + size!
void WebSocketFrame::applyMaskTo(char *dst, int offset, int size) const
{
    int i = offset;
    int j = 0;
    if (size < payload.size()) {
        qtng_warning << "applyMaskTo() got an dest buffer which is too small.";
    }
    int last = offset + qMin(size, payload.size());
    int next_offset_8 = (offset + 7) / 8 * 8;
    const char *src = payload.constData();
    uchar maskbuf[4];
    qToBigEndian<quint32>(maskkey, maskbuf);

    // We shoud make sure the memory allocator aligns everything on 8 bytes boundaries.
    // and assume that payload buf is aligns on 8 bytes boundaries.
    for (; i < next_offset_8 && i < last; ++i, ++j) {
        dst[i] = src[j] ^ maskbuf[j % 4];
    }

    // We need a new scope for MSVC 2010 (non C99 friendly)
    {
#if __ARM_NEON
        // With NEON support, XOR by blocks of 16 bytes = 128 bits.

        int last_128 = last & ~15;
        uint8x16_t mask_128 = vreinterpretq_u8_u32(vdupq_n_u32(maskkey));

        for (; i < last_128; i += 16, j += 16) {
            uint8x16_t in_128 = vld1q_u8((uint8_t *) (src + j));
            uint8x16_t out_128 = veorq_u8(in_128, mask_128);
            vst1q_u8((uint8_t *) (dst + i), out_128);
        }
#elif __SSE2__
        // With SSE2 support, XOR by blocks of 16 bytes = 128 bits.
        // we use load/store instead of loadu/storeu

        int last_128 = last & ~15;
        __m128i mask_128 = _mm_set1_epi32(maskkey);

        for (; i < last_128; i += 16, j += 16) {
            __m128i in_128 = _mm_loadu_si128((__m128i *) (src + j));
            __m128i out_128 = _mm_xor_si128(in_128, mask_128);
            _mm_storeu_si128((__m128i *) (dst + i), out_128);
        }
#else
        // Without SSE2 support, XOR by blocks of 8 bytes = 64 bits.

        int last_64 = last & ~7;
        uint64_t mask_64 = ((uint64_t) maskkey << 32) | (uint64_t) maskkey;

        for (; i < last_64; i += 8, j += 8) {
            *(uint64_t *) (dst + i) = *(uint64_t *) (src + j) ^ mask_64;
        }
#endif
    }

    // XOR the remainder of the input byte by byte.
    for (; i < last; ++i, ++j) {
        dst[i] = src[j] ^ maskbuf[j % 4];
    }
}
*/

QByteArray WebSocketFrame::toByteArray() const
{
    int len = payload.size();
    QByteArray buf(len + 32, Qt::Uninitialized);
    int packetSize = 2;

    if (fin) {
        buf[0] = 0x80;
    } else {
        buf[0] = 0;
    }
    buf[0] = buf[0] | opcode;

    if (maskkey > 0) {
        buf[1] = 0x80;
    } else {
        buf[1] = 0;
    }

    uchar *ubuf = reinterpret_cast<uchar *>(buf.data());
    if (len <= 125) {
        buf[1] = buf[1] | len;
    } else if (len < 65535) {
        buf[1] = buf[1] | 126;
        qToBigEndian<quint16>(len, ubuf + 2);
        packetSize += 2;
    } else {
        buf[1] = buf[1] | 127;
        qToBigEndian<quint64>(len, ubuf + 2);
        packetSize += 8;
    }

    if (maskkey > 0) {
        qToBigEndian<quint32>(this->maskkey, ubuf + packetSize);
        packetSize += 4;
        applyMaskTo(buf.data(), packetSize, buf.size() - packetSize);
    } else {
        memcpy(buf.data() + packetSize, payload.constData(), payload.size());
    }
    packetSize += payload.size();
    return buf.left(packetSize);
}

WebSocketConnectionPrivate::WebSocketConnectionPrivate(QSharedPointer<SocketLike> connection,const QByteArray &headBytes,
                                                       WebSocketConnection::Side side,
                                                       const WebSocketConfiguration &config, WebSocketConnection *q)
    : operations(new CoroutineGroup())
    , connection(connection)
    , receivingQueue(config.receivingQueueCapacity())
    , sendingQueue(config.sendingQueueCapacity())
    , state(WebSocketConnection::Open)
    , side(side)
    , debugLevel(0)
    , maxPayloadSize(config.maxPayloadSize())
    , outgoingSize(config.outgoingSize())
    , lastActiveTimestamp(QDateTime::currentMSecsSinceEpoch())
    , lastKeepaliveTimestamp(lastActiveTimestamp)
    , keepaliveTimeout(config.keepaliveTimeout() * 1000)
    , keepaliveInterval(config.keepaliveInterval() * 1000)
    , errorCode(0)
    , mustMask(side == WebSocketConnection::Client)
    , q_ptr(q)
{
    id = randomBytes(16);
#if QT_VERSION < QT_VERSION_CHECK(5, 10, 0)
    static bool inited = false;
    if (!inited) {
        inited = true;
        qsrand(static_cast<uint>(QDateTime::currentMSecsSinceEpoch()));
    }
#endif
    operations->spawnWithName(QString::fromUtf8("send"), [this] { doSend(); });
    operations->spawnWithName(QString::fromUtf8("receive"), [this, headBytes] { doReceive(headBytes); });
    operations->spawnWithName(QString::fromUtf8("keepalive"), [this] { doKeepalive(); });
}

WebSocketConnectionPrivate::~WebSocketConnectionPrivate()
{
    abort(WebSocketConnection::GoingAway);
    delete operations;
}

quint32 WebSocketConnectionPrivate::makeMaskkey()
{
#if QT_VERSION >= QT_VERSION_CHECK(5, 10, 0)
    QRandomGenerator *generator = QRandomGenerator::global();
    return generator->bounded(static_cast<quint32>(1), static_cast<quint32>(0xffffffff));
#else
    return 1 + (static_cast<quint32>(qrand()) & 0xfffffffe);
#endif
}

QVector<WebSocketFrame> WebSocketConnectionPrivate::fragmentFrame(const PacketToWrite &writingPacket,
                                                                  const int blockSize)
{
    int nFrames = (writingPacket.payload.size() + blockSize - 1) / blockSize;
    if (nFrames == 0)
        nFrames = 1;
    QVector<WebSocketFrame> frames(nFrames);
    // optimize if there is only one frame
    if (nFrames == 1) {
        frames[0].payload = writingPacket.payload;
        if (mustMask) {
            frames[0].maskkey = makeMaskkey();
        } else {
            frames[0].maskkey = 0;
        }
    } else {
        for (int i = 0; i < nFrames; ++i) {
            int start = blockSize * i;
            int len = qMin(start + blockSize, writingPacket.payload.size());
            frames[i].fin = 0;  // may be changed before function returns
            frames[i].opcode = 0;  // continuation frame, may be changed before function returns
            frames[i].payload = writingPacket.payload.mid(start, len - start);
            if (mustMask) {
                frames[i].maskkey = makeMaskkey();
            } else {
                frames[i].maskkey = 0;
            }
        }
    }

    if (writingPacket.type == WebSocketConnection::Text) {
        frames.first().opcode = 0x1;
    } else {
        Q_ASSERT(writingPacket.type == WebSocketConnection::Binary);
        frames.first().opcode = 0x2;
    }
    frames.last().fin = 1;

    return frames;
}

WebSocketFrame WebSocketConnectionPrivate::makeControlFrame(FrameType type)
{
    WebSocketFrame frame;
    frame.fin = 1;
    switch (type) {
    case CloseFrame:
        frame.opcode = 0x8;
        break;
    case PingFrame:
        frame.opcode = 0x9;
        break;
    case PongFrame:
        frame.opcode = 0xa;
        break;
    default:
        Q_UNREACHABLE();
    }
    if (mustMask) {
        frame.maskkey = makeMaskkey();
    } else {
        frame.maskkey = 0;
    }
    return frame;
}

QPair<int, QString> WebSocketConnectionPrivate::parseClosePayload(const QByteArray &payload)
{
    QPair<int, QString> result = qMakePair(WebSocketConnection::NormalClosure, QString::fromUtf8("Normal Closure"));
    if (payload.size() < 2) {
        return result;
    }
    result.first = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(payload.constData()));
    result.second = QString::fromUtf8(QByteArray::fromRawData(payload.constData() + 2, payload.size() - 2));
    return result;
}

QByteArray WebSocketConnectionPrivate::makeClosePayload(int closeCode, const QString &closeReason)
{
    if (closeCode < 0 || closeCode > 1024 * 64) {
        return QByteArray();
    }
    QByteArray buf(closeReason.size() * 4 + 2, Qt::Uninitialized);
    qToBigEndian<quint16>(closeCode, reinterpret_cast<uchar *>(buf.data()));
    const QByteArray t = closeReason.toUtf8();
    memcpy(buf.data() + 2, t.constData(), t.size());
    // the the max size of control frames is 125.
    return buf.left(qMin(t.size() + 2, 125));
}

void WebSocketConnectionPrivate::doSend()
{
    PacketToWrite writingPacket;
    while (true) {
        try {
            writingPacket = sendingQueue.get();
        } catch (CoroutineExitException &) {
            Q_ASSERT(errorCode != WebSocketConnection::NoError);
            return;
        } catch (...) {
            qtng_critical << "unknown error occured in WebSocketConnectionPrivate::doSend().";
            return abort(WebSocketConnection::InternalError);
        }
        if (!writingPacket.isValid()) {
            Q_ASSERT(errorCode != WebSocketConnection::NoError);
            return;
        }

        QSharedPointer<ValueEvent<bool>> done = writingPacket.done;
        auto cleanup = qScopeGuard([done] {
            if (!done.isNull()) {
                done->send(false);
            }
        });

        const QVector<WebSocketFrame> &frames = fragmentFrame(writingPacket, outgoingSize);
        for (const WebSocketFrame &frame : frames) {
            if (errorCode != WebSocketConnection::NoError) {
                return;
            }

            // the other coroutines may want to send something.
            // can raise CoroutineExitException!
            // Coroutine::sleep(0);

            const QByteArray &packet = frame.toByteArray();
            if (!sendBytes(packet)) {
                return;
            }
        }

        cleanup.dismiss();
        if (!writingPacket.done.isNull()) {
            writingPacket.done->send(true);
        }
    }
}

inline bool isOpCodeReserved(int code)
{
    return ((code > BinaryFrame) && (code < CloseFrame)) || (code > PongFrame);
}

inline bool isCloseCodeValid(int closeCode)
{
    // see RFC6455 7.4.1
    return (closeCode > 999) && (closeCode < 5000) && (closeCode != 1004) && (closeCode != 1005) && (closeCode != 1006)
            && ((closeCode >= 3000) || (closeCode < 1012));
}

void WebSocketConnectionPrivate::doReceive(const QByteArray &headBytes)
{
    QByteArray buf(1024 * 64, Qt::Uninitialized);
    int usedSize = 0;
    if (headBytes.size() > buf.size()) {
        buf = headBytes;
        usedSize = headBytes.size();
    } else if (!headBytes.isEmpty()) {
        memcpy(buf.data(), headBytes.constData(), headBytes.size());
        usedSize = headBytes.size();
    }

    WebSocketConnection::FrameType tmpType = WebSocketConnection::Unknown;
    QByteArray tmpPayload;
    bool needMoreData = buf.size() < 2;

    while (true) {
        if ((usedSize < 2 || needMoreData) && !recvBytes(buf, usedSize)) {
            return;
        }
        if (usedSize < 2) {
            continue;
        }

        WebSocketFrame frame;
        qint64 payloadSize = frame.feedHeader(buf.data(), usedSize);
        if (payloadSize < 0) {
            // there are not enough header bytes to parse. we will receive more, and try again later.
            Q_ASSERT(buf.size() > usedSize);
            needMoreData = true;
            continue;
        } else if (payloadSize > maxPayloadSize) {
            qtng_info << "can not process web socket frame larger than " << maxPayloadSize;
            WebSocketFrame closeFrame = makeControlFrame(CloseFrame);
            closeFrame.payload = makeClosePayload(WebSocketConnection::MessageTooBig,
                                                  QString::fromUtf8("the frame is too big to process."));
            if (sendBytes(closeFrame.toByteArray())) {
                // XXX do abort() only if sendBytes() returns success.
                return abort(WebSocketConnection::MessageTooBig);
            } else {
                return;
            }
        }
        needMoreData = false;
        if (debugLevel >= 3) {
            qtng_debug << "want payload:" << payloadSize;
        }

        while (frame.payload.size() < payloadSize) {
            int size = qMin<int>(payloadSize - frame.payload.size(), usedSize);
            frame.payload.append(buf.data(), size);
            usedSize -= size;
            if (usedSize > 0) {
                memmove(buf.data(), buf.data() + size, usedSize);
            }

            // we got enougth data!
            if (frame.payload.size() >= payloadSize) {
                Q_ASSERT(frame.payload.size() == payloadSize);
                if (frame.maskkey > 0) {
                    frame.applyMaskTo(frame.payload.data(), 0, payloadSize);
                }
                break;
            }

            // not enough payload!
            if (!recvBytes(buf, usedSize)) {
                return;
            }
        }
        if (debugLevel >= 1) {
            qtng_debug << "got frame:" << frame.opcode;
        }
        if (frame.opcode == FrameType::ContinuationFrame) {
            if (tmpType == WebSocketConnection::Unknown) {
                // ContinuationFrame is sent before text frame or binary frame?
                return abort(WebSocketConnection::ProtocolError);
            }
            tmpPayload.append(frame.payload);
            if (frame.fin) {
                PacketToRead packet;
                packet.payload = tmpPayload;
                packet.type = tmpType;
                receivingQueue.put(packet);
                tmpPayload.clear();
                tmpType = WebSocketConnection::Unknown;
            }
        } else if (frame.opcode == FrameType::TextFrame) {
            if (frame.fin) {
                PacketToRead packet;
                packet.payload = frame.payload;
                packet.type = WebSocketConnection::Text;
                receivingQueue.put(packet);
            } else {
                if (tmpType != WebSocketConnection::Unknown || !tmpPayload.isEmpty()) {
                    // the previous frame have no last ContinuationFrame which set fin to 1.
                    return abort(WebSocketConnection::ProtocolError);
                }
                tmpType = WebSocketConnection::Text;
                tmpPayload = frame.payload;
            }
        } else if (frame.opcode == FrameType::BinaryFrame) {
            if (frame.fin) {
                PacketToRead packet;
                packet.payload = frame.payload;
                packet.type = WebSocketConnection::Binary;
                receivingQueue.put(packet);
            } else {
                if (tmpType != WebSocketConnection::Unknown || !tmpPayload.isEmpty()) {
                    // the previous frame have no last ContinuationFrame which set fin to 1.
                    return abort(WebSocketConnection::ProtocolError);
                }
                tmpType = WebSocketConnection::Binary;
                tmpPayload = frame.payload;
            }
        } else if (frame.opcode == FrameType::CloseFrame) {
            const QPair<int, QString> &result = parseClosePayload(frame.payload);
            if (state == WebSocketConnection::Open) {
                state = WebSocketConnection::Closing;
                WebSocketFrame closeFrame = makeControlFrame(CloseFrame);
                closeFrame.payload = frame.payload;
                if (!sendBytes(closeFrame.toByteArray())) {
                    return;
                }
                return abort(WebSocketConnection::NormalClosure);
            } else if (state == WebSocketConnection::Closing) {
                return abort(WebSocketConnection::NormalClosure);
            }
            if (result.first >= 1000) {
                // TODO 正常关闭。
            }
        } else if (frame.opcode == FrameType::PingFrame) {
            WebSocketFrame pongFrame = makeControlFrame(PongFrame);
            pongFrame.payload = frame.payload;
            if (!sendBytes(pongFrame.toByteArray())) {
                return;
            }
        } else if (frame.opcode == FrameType::PongFrame) {
            // ignore
        } else {
            // unknown opcode is an error.
            return abort(WebSocketConnection::ProtocolError);
        }
    }
}

void WebSocketConnectionPrivate::doKeepalive()
{
    while (true) {
        Coroutine::sleep(0.5f);
        qint64 now = QDateTime::currentMSecsSinceEpoch();
        // now and lastActiveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastActiveTimestamp && (now - lastActiveTimestamp > keepaliveTimeout)) {
            if (debugLevel >= 1) {
                qtng_debug << "channel is timeout.";
            }
            return abort(WebSocketConnection::GoingAway);
        }

        // TODO only send ping frame while the doSend() coroutine is idle.
        // now and lastKeepaliveTimestamp both are unsigned int, we should check which is larger before apply minus
        // operator to them.
        if (now > lastKeepaliveTimestamp && (now - lastKeepaliveTimestamp > keepaliveInterval)) {
            if (debugLevel >= 2) {
                qtng_debug << "sending keepalive packet.";
            }
            const WebSocketFrame &pingFrame = makeControlFrame(PingFrame);
            if (!sendBytes(pingFrame.toByteArray())) {
                return;
            }
        }
    }
}

bool WebSocketConnectionPrivate::close()
{
    if (state != WebSocketConnection::Open) {
        return true;
    }
    if (debugLevel >= 1) {
        qtng_debug << "closing web socket.";
    }
    state = WebSocketConnection::Closing;
    WebSocketFrame closeFrame = makeControlFrame(CloseFrame);
    closeFrame.payload = makeClosePayload(WebSocketConnection::NormalClosure, QString::fromUtf8("normal closure."));
    if (!sendBytes(closeFrame.toByteArray())) {
        return false;
    }
    abort(WebSocketConnection::NormalClosure);
    return true;
}

void WebSocketConnectionPrivate::setErrorCode(int errorCode, const QString &errorString)
{
    if (this->errorCode != 0) {
        qtng_warning << "the error code of web socket connection is not zero. did you have set it?" << this->errorCode
                     << errorCode;
    }
    this->errorCode = errorCode;
    if (errorString.isEmpty()) {
        switch (errorCode) {
        case WebSocketConnection::NormalClosure:
            this->errorString = QString::fromUtf8("OK");
            break;
        case WebSocketConnection::GoingAway:
            this->errorString = QString::fromUtf8("going away");
            break;
        case WebSocketConnection::ProtocolError:
            this->errorString = QString::fromUtf8("protocol error");
            break;
        case WebSocketConnection::UnsupportedData:
            this->errorString = QString::fromUtf8("unsupported data");
            break;
        case WebSocketConnection::NoStatusRcvd:
            this->errorString = QString::fromUtf8("no status received [internal]");
            break;
        case WebSocketConnection::AbnormalClosure:
            this->errorString = QString::fromUtf8("abnormal closure [internal]");
            break;
        case WebSocketConnection::InvalidData:
            this->errorString = QString::fromUtf8("invalid frame payload data");
            break;
        case WebSocketConnection::PolicyViolation:
            this->errorString = QString::fromUtf8("policy violation");
            break;
        case WebSocketConnection::MessageTooBig:
            this->errorString = QString::fromUtf8("message too big");
            break;
        case WebSocketConnection::MandatoryExtension:
            this->errorString = QString::fromUtf8("mandatory extension");
            break;
        case WebSocketConnection::InternalError:
            this->errorString = QString::fromUtf8("internal error");
            break;
        case WebSocketConnection::ServiceRestart:
            this->errorString = QString::fromUtf8("service restart");
            break;
        case WebSocketConnection::TryAgainLater:
            this->errorString = QString::fromUtf8("try again later");
            break;
        case WebSocketConnection::BadGateway:
            this->errorString = QString::fromUtf8("bad gateway");
            break;
        case WebSocketConnection::TlsHandshake:
            this->errorString = QString::fromUtf8("TLS handshake failure [internal]");
            break;
        default:
            qtng_warning << "the error code is not recognized:" << errorCode;
        }
    }
}

void WebSocketConnectionPrivate::abort(int errorCode)
{
    Q_Q(WebSocketConnection);
    if (this->errorCode != WebSocketConnection::NoError) {
        return;
    }
    if (debugLevel >= 1) {
        qtng_debug << "abort(" << errorCode << ")";
    }
    Q_ASSERT(state != WebSocketConnection::Closed);
    setErrorCode(errorCode, QString());
    state = WebSocketConnection::Closed;
    Coroutine *current = Coroutine::current();
    if (errorCode == WebSocketConnection::NormalClosure) {
        connection->close();
    } else {
        connection->abort();
    }

    while (!sendingQueue.isEmpty()) {
        const PacketToWrite &writingPacket = sendingQueue.get();
        if (!writingPacket.done.isNull()) {
            writingPacket.done->send(false);
        }
    }
    if (operations->get(QString::fromLatin1("receive")).data() != current) {
        operations->kill(QString::fromLatin1("receive"));
    }
    if (operations->get(QString::fromLatin1("send")).data() != current) {
        operations->kill(QString::fromLatin1("send"));
    }
    if (operations->get(QString::fromLatin1("keepalive")).data() != current) {
        operations->kill(QString::fromLatin1("keepalive"));
    }
    for (quint32 i = 0; i < receivingQueue.getting(); ++i) {
        receivingQueue.put(PacketToRead(WebSocketConnection::Unknown, QByteArray()));
    }
    q->disconnected->set();
}

bool WebSocketConnectionPrivate::recvBytes(QByteArray &buf, int &usedSize)
{
    qint32 receivedBytes;
    try {
        receivedBytes = connection->recv(buf.data() + usedSize, buf.size() - usedSize);
    } catch (CoroutineExitException &) {
        Q_ASSERT(errorCode != WebSocketConnection::NoError);
        return false;
    } catch (...) {
        abort(WebSocketConnection::InternalError);
        return false;
    }

    if (receivedBytes <= 0) {
        abort(WebSocketConnection::AbnormalClosure);
        return false;
    } else {
        if (debugLevel >= 3) {
            qtng_debug << "received data:" << QByteArray::fromRawData(buf.data() + usedSize, receivedBytes);
        } else if (debugLevel >= 2) {
            qtng_debug << "received data:" << receivedBytes;
        }
        usedSize += receivedBytes;
        lastActiveTimestamp = QDateTime::currentMSecsSinceEpoch();
        return true;
    }
}

bool WebSocketConnectionPrivate::sendBytes(const QByteArray &packet)
{
    ScopedLock<Lock> locklock(writeLock);
    if (debugLevel >= 2) {
        qtng_debug << "sending packet:" << packet;
    } else if (debugLevel >= 1) {
        qtng_debug << "sending packet:" << packet.size();
    }
    qint32 sentBytes;
    try {
        sentBytes = connection->sendall(packet);
    } catch (CoroutineExitException &) {
        Q_ASSERT(errorCode != WebSocketConnection::NoError);
        return false;
    } catch (...) {
        if (debugLevel >= 1) {
            qtng_info << "unhandled exception while sending packet.";
        }
        abort(WebSocketConnection::InternalError);
        return false;
    }
    if (sentBytes != packet.size()) {
        abort(WebSocketConnection::AbnormalClosure);
        return false;
    }
    lastKeepaliveTimestamp = QDateTime::currentMSecsSinceEpoch();
    return true;
}

WebSocketConnection::WebSocketConnection(QSharedPointer<SocketLike> connection, const QByteArray &headBytes, Side side,
                                         const WebSocketConfiguration &config)
    : disconnected(new Event())
    , d_ptr(new WebSocketConnectionPrivate(connection, headBytes, side, config, this))
{
}

WebSocketConnection::~WebSocketConnection()
{
    delete d_ptr;
}

void WebSocketConnection::setConfiguration(const WebSocketConfiguration &config)
{
    Q_D(WebSocketConnection);
    d->receivingQueue.setCapacity(config.receivingQueueCapacity());
    d->sendingQueue.setCapacity(config.sendingQueueCapacity());
    d->maxPayloadSize = config.maxPayloadSize();
    d->outgoingSize = config.outgoingSize();
    d->keepaliveTimeout = config.keepaliveTimeout() * 1000;
    d->keepaliveInterval = config.keepaliveInterval() * 1000;
}

bool WebSocketConnection::send(const QByteArray &packet)
{
    Q_D(WebSocketConnection);
    if (d->state != WebSocketConnection::Open) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done = QSharedPointer<ValueEvent<bool>>::create();
    d->sendingQueue.put(PacketToWrite(packet, done));
    return done->tryWait();
}

bool WebSocketConnection::send(const QString &text)
{
    Q_D(WebSocketConnection);
    if (d->state != WebSocketConnection::Open) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done = QSharedPointer<ValueEvent<bool>>::create();
    d->sendingQueue.put(PacketToWrite(text, done));
    return done->tryWait();
}

bool WebSocketConnection::post(const QByteArray &packet)
{
    Q_D(WebSocketConnection);
    if (d->state != WebSocketConnection::Open) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done;
    d->sendingQueue.put(PacketToWrite(packet, done));
    return true;
}

bool WebSocketConnection::post(const QString &text)
{
    Q_D(WebSocketConnection);
    if (d->state != WebSocketConnection::Open) {
        return false;
    }
    QSharedPointer<ValueEvent<bool>> done;
    d->sendingQueue.put(PacketToWrite(text, done));
    return true;
}

QByteArray WebSocketConnection::recv(FrameType *type)
{
    Q_D(WebSocketConnection);
    if (d->state != WebSocketConnection::Open) {
        return QByteArray();
    }
    const PacketToRead &p = d->receivingQueue.get();
    if (!p.isValid()) {
        if (type) {
            *type = WebSocketConnection::Unknown;
        }
        return QByteArray();
    }
    if (type) {
        *type = p.type;
    }
    return p.payload;
}

void WebSocketConnection::close()
{
    Q_D(WebSocketConnection);
    d->close();
}

void WebSocketConnection::abort()
{
    Q_D(WebSocketConnection);
    d->abort(WebSocketConnection::AbnormalClosure);
}

QByteArray WebSocketConnection::id() const
{
    Q_D(const WebSocketConnection);
    return d->id;
}

WebSocketConnection::Side WebSocketConnection::side() const
{
    Q_D(const WebSocketConnection);
    return d->side;
}

WebSocketConnection::State WebSocketConnection::state() const
{
    Q_D(const WebSocketConnection);
    return d->state;
}

int WebSocketConnection::WebSocketConnection::closeCode() const
{
    Q_D(const WebSocketConnection);
    return d->errorCode;
}

QString WebSocketConnection::closeReason() const
{
    Q_D(const WebSocketConnection);
    return d->errorString;
}

QString WebSocketConnection::toString() const
{
    Q_D(const WebSocketConnection);
    QString pattern = QString::fromUtf8("<WebSocketConnection (id = %1, error = %2, capacity = %3, queue_size = %4)>");
    return pattern.arg(QString::fromLatin1(d->id.toHex()))
            .arg(d->errorString)
            .arg(d->receivingQueue.capacity())
            .arg(d->receivingQueue.size());
}

void WebSocketConnection::setDebugLevel(int level)
{
    Q_D(WebSocketConnection);
    if (level >= 0) {
        d->debugLevel = level;
    }
}

int WebSocketConnection::debugLevel() const
{
    Q_D(const WebSocketConnection);
    return d->debugLevel;
}

void WebSocketConnection::setMustMask(bool yes)
{
    Q_D(WebSocketConnection);
    d->mustMask = yes;
}

bool WebSocketConnection::mustMask() const
{
    Q_D(const WebSocketConnection);
    return d->mustMask;
}

QString WebSocketConnection::origin() const
{
    Q_D(const WebSocketConnection);
    return QString::fromUtf8(d->response.request().header(QString::fromUtf8("Origin")));
}

QUrl WebSocketConnection::url() const
{
    Q_D(const WebSocketConnection);
    return d->response.url();
}

const HttpResponse &WebSocketConnection::response() const
{
    Q_D(const WebSocketConnection);
    return d->response;
}

QTNETWORKNG_NAMESPACE_END
