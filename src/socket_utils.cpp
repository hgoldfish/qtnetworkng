#include <string.h>
#include "../include/socket_utils.h"

QTNETWORKNG_NAMESPACE_BEGIN

SocketLike::~SocketLike()
{
}

namespace {
class SocketLikeImpl: public SocketLike
{
public:
    SocketLikeImpl(QSharedPointer<Socket> s);
    virtual ~SocketLikeImpl();
public:
    virtual Socket::SocketError error() const override;
    virtual QString errorString() const override;
    virtual bool isValid() const override;
    virtual QHostAddress localAddress() const override;
    virtual quint16 localPort() const override;
    virtual QHostAddress peerAddress() const override;
    virtual QString peerName() const override;
    virtual quint16 peerPort() const override;
    virtual qintptr	fileno() const override;
    virtual Socket::SocketType type() const override;
    virtual Socket::SocketState state() const override;
    virtual Socket::NetworkLayerProtocol protocol() const override;

    virtual Socket *acceptRaw() override;
    virtual QSharedPointer<SocketLike> accept() override;
    virtual bool bind(QHostAddress &address, quint16 port, Socket::BindMode mode) override;
    virtual bool bind(quint16 port, Socket::BindMode mode) override;
    virtual bool connect(const QHostAddress &addr, quint16 port) override;
    virtual bool connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol) override;
    virtual bool close() override;
    virtual bool listen(int backlog) override;
    virtual bool setOption(Socket::SocketOption option, const QVariant &value) override;
    virtual QVariant option(Socket::SocketOption option) const override;

    virtual qint32 recv(char *data, qint32 size) override;
    virtual qint32 recvall(char *data, qint32 size) override;
    virtual qint32 send(const char *data, qint32 size) override;
    virtual qint32 sendall(const char *data, qint32 size) override;
    virtual QByteArray recv(qint32 size) override;
    virtual QByteArray recvall(qint32 size) override;
    virtual qint32 send(const QByteArray &data) override;
    virtual qint32 sendall(const QByteArray &data) override;
private:
    QSharedPointer<Socket> s;
};

SocketLikeImpl::SocketLikeImpl(QSharedPointer<Socket> s)
    :s(s) {}


SocketLikeImpl::~SocketLikeImpl()
{
}

Socket::SocketError SocketLikeImpl::error() const
{
    return s->error();
}

QString SocketLikeImpl::errorString() const
{
    return s->errorString();
}

bool SocketLikeImpl::isValid() const
{
    return s->isValid();
}

QHostAddress SocketLikeImpl::localAddress() const
{
    return s->localAddress();
}

quint16 SocketLikeImpl::localPort() const
{
    return s->localPort();
}

QHostAddress SocketLikeImpl::peerAddress() const
{
    return s->peerAddress();
}

QString SocketLikeImpl::peerName() const
{
    return s->peerName();
}

quint16 SocketLikeImpl::peerPort() const
{
    return s->peerPort();
}

qintptr	SocketLikeImpl::fileno() const
{
    return s->fileno();
}

Socket::SocketType SocketLikeImpl::type() const
{
    return s->type();
}

Socket::SocketState SocketLikeImpl::state() const
{
    return s->state();
}

Socket::NetworkLayerProtocol SocketLikeImpl::protocol() const
{
    return s->protocol();
}

Socket *SocketLikeImpl::acceptRaw()
{
    return s->accept();
}


QSharedPointer<SocketLike> SocketLikeImpl::accept()
{
    return SocketLike::rawSocket(s->accept());
}

bool SocketLikeImpl::bind(QHostAddress &address, quint16 port, Socket::BindMode mode)
{
    return s->bind(address, port, mode);
}

bool SocketLikeImpl::bind(quint16 port, Socket::BindMode mode)
{
    return s->bind(port, mode);
}

bool SocketLikeImpl::connect(const QHostAddress &addr, quint16 port)
{
    return s->connect(addr, port);
}

bool SocketLikeImpl::connect(const QString &hostName, quint16 port, Socket::NetworkLayerProtocol protocol)
{
    return s->connect(hostName, port, protocol);
}

bool SocketLikeImpl::close()
{
    return s->close();
}

bool SocketLikeImpl::listen(int backlog)
{
    return s->listen(backlog);
}

bool SocketLikeImpl::setOption(Socket::SocketOption option, const QVariant &value)
{
    return s->setOption(option, value);
}

QVariant SocketLikeImpl::option(Socket::SocketOption option) const
{
    return s->option(option);
}

qint32 SocketLikeImpl::recv(char *data, qint32 size)
{
    return s->recv(data, size);
}

qint32 SocketLikeImpl::recvall(char *data, qint32 size)
{
    return s->recvall(data, size);
}

qint32 SocketLikeImpl::send(const char *data, qint32 size)
{
    return s->send(data, size);
}

qint32 SocketLikeImpl::sendall(const char *data, qint32 size)
{
    return s->sendall(data, size);
}

QByteArray SocketLikeImpl::recv(qint32 size)
{
    return s->recv(size);
}

QByteArray SocketLikeImpl::recvall(qint32 size)
{
    return s->recvall(size);
}

qint32 SocketLikeImpl::send(const QByteArray &data)
{
    return s->send(data);
}

qint32 SocketLikeImpl::sendall(const QByteArray &data)
{
    return s->sendall(data);
}

} //anonymous namespace

QSharedPointer<SocketLike> SocketLike::rawSocket(QSharedPointer<Socket> s)
{
    return QSharedPointer<SocketLikeImpl>::create(s).dynamicCast<SocketLike>();
}


FileLike::~FileLike() {}


QByteArray FileLike::readall(bool *ok)
{
    QByteArray data;
    qint64 s = size();
    if (s >= static_cast<qint64>(INT32_MAX)) {
        if (ok) *ok = false;
        return data;
    } else if (s == 0) {
        return data;
    } else if (s < 0) {
        // size() is not supported.
    } else { // 0 < s < INT32_MAX
        data.reserve(static_cast<qint32>(s));
    }
    char buf[1024 * 8];
    while (!atEnd()) {
        qint32 readBytes = read(buf, 1024 * 8);
        if (readBytes <= 0) {
            if (ok) *ok = false;
            return data;
        }
        data.append(buf, readBytes);
    }
    if (s > 0) {
        if (data.size() != s) {
            if (ok) *ok = false;
            return data;
        }
    }
    if (ok) *ok = true;
    return data;
}

class RawFile: public FileLike
{
public:
    RawFile(QSharedPointer<QFile> f)
        :f(f) {}
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 readall(char *data, qint32 size) override;
    virtual qint32 write(char *data, qint32 size) override;
    virtual qint32 writeall(char *data, qint32 size) override;
    virtual bool atEnd() override;
    virtual void close() override;
    virtual qint64 size() override;
private:
    QSharedPointer<QFile> f;
};

qint32 RawFile::read(char *data, qint32 size)
{
    return f->read(data, size);
}

qint32 RawFile::readall(char *data, qint32 size)
{
    return f->read(data, size);
}

qint32 RawFile::write(char *data, qint32 size)
{
    return f->write(data, size);
}

qint32 RawFile::writeall(char *data, qint32 size)
{
    return f->write(data, size);
}

bool RawFile::atEnd()
{
    return f->atEnd();
}

void RawFile::close()
{
    f->close();
}

qint64 RawFile::size()
{
    return f->size();
}

QSharedPointer<FileLike> FileLike::rawFile(QSharedPointer<QFile> f)
{
    return QSharedPointer<RawFile>::create(f).dynamicCast<FileLike>();
}



class BytesIO: public FileLike
{
public:
    BytesIO(const QByteArray &buf)
        :buf(buf), pos(0) {}
    virtual qint32 read(char *data, qint32 size) override;
    virtual qint32 readall(char *data, qint32 size) override;
    virtual qint32 write(char *data, qint32 size) override;
    virtual qint32 writeall(char *data, qint32 size) override;
    virtual bool atEnd() override;
    virtual void close() override;
    virtual qint64 size() override;
private:
    QByteArray buf;
    qint32 pos;
};

qint32 BytesIO::read(char *data, qint32 size)
{
    qint32 leftBytes = buf.size() - pos;
    qint32 readBytes = qMin(leftBytes, size);
    memcpy(data, buf.data() + pos, readBytes);
    pos += readBytes;
    return readBytes;
}

qint32 BytesIO::readall(char *data, qint32 size)
{
    return BytesIO::read(data, size);
}

qint32 BytesIO::write(char *data, qint32 size)
{
    if (pos + size > buf.size()) {
        buf.resize(pos + size);
    }
    memcpy(buf.data() + pos, data, size);
    pos += size;
    return size;
}

qint32 BytesIO::writeall(char *data, qint32 size)
{
    return BytesIO::write(data, size);
}

bool BytesIO::atEnd()
{
    return pos >= buf.size();
}

void BytesIO::close()
{

}

qint64 BytesIO::size()
{
    return buf.size();
}

QSharedPointer<FileLike> FileLike::bytes(const QByteArray &data)
{
    return QSharedPointer<BytesIO>::create(data).dynamicCast<FileLike>();
}


QTNETWORKNG_NAMESPACE_END
