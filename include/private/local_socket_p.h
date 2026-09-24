#ifndef QTNG_LOCAL_SOCKET_P_H
#define QTNG_LOCAL_SOCKET_P_H

#include <QtCore/qstring.h>
#include <QtCore/qbytearray.h>
#include "../local_socket.h"
#include "../locks.h"

QTNETWORKNG_NAMESPACE_BEGIN

class LocalSocketPrivate
{
public:
    enum ErrorString {
        NonBlockingInitFailedErrorString,
        RemoteHostClosedErrorString,
        TimeOutErrorString,
        ResourceErrorString,
        OperationUnsupportedErrorString,
        InvalidSocketErrorString,
        AccessErrorString,
        ConnectionRefusedErrorString,
        AddressInuseErrorString,
        AddressNotAvailableErrorString,
        WriteErrorString,
        ReadErrorString,
        OutOfMemoryErrorString,
        UnknownSocketErrorString = -1
    };
public:
    LocalSocketPrivate(LocalSocket *parent);
    explicit LocalSocketPrivate(qintptr socketDescriptor, LocalSocket *parent);
    virtual ~LocalSocketPrivate();
public:
    void setError(Socket::SocketError error, const QString &errorString);
    void setError(Socket::SocketError error, ErrorString errorString);
    QString getErrorString() const;
    bool isValid() const;
    bool checkState() const;

    LocalSocket *accept();
    bool bind(const QString &name, Socket::BindMode mode);
    bool connect(const QString &name);
    // close(): wake waiters, drain readLock/writeLock, then release the handle.
    // abort(): wake and release immediately without draining — safe to call
    // while the current coroutine already holds a lock (e.g. from recv/send).
    // Not interchangeable: destroying/aborting a listening socket while another
    // coroutine is in accept() is undefined; stop the server with close().
    void close();
    void abort();
    bool listen(int backlog);
    bool setOption(Socket::SocketOption option, const QVariant &value);
    QVariant option(Socket::SocketOption option) const;

    qint32 peek(char *data, qint32 size);
    qint32 recv(char *data, qint32 size, bool all);
    qint32 send(const char *data, qint32 size, bool all);

    static QString makeFullServerName(const QString &name);
    QString localAddressURI() const;
    QString peerAddressURI() const;
protected:
    bool createSocket();
    void setSocketDescriptor(qintptr socketDescriptor);
#ifdef Q_OS_WIN
    bool createPipeInstance(bool firstInstance);
    // Queue a ConnectNamedPipe on the current listening instance.
    //  1: queued (or a client was already waiting),  -1: hard error (error set).
    int startAcceptWait();
    void discardAcceptWait(bool cancelIo);
    void releaseAcceptWait();
    // Drop a listening instance that can serve nobody anymore: cancel the queued
    // wait, close the handle and leave the listening state.
    void dropListeningInstance();
#endif
public:
    LocalSocket *q_ptr;
    Socket::SocketError error;
    QString errorString;
    Socket::SocketState state;
    QString serverName;
    QString fullServerName;
#ifdef Q_OS_WIN
    qintptr fd;  // HANDLE
    // Pending ConnectNamedPipe state, owned by local_socket_win.cpp (Windows
    // types are kept out of this header on purpose). It exists while a pipe
    // instance has ever been armed; `acceptArmed` is what tells whether a
    // ConnectNamedPipe is queued right now. Together they keep the pipe name
    // attended between two accept() calls.
    void *acceptWait;
    bool acceptArmed;
    // Bumped every time the queued wait is replaced or taken away. accept()
    // captures it before sleeping and compares afterwards, so a wake-up caused
    // by a discard can never be mistaken for a client - not even when the socket
    // has been closed and bound again meanwhile.
    quint32 acceptGeneration;
    bool ownsHandle;
#else
    int fd;
    // Path of the socket file this object bound. connect() replaces
    // fullServerName with the peer, so close() must not unlink that.
    QString unlinkPath;
    bool shouldUnlink;
#endif
    Lock readLock;
    Lock writeLock;

    Q_DECLARE_PUBLIC(LocalSocket)
};

QTNETWORKNG_NAMESPACE_END

#endif  // QTNG_LOCAL_SOCKET_P_H
