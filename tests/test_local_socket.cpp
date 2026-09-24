#include <QtTest>
#include <QtCore/quuid.h>
#include <QtCore/qfile.h>
#include <QtCore/qdir.h>
#include <QtCore/qset.h>
#include <QtCore/qelapsedtimer.h>
#include "qtnetworkng.h"

#ifndef Q_OS_WIN
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#endif

using namespace qtng;

// Relative names are resolved against the temp directory by
// LocalSocketPrivate::makeFullServerName() and have to fit into
// sockaddr_un::sun_path - 104 bytes on macOS, 108 on Linux - while macOS already
// spends about 60 of them on the per-user temp directory. Keep the generated
// part short instead of appending a whole UUID.
static QString shortSocketName(const QString &prefix, int randomChars = 12)
{
    return prefix + QUuid::createUuid().toString(QUuid::Id128).left(randomChars);
}

#ifndef Q_OS_WIN
// Leaves a socket file behind with nothing listening on it - exactly what a
// server that died before unlinking its name leaves in the temp directory.
static bool createStaleSocketFile(const QString &path)
{
    const QByteArray encoded = QFile::encodeName(path);
    if (encoded.isEmpty() || encoded.size() >= int(sizeof(((sockaddr_un *) nullptr)->sun_path))) {
        return false;
    }
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, encoded.constData(), static_cast<size_t>(encoded.size()) + 1);
    const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + encoded.size() + 1);
    const int staleSocket = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (staleSocket < 0) {
        return false;
    }
    const bool bound = ::bind(staleSocket, reinterpret_cast<sockaddr *>(&addr), addrLen) == 0;
    ::close(staleSocket);
    return bound;
}

static volatile sig_atomic_t localSocketSigPipeRaised = 0;

static void localSocketSigPipeHandler(int)
{
    localSocketSigPipeRaised = 1;
}

// Installs a catching SIGPIPE handler for the rest of the scope so a raised
// signal is recorded instead of killing the test process. Restores the
// previous action on the way out, including when a QVERIFY returns early.
class RestoreSigPipe
{
public:
    RestoreSigPipe()
        : installed(false)
    {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = localSocketSigPipeHandler;
        sigemptyset(&action.sa_mask);
        localSocketSigPipeRaised = 0;
        installed = ::sigaction(SIGPIPE, &action, &previous) == 0;
    }
    ~RestoreSigPipe()
    {
        if (installed) {
            ::sigaction(SIGPIPE, &previous, nullptr);
        }
    }
    bool installed;
    struct sigaction previous;
};
#endif

struct RemoveFileLater
{
    QString path;
    ~RemoveFileLater()
    {
        if (!path.isEmpty()) {
            QFile::remove(path);
        }
    }
};

// Reads a fixed size request and echoes it back; used by testLocalServerTemplate().
class EchoRequestHandler : public BaseRequestHandler
{
protected:
    virtual void handle() override
    {
        const QByteArray data = request->recvall(4);
        request->sendall(data);
    }
};

class TestLocalSocket : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void init();
    void cleanup();
    void testEcho();
    void testAsSocketLike();
    void testLargeData();
    void testPeerClose();
    void testDuplicateBind();
    void testStaleSocketFileCleanup();
    void testDontShareAddressKeepsStaleFile();
    void testCreateServerAndConnection();
    void testConvertSocketLikeToLocalSocket();
    void testPeek();
    void testMultipleClients();
    void testLocalServerTemplate();
    void testLocalServerRefuseStaleFile();
    void testCloseWhileAccepting();
    void testReuseNameAfterCloseWhileAccepting();
    void testCloseRacesAcceptHandoff();
    void testWrongStateBindListenReportsError();
    void testConnectToMissingServer();
    void testServerCloseReleasesName();
    void testSequentialConnections();
    void testManySmallMessages();
    void testPingPong();
    void testShortRead();
    void testAbortWakesBlockedRecv();
    void testOperationsAfterClose();
    void testZeroSizedTransfers();
    void testUnicodeServerName();
    void testOverlongServerName();
    void testTwoServersInterleaved();
    void testEarlyClientIsNotLost();
    void testAcceptedConnectionSurvivesServerClose();
    void testAbortedClientsDoNotBlockServer();
    void testLocalServerServesSeveralRequests();
    void testCreateServerWithoutListen();
    void testInvalidFileDescriptor();
    void testNameAndUriAccessors();
    void testBindThenConnectMustNotUnlinkPeer();
    void testSendAfterPeerCloseMustNotRaiseSigPipe();
    void testBindThenConnectMustReleaseLocalName();
    void testCloseDuringBusyConnectReturnsPromptly();
private:
    QString pipeName;
};

void TestLocalSocket::initTestCase()
{
#ifndef Q_OS_WIN
    // Almost every test binds a name, and a name that does not fit into
    // sun_path makes bind() fail with "the address is not available". Report
    // that once, with the real cause, instead of failing twenty-seven tests.
    const QByteArray full = QFile::encodeName(
            QDir::temp().absoluteFilePath(shortSocketName(QString::fromLatin1("qtng-"))));
    QVERIFY2(full.size() < int(sizeof(((sockaddr_un *) nullptr)->sun_path)),
             qPrintable(QString::fromLatin1("the temp directory leaves no room for an AF_UNIX name: %1 bytes")
                                .arg(full.size())));
#endif
}

void TestLocalSocket::init()
{
    pipeName = shortSocketName(QString::fromLatin1("qtng-local-"));
}

void TestLocalSocket::cleanup()
{
#ifndef Q_OS_WIN
    const QString path = QDir::temp().absoluteFilePath(pipeName + QString::fromLatin1(".sock"));
    QFile::remove(path);
#endif
}

void TestLocalSocket::testEcho()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.state() == Socket::BoundState);
    QVERIFY(server.listen(10));
    QVERIFY(server.state() == Socket::ListeningState);

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        bool ok = client.connect(pipeName);
        if (!ok) {
            return;
        }
        client.sendall("fish is here.");
        client.close();
    }));

    {
        Timeout _(5.0);
        LocalSocket *request = server.accept();
        QVERIFY(request != nullptr);
        QScopedPointer<LocalSocket> req(request);
        QByteArray data = req->recv(1024);
        QCOMPARE(data, QByteArray("fish is here."));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testAsSocketLike()
{
    QSharedPointer<SocketLike> server = asSocketLike(new LocalSocket());
    QVERIFY(server->bind(pipeName));
    QVERIFY(server->listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        QSharedPointer<SocketLike> client = asSocketLike(new LocalSocket());
        if (!client->connect(pipeName)) {
            return;
        }
        client->sendall("hello socketlike");
        client->close();
    }));

    {
        Timeout _(5.0);
        QSharedPointer<SocketLike> request = server->accept();
        QVERIFY(!request.isNull());
        QCOMPARE(request->type(), Socket::LocalSocket);
        QByteArray data = request->recv(1024);
        QCOMPARE(data, QByteArray("hello socketlike"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testLargeData()
{
    const int payloadSize = 256 * 1024;
    QByteArray payload(payloadSize, Qt::Uninitialized);
    for (int i = 0; i < payloadSize; ++i) {
        payload[i] = static_cast<char>(i & 0xff);
    }

    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, payload] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(payload);
        client.close();
    }));

    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QByteArray data = request->recvall(payloadSize);
        QCOMPARE(data.size(), payloadSize);
        QCOMPARE(data, payload);
    }
    clientCoroutine->join();
}

void TestLocalSocket::testPeerClose()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Event> accepted(new Event());
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, accepted] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        accepted->tryWait();
        client.close();
    }));

    {
        Timeout _(5.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        accepted->set();
        // Wait until peer closes, then recv should report closed.
        Coroutine::msleep(50);
        char buf[64];
        qint32 n = request->recv(buf, sizeof(buf));
        QVERIFY(n <= 0);
        QVERIFY(request->error() == Socket::RemoteHostClosedError || n == 0 || n == -1);
    }
    clientCoroutine->join();
}

void TestLocalSocket::testDuplicateBind()
{
    LocalSocket server1;
    QVERIFY(server1.bind(pipeName));
    QVERIFY(server1.listen(10));

    LocalSocket server2;
    QVERIFY(!server2.bind(pipeName));
    QVERIFY(server2.error() == Socket::AddressInUseError
            || server2.error() == Socket::SocketAccessError
            || server2.error() != Socket::NoError);
}

void TestLocalSocket::testStaleSocketFileCleanup()
{
#ifdef Q_OS_WIN
    QSKIP("stale socket files are a Unix concept");
#else
    const QString path = QDir::temp().absoluteFilePath(pipeName + QString::fromLatin1(".sock"));

    // Simulate a server that died before it could unlink its socket file: bind a
    // plain AF_UNIX socket and close it without removing the path, so the file
    // stays behind with nothing listening on it.
    {
        const QByteArray encoded = QFile::encodeName(path);
        QVERIFY(encoded.size() < int(sizeof(((sockaddr_un *) nullptr)->sun_path)));
        sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, encoded.constData(), static_cast<size_t>(encoded.size()) + 1);
        const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + encoded.size() + 1);
        const int staleSocket = ::socket(AF_UNIX, SOCK_STREAM, 0);
        QVERIFY(staleSocket >= 0);
        QCOMPARE(::bind(staleSocket, reinterpret_cast<sockaddr *>(&addr), addrLen), 0);
        ::close(staleSocket);
    }
    QVERIFY(QFile::exists(path));

    // bind() must recognise the file as stale and reclaim the name.
    LocalSocket server;
    const bool bound = server.bind(pipeName);
    if (!bound) {
        qWarning("bind() over a stale socket file failed: error = %d (%s)", int(server.error()),
                 qPrintable(server.errorString()));
    }
    QVERIFY(bound);
    QVERIFY(server.listen(10));

    // The reclaimed name is live now, so a duplicate bind must still fail.
    LocalSocket other;
    QVERIFY(!other.bind(pipeName));
    QCOMPARE(other.error(), Socket::AddressInUseError);

    server.close();
    QVERIFY(!QFile::exists(path));
#endif
}

void TestLocalSocket::testDontShareAddressKeepsStaleFile()
{
#ifdef Q_OS_WIN
    QSKIP("socket files are a Unix concept");
#else
    const QString path = QDir::temp().absoluteFilePath(pipeName + QString::fromLatin1(".sock"));
    QVERIFY(createStaleSocketFile(path));
    QVERIFY(QFile::exists(path));

    // DontShareAddress asks for the name as it is: the leftover file stays
    // where it is and bind() reports the name as taken.
    LocalSocket server;
    QVERIFY(!server.bind(pipeName, Socket::DontShareAddress));
    QCOMPARE(server.error(), Socket::AddressInUseError);
    QVERIFY(QFile::exists(path));

    // The default mode reclaims exactly the same name.
    LocalSocket reclaiming;
    QVERIFY(reclaiming.bind(pipeName));
    reclaiming.close();
    QVERIFY(!QFile::exists(path));
#endif
}

void TestLocalSocket::testCreateServerAndConnection()
{
    QScopedPointer<LocalSocket> server(LocalSocket::createServer(pipeName));
    QVERIFY(!server.isNull());
    if (server.isNull()) {
        return;
    }
    QCOMPARE(server->state(), Socket::ListeningState);

    Socket::SocketError error = Socket::UnknownSocketError;
    QScopedPointer<LocalSocket> client(LocalSocket::createConnection(pipeName, &error));
    QVERIFY(!client.isNull());
    if (client.isNull()) {
        return;
    }
    QCOMPARE(error, Socket::NoError);

    Timeout _(10.0);
    QCOMPARE(client->sendall(QByteArray("hi")), 2);
    QScopedPointer<LocalSocket> request(server->accept());
    QVERIFY(!request.isNull());
    if (request.isNull()) {
        return;
    }
    QCOMPARE(request->recvall(2), QByteArray("hi"));
}

void TestLocalSocket::testConvertSocketLikeToLocalSocket()
{
    QSharedPointer<LocalSocket> local(new LocalSocket());
    QSharedPointer<SocketLike> like = asSocketLike(local);
    QVERIFY(!like.isNull());
    QSharedPointer<LocalSocket> back = convertSocketLikeToLocalSocket(like);
    QVERIFY(!back.isNull());
    QCOMPARE(back.data(), local.data());

    // A TCP SocketLike is not backed by a LocalSocket.
    QSharedPointer<SocketLike> tcpLike = asSocketLike(new Socket());
    QVERIFY(!tcpLike.isNull());
    QVERIFY(convertSocketLikeToLocalSocket(tcpLike).isNull());

    // A local socket has no host:port peer; connect(hostName, port) must refuse
    // instead of silently opening a pipe named after the host.
    QVERIFY(!like->connect(QString::fromLatin1("example.com"), 80));
}

void TestLocalSocket::testPeek()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("abcdef"));
        // Blocks until the server side goes away.
        client.recvall(1);
        client.close();
    }));

    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        if (request.isNull()) {
            return;
        }
        char buf[16];
        qint32 peeked = 0;
        // peek() is allowed to report "nothing yet" before the payload arrives.
        for (int i = 0; i < 500 && peeked <= 0; ++i) {
            peeked = request->peek(buf, static_cast<qint32>(sizeof(buf)));
            if (peeked <= 0) {
                Coroutine::msleep(10);
            }
        }
        QCOMPARE(peeked, 6);
        QCOMPARE(QByteArray(buf, peeked), QByteArray("abcdef"));
        // peek() must not consume the data.
        QCOMPARE(request->recvall(6), QByteArray("abcdef"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testMultipleClients()
{
    const int clientCount = 5;
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<QList<int>> connected(new QList<int>());
    CoroutineGroup clients;
    for (int i = 0; i < clientCount; ++i) {
        clients.spawn([this, i, connected] {
            LocalSocket client;
            if (!client.connect(pipeName)) {
                return;
            }
            connected->append(i);
            client.sendall(QString::fromLatin1("client-%1").arg(i).toLatin1());
            client.close();
        });
    }

    QSet<QString> received;
    int accepted = 0;
    {
        Timeout _(30.0);
        for (int i = 0; i < clientCount; ++i) {
            QScopedPointer<LocalSocket> request(server.accept());
            if (request.isNull()) {
                break;
            }
            ++accepted;
            received.insert(QString::fromLatin1(request->recvall(32)));
        }
        clients.joinall();
    }
    if (received.size() != clientCount) {
        QFAIL(qPrintable(QString::fromLatin1("accepted %1, distinct %2, connected %3, server error %4: %5")
                                 .arg(accepted)
                                 .arg(received.size())
                                 .arg(connected->size())
                                 .arg(static_cast<int>(server.error()))
                                 .arg(server.errorString())));
    }
}

void TestLocalSocket::testLocalServerTemplate()
{
    LocalServer<EchoRequestHandler> server(pipeName);
    QCOMPARE(server.serverName(), pipeName);
    QVERIFY(server.start());

    QByteArray echoed;
    {
        Timeout _(30.0);
        QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, &echoed] {
            LocalSocket client;
            if (!client.connect(pipeName)) {
                return;
            }
            client.sendall(QByteArray("ping"));
            echoed = client.recvall(4);
            client.close();
        }));
        QVERIFY(clientCoroutine->join());
        server.stop();
        QVERIFY(server.wait());
    }
    QCOMPARE(echoed, QByteArray("ping"));
}

void TestLocalSocket::testLocalServerRefuseStaleFile()
{
#ifdef Q_OS_WIN
    QSKIP("stale socket files are a Unix concept");
#else
    const QString path = QDir::temp().absoluteFilePath(pipeName + QString::fromLatin1(".sock"));
    QVERIFY(createStaleSocketFile(path));
    QVERIFY(QFile::exists(path));

    // allowReuseAddress false must keep the leftover and refuse the name.
    LocalServer<EchoRequestHandler> exclusive(pipeName);
    exclusive.setAllowReuseAddress(false);
    QVERIFY(!exclusive.start());
    QVERIFY(QFile::exists(path));

    // The default still reclaims that same file and serves the name.
    LocalServer<EchoRequestHandler> reclaiming(pipeName);
    QVERIFY(reclaiming.start());
    reclaiming.stop();
    QVERIFY(reclaiming.wait());
    QVERIFY(!QFile::exists(path));
#endif
}

void TestLocalSocket::testCloseWhileAccepting()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    bool accepted = true;
    QSharedPointer<Coroutine> acceptor(Coroutine::spawn([&server, &accepted] {
        LocalSocket *request = server.accept();
        accepted = request != nullptr;
        delete request;
    }));
    Coroutine::msleep(100);
    server.close();
    // close() wakes the coroutine parked in accept() and waits for it to leave
    // before returning, so accept() has already given up here - the listening
    // instance is not torn down under it.
    QVERIFY(!accepted);
    {
        Timeout _(10.0);
        QVERIFY(acceptor->join());
    }
    // accept() must give up once the socket is closed instead of hanging.
    QVERIFY(!accepted);
    server.close();  // closing again has no waiter left to release
}

void TestLocalSocket::testReuseNameAfterCloseWhileAccepting()
{
    // Restarting a server on the same name must not let the coroutine that was
    // parked in the old accept() grab a connection that belongs to the new life.
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    bool staleAccepted = true;
    QSharedPointer<Coroutine> stale(Coroutine::spawn([&server, &staleAccepted] {
        LocalSocket *request = server.accept();
        staleAccepted = request != nullptr;
        delete request;
    }));
    Coroutine::msleep(50);
    server.close();
    {
        Timeout _(10.0);
        QVERIFY(stale->join());
    }
    QVERIFY(!staleAccepted);

    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));
    QSharedPointer<Coroutine> client(Coroutine::spawn([this] {
        LocalSocket c;
        if (!c.connect(pipeName)) {
            return;
        }
        c.sendall(QByteArray("again"));
        c.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(5), QByteArray("again"));
    }
    client->join();
    server.close();
}

void TestLocalSocket::testCloseRacesAcceptHandoff()
{
    // Stress the accept()/close() handoff window. The old Windows path called
    // DisconnectNamedPipe before accept() claimed fd, so accept() could return a
    // non-null socket whose server end was already gone — the next read/write
    // saw a broken pipe. The contract now is binary: accept() returns nullptr,
    // or the handed-over connection still carries bytes end to end.
    const int rounds = 80;
    int handedOff = 0;
    int gaveUp = 0;

    for (int round = 0; round < rounds; ++round) {
        // Fresh name every round so a busy leftover cannot poison the next try.
        const QString name = shortSocketName(QString::fromLatin1("qtng-race-"));
        LocalSocket server;
        QVERIFY(server.bind(name));
        QVERIFY(server.listen(10));

        const QByteArray payload = QByteArray("race");
        QSharedPointer<Event> connected(new Event());
        QSharedPointer<bool> clientOk(new bool(false));

        QSharedPointer<Coroutine> client(Coroutine::spawn([name, connected, payload, clientOk] {
            LocalSocket c;
            if (!c.connect(name)) {
                return;
            }
            connected->set();
            if (c.sendall(payload) != payload.size()) {
                return;
            }
            // Keep the client end alive so a successful server handoff can echo.
            const QByteArray reply = c.recvall(payload.size());
            *clientOk = (reply == payload);
            c.close();
        }));

        // -1 = broken handoff (the bug), 0 = accept gave up, 1 = usable connection.
        QSharedPointer<int> acceptOutcome(new int(0));
        QSharedPointer<Coroutine> acceptor(Coroutine::spawn([&server, payload, acceptOutcome] {
            LocalSocket *request = server.accept();
            if (request == nullptr) {
                *acceptOutcome = 0;
                return;
            }
            QScopedPointer<LocalSocket> req(request);
            const QByteArray got = req->recvall(payload.size());
            if (got != payload) {
                *acceptOutcome = -1;
                return;
            }
            if (req->sendall(payload) != payload.size()) {
                *acceptOutcome = -1;
                return;
            }
            *acceptOutcome = 1;
        }));

        // Close as soon as the client owns a pipe, with a tiny varying delay so
        // the closer sweeps across the handoff window instead of always missing it.
        {
            Timeout _(5.0);
            QVERIFY(connected->tryWait());
        }
        Coroutine::msleep(round % 3);
        server.close();

        {
            Timeout _(10.0);
            QVERIFY(acceptor->join());
            QVERIFY(client->join());
        }

        QVERIFY2(*acceptOutcome >= 0,
                 qPrintable(QString::fromLatin1(
                                    "round %1: accept returned a connection that could not carry I/O")
                                    .arg(round)));
        if (*acceptOutcome == 1) {
            ++handedOff;
            QVERIFY2(*clientOk,
                     qPrintable(QString::fromLatin1(
                                        "round %1: server handoff worked but client echo failed")
                                        .arg(round)));
        } else {
            ++gaveUp;
        }
    }

    QCOMPARE(handedOff + gaveUp, rounds);
    // At least some rounds should win the handoff; otherwise we only tested
    // "close before accept" and never the path that used to be wrong.
    QVERIFY2(handedOff > 0,
             qPrintable(QString::fromLatin1(
                                "close always beat accept (%1 rounds); handoff path not exercised")
                                .arg(rounds)));
}

void TestLocalSocket::testWrongStateBindListenReportsError()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QCOMPARE(server.error(), Socket::NoError);

    // Already bound: callers must see an error, not a silent false. listen()
    // must still succeed afterwards — the sticky error reports the misuse, it
    // must not poison an otherwise valid Bound socket.
    QVERIFY(!server.bind(pipeName + QString::fromLatin1("-other")));
    QCOMPARE(server.error(), Socket::UnsupportedSocketOperationError);
    QCOMPARE(server.state(), Socket::BoundState);

    QVERIFY(server.listen(10));
    QCOMPARE(server.state(), Socket::ListeningState);
    QCOMPARE(server.error(), Socket::NoError);

    QVERIFY(!server.listen(10));
    QCOMPARE(server.error(), Socket::UnsupportedSocketOperationError);
    QCOMPARE(server.state(), Socket::ListeningState);

    QVERIFY(!server.bind(pipeName + QString::fromLatin1("-again")));
    QCOMPARE(server.error(), Socket::UnsupportedSocketOperationError);

    QSharedPointer<Coroutine> client(Coroutine::spawn([this] {
        LocalSocket c;
        if (!c.connect(pipeName)) {
            return;
        }
        c.sendall(QByteArray("x"));
        c.close();
    }));
    QScopedPointer<LocalSocket> accepted;
    {
        Timeout _(5.0);
        accepted.reset(server.accept());
    }
    QVERIFY(!accepted.isNull());
    QCOMPARE(accepted->recvall(1), QByteArray("x"));
    // Already connected: connect() again must report the bad state.
    QVERIFY(!accepted->connect(pipeName + QString::fromLatin1("-nope")));
    QCOMPARE(accepted->error(), Socket::UnsupportedSocketOperationError);
    client->join();
    accepted->close();
    server.close();
}

void TestLocalSocket::testConnectToMissingServer()
{
    const QString missing = pipeName + QString::fromLatin1("-missing");
    LocalSocket client;
    QElapsedTimer timer;
    timer.start();
    QVERIFY(!client.connect(missing));
    // A name nobody serves must be refused at once, not after a retry storm.
    QVERIFY(timer.elapsed() < 3000);
    QVERIFY(client.error() == Socket::SocketAddressNotAvailableError
            || client.error() == Socket::ConnectionRefusedError);
    QCOMPARE(client.state(), Socket::UnconnectedState);
    QVERIFY(!client.isValid());

    Socket::SocketError error = Socket::NoError;
    QScopedPointer<LocalSocket> connection(LocalSocket::createConnection(missing, &error));
    QVERIFY(connection.isNull());
    QVERIFY(error != Socket::NoError);
}

void TestLocalSocket::testServerCloseReleasesName()
{
    LocalSocket first;
    QVERIFY(first.bind(pipeName));
    QVERIFY(first.listen(10));
    first.close();
    QCOMPARE(first.state(), Socket::UnconnectedState);
    QVERIFY(!first.isValid());

    // The name has to be reusable right away, otherwise a restarted server
    // can never come back on the same name.
    LocalSocket second;
    QVERIFY(second.bind(pipeName));
    QVERIFY(second.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("again"));
        client.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(second.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(5), QByteArray("again"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testSequentialConnections()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    // One listening socket must survive many connect/serve/close cycles; the
    // Windows implementation rebuilds its listening instance after each accept.
    for (int i = 0; i < 3; ++i) {
        const QByteArray message = QString::fromLatin1("round-%1").arg(i).toLatin1();
        QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, message] {
            LocalSocket client;
            if (!client.connect(pipeName)) {
                return;
            }
            client.sendall(message);
            client.close();
        }));
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(message.size()), message);
        clientCoroutine->join();
    }
}

void TestLocalSocket::testManySmallMessages()
{
    const int count = 200;
    const QByteArray chunk = QByteArray("0123456789abcde");
    QByteArray expected;
    for (int i = 0; i < count; ++i) {
        expected.append(chunk);
    }

    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, chunk, count] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        for (int i = 0; i < count; ++i) {
            client.sendall(chunk);
            if (i % 20 == 0) {
                Coroutine::msleep(1);
            }
        }
        client.close();
    }));
    {
        Timeout _(20.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        const QByteArray received = request->recvall(expected.size());
        QCOMPARE(received.size(), expected.size());
        QCOMPARE(received, expected);
    }
    clientCoroutine->join();
}

void TestLocalSocket::testPingPong()
{
    const int rounds = 50;
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, rounds] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        for (int i = 0; i < rounds; ++i) {
            const QByteArray request = QString::fromLatin1("req-%1").arg(i).toLatin1();
            if (client.sendall(request) != request.size()) {
                return;
            }
            if (client.recvall(request.size()) != request) {
                return;
            }
        }
        client.close();
    }));
    {
        Timeout _(20.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        for (int i = 0; i < rounds; ++i) {
            const QByteArray expected = QString::fromLatin1("req-%1").arg(i).toLatin1();
            const QByteArray received = request->recvall(expected.size());
            QCOMPARE(received, expected);
            QCOMPARE(request->sendall(received), received.size());
        }
    }
    clientCoroutine->join();
}

void TestLocalSocket::testShortRead()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("0123456789"));
        client.close();
    }));
    QByteArray received;
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        char buf[16];
        // recv() may return less than asked for; the rest must stay readable.
        const qint32 n = request->recv(buf, static_cast<qint32>(sizeof(buf)));
        QVERIFY(n > 0);
        QVERIFY(n <= 10);
        received.append(buf, n);
        if (received.size() < 10) {
            received.append(request->recvall(10 - received.size()));
        }
    }
    clientCoroutine->join();
    QCOMPARE(received, QByteArray("0123456789"));
}

void TestLocalSocket::testAbortWakesBlockedRecv()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.recvall(1);  // parks until the server side goes away
        client.close();
    }));

    QScopedPointer<LocalSocket> request;
    {
        Timeout _(10.0);
        request.reset(server.accept());
    }
    QVERIFY(!request.isNull());
    if (request.isNull()) {
        return;
    }

    // Close the connection from another coroutine while this one is parked in
    // recv(); the parked coroutine must be woken up instead of hanging forever.
    QSharedPointer<Coroutine> killer(Coroutine::spawn([&request] {
        Coroutine::msleep(100);
        request->close();
    }));
    char buf[16];
    qint32 n = 1;
    {
        Timeout _(10.0);
        n = request->recv(buf, static_cast<qint32>(sizeof(buf)));
    }
    killer->join();
    clientCoroutine->join();
    QVERIFY(n <= 0);
    QVERIFY(!request->isValid());
}

void TestLocalSocket::testOperationsAfterClose()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("x"));
        client.close();
    }));
    QScopedPointer<LocalSocket> request;
    {
        Timeout _(10.0);
        request.reset(server.accept());
    }
    QVERIFY(!request.isNull());
    clientCoroutine->join();
    request->close();

    char buf[16];
    QVERIFY(!request->isValid());
    QCOMPARE(request->state(), Socket::UnconnectedState);
    QCOMPARE(request->recv(buf, static_cast<qint32>(sizeof(buf))), -1);
    QCOMPARE(request->recvall(1), QByteArray());
    QCOMPARE(request->send("x", 1), -1);
    QCOMPARE(request->peek(buf, static_cast<qint32>(sizeof(buf))), -1);
    // Closing twice must stay harmless.
    request->close();
    QVERIFY(!request->isValid());
}

void TestLocalSocket::testZeroSizedTransfers()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.recvall(1);
        client.close();
    }));
    QScopedPointer<LocalSocket> request;
    {
        Timeout _(10.0);
        request.reset(server.accept());
    }
    QVERIFY(!request.isNull());

    // A zero-sized transfer is refused instead of being reported as a success,
    // so a caller cannot mistake it for "nothing to do, everything sent".
    char buf[4];
    QCOMPARE(request->sendall(QByteArray()), -1);
    QCOMPARE(request->recv(buf, 0), -1);
    QCOMPARE(request->peek(buf, 0), -1);
    request->close();
    clientCoroutine->join();
}

void TestLocalSocket::testUnicodeServerName()
{
    // qtng-<本地套接字>-<short id>, spelled with code points so that the test
    // does not depend on the encoding of this source file. The name has to stay
    // short: each of the five ideographs takes three bytes in UTF-8.
    const ushort nameChars[] = {0x672C, 0x5730, 0x5957, 0x63A5, 0x5B57, 0x002D};
    const QString name = shortSocketName(QString::fromLatin1("qtng-") + QString::fromUtf16(nameChars, 6), 8);

    LocalSocket server;
    QVERIFY(server.bind(name));
    QVERIFY(server.listen(10));
    QCOMPARE(server.serverName(), name);

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([name] {
        LocalSocket client;
        if (!client.connect(name)) {
            return;
        }
        client.sendall(QByteArray("unicode"));
        client.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(7), QByteArray("unicode"));
    }
    clientCoroutine->join();
    server.close();
}

void TestLocalSocket::testOverlongServerName()
{
    // Longer than sockaddr_un::sun_path on Unix and than the pipe name limit
    // on Windows; the point is that it fails cleanly either way.
    const QString name = QString::fromLatin1("qtng-overlong-") + QString(300, QLatin1Char('x'));
    LocalSocket server;
    if (!server.bind(name)) {
        QVERIFY(server.error() != Socket::NoError);
        QCOMPARE(server.state(), Socket::UnconnectedState);
        return;
    }
    // If the platform does accept it, the name must work end to end.
    QVERIFY(server.listen(10));
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([name] {
        LocalSocket client;
        if (!client.connect(name)) {
            return;
        }
        client.sendall(QByteArray("long"));
        client.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(4), QByteArray("long"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testTwoServersInterleaved()
{
    const QString nameA = pipeName + QString::fromLatin1("-a");
    const QString nameB = pipeName + QString::fromLatin1("-b");
    LocalSocket serverA;
    LocalSocket serverB;
    QVERIFY(serverA.bind(nameA));
    QVERIFY(serverA.listen(10));
    QVERIFY(serverB.bind(nameB));
    QVERIFY(serverB.listen(10));

    QSharedPointer<Coroutine> clientA(Coroutine::spawn([nameA] {
        LocalSocket client;
        if (!client.connect(nameA)) {
            return;
        }
        client.sendall(QByteArray("aaa"));
        client.close();
    }));
    QSharedPointer<Coroutine> clientB(Coroutine::spawn([nameB] {
        LocalSocket client;
        if (!client.connect(nameB)) {
            return;
        }
        client.sendall(QByteArray("bbb"));
        client.close();
    }));
    {
        Timeout _(10.0);
        // Serve B first: accepting on one server must not disturb the other,
        // and a client that arrived while we were busy elsewhere must still be
        // served.
        QScopedPointer<LocalSocket> requestB(serverB.accept());
        QVERIFY(!requestB.isNull());
        QCOMPARE(requestB->recvall(3), QByteArray("bbb"));
        QScopedPointer<LocalSocket> requestA(serverA.accept());
        QVERIFY(!requestA.isNull());
        QCOMPARE(requestA->recvall(3), QByteArray("aaa"));
    }
    clientA->join();
    clientB->join();
}

void TestLocalSocket::testEarlyClientIsNotLost()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    // A client that connects - and hangs up - before the server ever reaches
    // accept() must not be thrown away together with its request. On Unix it
    // waits in the accept queue; Windows used to drop it on ERROR_NO_DATA and
    // then wait for a client that was never going to come again.
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("early"));
        client.close();
    }));
    clientCoroutine->join();

    QByteArray received;
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        received = request->recvall(5);
    }
    QCOMPARE(received, QByteArray("early"));
}

void TestLocalSocket::testAcceptedConnectionSurvivesServerClose()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    QSharedPointer<QByteArray> echoed(new QByteArray());
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this, echoed] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("hello"));
        *echoed = client.recvall(3);
        client.close();
    }));

    QScopedPointer<LocalSocket> request;
    {
        Timeout _(10.0);
        request.reset(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(5), QByteArray("hello"));
    }

    // Dropping the listener must not disturb the already accepted connection.
    server.close();
    QVERIFY(!server.isValid());

    {
        Timeout _(10.0);
        QCOMPARE(request->sendall(QByteArray("bye")), 3);
    }
    clientCoroutine->join();
    QCOMPARE(*echoed, QByteArray("bye"));
    request->close();

    // With the listener and the accepted connection gone the name is free
    // again, so nothing can connect to it any more.
    LocalSocket late;
    QVERIFY(!late.connect(pipeName));
}

void TestLocalSocket::testAbortedClientsDoNotBlockServer()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    // A client that connects and hangs up at once used to leave the Windows
    // listening instance stuck on ERROR_NO_DATA, after which nobody served the
    // pipe name anymore. They are served one at a time: the server only has a
    // single listening instance until it accepts and builds the next one.
    for (int i = 0; i < 3; ++i) {
        QSharedPointer<Coroutine> rude(Coroutine::spawn([this] {
            LocalSocket client;
            if (!client.connect(pipeName)) {
                return;
            }
            client.close();
        }));
        rude->join();
        QScopedPointer<LocalSocket> request;
        {
            Timeout _(10.0);
            request.reset(server.accept());
        }
        QVERIFY(!request.isNull());
        if (request.isNull()) {
            return;
        }
        // The client is already gone, so reading must report EOF instead of
        // hanging or handing us stale bytes.
        QVERIFY(request->recv(64).isEmpty());
    }

    // The server still works after all that.
    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("good"));
        client.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server.accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(4), QByteArray("good"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testLocalServerServesSeveralRequests()
{
    LocalServer<EchoRequestHandler> server(pipeName);
    QVERIFY(server.start());

    QSharedPointer<QList<QByteArray>> results(new QList<QByteArray>());
    {
        Timeout _(30.0);
        for (int i = 0; i < 3; ++i) {
            const QByteArray request = QString::fromLatin1("req%1").arg(i).toLatin1();
            QSharedPointer<Coroutine> client(Coroutine::spawn([this, request, results] {
                LocalSocket client;
                if (!client.connect(pipeName)) {
                    return;
                }
                client.sendall(request);
                results->append(client.recvall(request.size()));
                client.close();
            }));
            client->join();
        }
        // serveForever() has to give up once the listening socket is closed.
        server.stop();
        QVERIFY(server.wait());
    }
    QCOMPARE(results->size(), 3);
    for (int i = 0; i < results->size(); ++i) {
        QCOMPARE(results->at(i), QString::fromLatin1("req%1").arg(i).toLatin1());
    }
}

void TestLocalSocket::testCreateServerWithoutListen()
{
    QScopedPointer<LocalSocket> server(LocalSocket::createServer(pipeName, 0));
    QVERIFY(!server.isNull());
    if (server.isNull()) {
        return;
    }
    // backlog == 0 binds only; nothing is being served yet.
    QCOMPARE(server->state(), Socket::BoundState);
    QVERIFY(server->accept() == nullptr);

    QVERIFY(server->listen(5));
    QCOMPARE(server->state(), Socket::ListeningState);

    QSharedPointer<Coroutine> clientCoroutine(Coroutine::spawn([this] {
        LocalSocket client;
        if (!client.connect(pipeName)) {
            return;
        }
        client.sendall(QByteArray("later"));
        client.close();
    }));
    {
        Timeout _(10.0);
        QScopedPointer<LocalSocket> request(server->accept());
        QVERIFY(!request.isNull());
        QCOMPARE(request->recvall(5), QByteArray("later"));
    }
    clientCoroutine->join();
}

void TestLocalSocket::testInvalidFileDescriptor()
{
    LocalSocket socket(static_cast<qintptr>(-1));
    QVERIFY(!socket.isValid());
    QCOMPARE(socket.error(), Socket::UnsupportedSocketOperationError);
    QCOMPARE(socket.state(), Socket::UnconnectedState);
    char buf[4];
    QCOMPARE(socket.recv(buf, static_cast<qint32>(sizeof(buf))), -1);
    QCOMPARE(socket.send("x", 1), -1);
    QVERIFY(socket.accept() == nullptr);
    socket.close();  // must not crash
}

void TestLocalSocket::testNameAndUriAccessors()
{
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QCOMPARE(server.serverName(), pipeName);
    QVERIFY(server.fullServerName().contains(pipeName));
#ifdef Q_OS_WIN
    QVERIFY(server.fullServerName().startsWith(QString::fromLatin1("\\\\.\\pipe\\")));
    QVERIFY(server.localAddressURI().startsWith(QString::fromLatin1("pipe://")));
#else
    QVERIFY(server.fullServerName().endsWith(QString::fromLatin1(".sock")));
    QVERIFY(server.localAddressURI().startsWith(QString::fromLatin1("unix://")));
#endif
    QCOMPARE(server.peerAddressURI(), server.localAddressURI());
    QCOMPARE(server.type(), Socket::LocalSocket);
    QVERIFY(server.protocol() == HostAddress::UnknownNetworkLayerProtocol);
    QVERIFY(server.localAddress().isNull());
    QVERIFY(server.peerAddress().isNull());
    QCOMPARE(server.localPort(), static_cast<quint16>(0));
    QCOMPARE(server.peerPort(), static_cast<quint16>(0));
    QVERIFY(server.fileno() > 0);
    QVERIFY(server.isValid());
    // Options are not supported for local sockets, but must fail cleanly.
    QVERIFY(!server.setOption(Socket::AddressReusable, true));
    QVERIFY(!server.option(Socket::AddressReusable).isValid());
    QVERIFY(server.peerName() == pipeName);
}

void TestLocalSocket::testBindThenConnectMustNotUnlinkPeer()
{
#ifdef Q_OS_WIN
    QSKIP("AF_UNIX socket files exist only on Unix.");
#else
    // A client may bind its own name and then connect. close() unlinks the
    // name this socket bound, and leaves the peer's socket file in place.
    const QString clientName = shortSocketName(QString::fromLatin1("qtng-self-"));
    const QString serverPath = QDir::temp().absoluteFilePath(pipeName + QString::fromLatin1(".sock"));
    const QString clientPath = QDir::temp().absoluteFilePath(clientName + QString::fromLatin1(".sock"));
    RemoveFileLater clientFile;
    clientFile.path = clientPath;

    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));
    QVERIFY(QFile::exists(serverPath));

    LocalSocket client;
    QVERIFY(client.bind(clientName));
    QVERIFY(QFile::exists(clientPath));
    QVERIFY(client.connect(pipeName));
    client.close();

    QVERIFY2(QFile::exists(serverPath),
             qPrintable(QString::fromLatin1("peer socket file was removed: %1").arg(serverPath)));
    QVERIFY2(!QFile::exists(clientPath),
             qPrintable(QString::fromLatin1("local socket file is still there: %1").arg(clientPath)));

    server.close();
#endif
}

void TestLocalSocket::testSendAfterPeerCloseMustNotRaiseSigPipe()
{
#ifdef Q_OS_WIN
    QSKIP("SIGPIPE is a Unix-only failure mode.");
#else
    // Writing after the peer has closed reports the error and does not raise
    // SIGPIPE. The probe handler would record the signal instead of killing
    // the process, so a delivered signal fails the test.
    RestoreSigPipe probe;
    QVERIFY(probe.installed);

    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(10));

    LocalSocket client;
    QVERIFY(client.connect(pipeName));
    QScopedPointer<LocalSocket> accepted(server.accept());
    QVERIFY(!accepted.isNull());
    accepted->close();
    accepted.reset();

    localSocketSigPipeRaised = 0;
    qint32 n = client.send("hello", 5);
    if (n > 0) {
        // A first write can still land in the kernel buffer. The follow-up
        // write is the one that observes the closed peer.
        n = client.send("hello", 5);
    }
    QVERIFY2(localSocketSigPipeRaised == 0, "send() raised SIGPIPE");
    // EPIPE is reported as a short write (0 when nothing went out) plus
    // RemoteHostClosedError.
    QVERIFY2(n <= 0, "send() still succeeded after the peer closed");
    QCOMPARE(client.error(), Socket::RemoteHostClosedError);

    client.close();
    server.close();
#endif
}

void TestLocalSocket::testBindThenConnectMustReleaseLocalName()
{
#ifndef Q_OS_WIN
    QSKIP("Named-pipe instance ownership is a Windows-only failure mode.");
#else
    // bind() then connect() must drop the pipe instance created for the local
    // name, so that name can be bound again after the socket is destroyed.
    const QString localName = shortSocketName(QString::fromLatin1("qtng-bound-"));
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(1));

    {
        LocalSocket client;
        QVERIFY(client.bind(localName));
        QVERIFY(client.connect(pipeName));
        QCOMPARE(client.state(), Socket::ConnectedState);
    }

    LocalSocket again;
    QVERIFY2(again.bind(localName),
             qPrintable(QString::fromLatin1("rebinding %1 failed with %2 (%3)")
                                .arg(localName)
                                .arg(static_cast<int>(again.error()))
                                .arg(again.errorString())));
    again.close();
    server.close();
#endif
}

void TestLocalSocket::testCloseDuringBusyConnectReturnsPromptly()
{
#ifndef Q_OS_WIN
    QSKIP("The PIPE_BUSY connect retry loop is Windows-only.");
#else
    // One listening instance is already taken and accept() is never called, so
    // a second connect() sees a busy pipe and retries. close() must stop that
    // attempt and return without waiting out the retry budget.
    LocalSocket server;
    QVERIFY(server.bind(pipeName));
    QVERIFY(server.listen(1));

    LocalSocket holder;
    QVERIFY(holder.connect(pipeName));

    LocalSocket busy;
    QSharedPointer<bool> connected(new bool(true));
    QSharedPointer<Coroutine> connecting(Coroutine::spawn([this, &busy, connected] {
        *connected = busy.connect(pipeName);
    }));
    Coroutine::msleep(100);

    QElapsedTimer closeTimer;
    closeTimer.start();
    busy.close();
    const qint64 closeMs = closeTimer.elapsed();
    QVERIFY(connecting->join());

    QVERIFY2(closeMs < 1000,
             qPrintable(QString::fromLatin1("close() during a busy connect blocked for %1 ms").arg(closeMs)));
    QVERIFY2(!*connected, "connect() succeeded even though close() had already been requested");
    QCOMPARE(busy.state(), Socket::UnconnectedState);

    holder.close();
    server.close();
#endif
}

QTEST_MAIN(TestLocalSocket)
#include "test_local_socket.moc"
