#include <QtCore/qcoreapplication.h>
#include <QtCore/qcommandlineparser.h>

#include "qtnetworkng.h"

using namespace qtng;

enum ParserResult
{
    Success, Failed,
    Help, Version,
};

struct Configure
{
    QString password;
    QHostAddress localAddress;
    QString targetAddress;
    quint16 localPort;
    quint16 targetPort;
};


class KcptunServer
{
public:
    KcptunServer(const Configure& configure)
        :configure(configure), operations(new CoroutineGroup) {}
    ~KcptunServer() { delete operations; }
public:
    bool start();
private:
    void handleRequest(QSharedPointer<KcpSocket> request);
private:
    Configure configure;
    CoroutineGroup *operations;
};


bool KcptunServer::start()
{
    KcpSocket s;
    if (!s.bind(configure.localAddress, configure.localPort, Socket::ReuseAddressHint)) {
        return false;
    }
    s.listen(50);
    while (true) {
        QSharedPointer<KcpSocket> r(s.accept());
        if (r.isNull()) {
            return true;
        }
        operations->spawn([this, r] {
            handleRequest(r);
        });
    }
}


void KcptunServer::handleRequest(QSharedPointer<KcpSocket> request)
{
    QSharedPointer<Socket> forward(Socket::createConnection(configure.targetAddress, configure.targetPort));
    if (forward.isNull()) {
        QString errorMessage = QCoreApplication::translate("main", "can not connect to target %1:%2");
        printf("%s", qPrintable(errorMessage.arg(configure.targetAddress).arg(configure.targetPort)));
        request->close();
        return;
    }

    QSharedPointer<Cipher> cipher(new Cipher(Cipher::AES256, Cipher::CFB, Cipher::Encrypt));
    cipher->setPassword(configure.password.toUtf8(), "3.1415926535");
    QSharedPointer<SocketLike> encryptedRequest = encrypted(cipher, asSocketLike(request));

    Exchanger exchanger(encryptedRequest, asSocketLike(forward));
    exchanger.exchange();
}


ParserResult parseArguments(Configure *configure, QString *errorMessage)
{
    QCommandLineParser parser;
    parser.setApplicationDescription("kcptun server");
    const QCommandLineOption &helpOption = parser.addHelpOption();
    const QCommandLineOption &versionOption = parser.addVersionOption();

    QCommandLineOption passwordOption(QStringList() << "k" << "password",
                                      QCoreApplication::translate("main", "the password to encrypt the connection. default to `it is a secret`."),
                                      "password");
    parser.addOption(passwordOption);
    QCommandLineOption localAddressOption(QStringList() << "b" << "local-address",
                                          QCoreApplication::translate("main", "local address to listen, default to `0.0.0.0`."),
                                          "local_address");
    parser.addOption(localAddressOption);
    QCommandLineOption localPortOption(QStringList() << "l" << "local-port",
                                       QCoreApplication::translate("main", "local port to listen, default to `8000`."),
                                       "local_port");
    parser.addOption(localPortOption);
    QCommandLineOption targetAddressOption(QStringList() << "r" << "target-address",
                                           QCoreApplication::translate("main", "target host to forward. default to `127.0.0.1`."),
                                           "target_address");
    parser.addOption(targetAddressOption);
    QCommandLineOption targetPortOption(QStringList() << "p" << "target-port",
                                        QCoreApplication::translate("main", "target port to forward. default to `22`."),
                                        "target_port");
    parser.addOption(targetPortOption);


    if (!parser.parse(QCoreApplication::arguments())) {
        *errorMessage = parser.errorText();
        return Failed;
    }

    if (parser.isSet(helpOption)) {
        *errorMessage = parser.helpText();
        return Help;
    }

    if (parser.isSet(versionOption)) {
        *errorMessage = QStringLiteral("%1 %2").arg(QCoreApplication::applicationName()).arg(QCoreApplication::applicationVersion());
        return Version;
    }

    configure->password = parser.value(passwordOption);
    if (configure->password.isEmpty()) {
        configure->password = QStringLiteral("it is a secret");
    }

    QString localAddressStr = parser.value(localAddressOption);
    if (localAddressStr.isEmpty()) {
        configure->localAddress.setAddress(QHostAddress::Any);
    } else {
        configure->localAddress.setAddress(localAddressStr);
        if (configure->localAddress.isNull()) {
            *errorMessage = QCoreApplication::translate("main", "the local address is not valid.");
            return Failed;
        }
    }

    QString localPortStr = parser.value(localPortOption);
    if (localPortStr.isEmpty()) {
        configure->localPort = 8000;
    } else {
        bool ok;
        configure->localPort = localPortStr.toUShort(&ok);
        if (!ok) {
            *errorMessage = QCoreApplication::translate("main", "specify the local port.");
            return Failed;
        }
    }

    QString targetAddressStr = parser.value(targetAddressOption);
    if (targetAddressStr.isEmpty()) {
        configure->targetAddress = "127.0.0.1";
    } else {
        configure->targetAddress = targetAddressStr;
    }

    QString targetPortStr = parser.value(targetPortOption);
    if (targetPortStr.isEmpty()) {
        configure->targetPort = 22;
    } else {
        bool ok;
        configure->targetPort = targetPortStr.toUShort(&ok);
        if (!ok) {
            *errorMessage = QCoreApplication::translate("main", "the target port %1 is not valid.").arg(targetPortStr);
            return Failed;
        }
    }

    return Success;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("kcptun-server");
    app.setApplicationVersion("1.0");

    Configure configure;
    QString errorMessage;
    if (parseArguments(&configure, &errorMessage) != Success) {
        printf("%s\n", qPrintable(errorMessage));
        return 1;
    }
    QSharedPointer<KcptunServer> server(new KcptunServer(configure));
    if (!server->start()) {
        errorMessage = QCoreApplication::translate("main", "can not start server. there may be some application use the local port: %1").arg(configure.localPort);
        printf("%s\n", qPrintable(errorMessage));
        return 2;
    }
    return startQtLoop();
}
