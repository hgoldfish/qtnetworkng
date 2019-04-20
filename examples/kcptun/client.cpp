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
    QString remoteAddress;
    quint16 localPort;
    quint16 remotePort;
};


class KcptunClient
{
public:
    KcptunClient(const Configure& configure)
        :configure(configure), operations(new CoroutineGroup) {}
    ~KcptunClient() { delete operations; }
public:
    bool start();
private:
    void handleRequest(QSharedPointer<Socket> request);
private:
    Configure configure;
    CoroutineGroup *operations;
};


bool KcptunClient::start()
{
    Socket s;
    if (!s.bind(configure.localAddress, configure.localPort, Socket::ReuseAddressHint)) {
        return false;
    }
    s.listen(50);
    while (true) {
        QSharedPointer<Socket> r(s.accept());
        if (r.isNull()) {
            return true;
        }
        operations->spawn([this, r] {
            handleRequest(r);
        });
    }
}


void KcptunClient::handleRequest(QSharedPointer<Socket> request)
{
    QSharedPointer<KcpSocket> forward(new KcpSocket);
    if (!forward->connect(configure.remoteAddress, configure.remotePort)) {
        QString errorMessage = QCoreApplication::translate("main", "can not connect to remote host %1:%2");
        printf("%s", qPrintable(errorMessage.arg(configure.remoteAddress).arg(configure.remotePort)));
        request->close();
        return;
    }
    Exchanger exchanger(asStream(request), asStream(forward));
    exchanger.exchange();
}


ParserResult parseArguments(Configure *configure, QString *errorMessage)
{
    QCommandLineParser parser;
    parser.setApplicationDescription("joker server");
    const QCommandLineOption &helpOption = parser.addHelpOption();
    const QCommandLineOption &versionOption = parser.addVersionOption();

    QCommandLineOption passwordOption(QStringList() << "k" << "password",
                                      QCoreApplication::translate("main", "the password to encrypt the connection. default to `it is a secret`."),
                                      "password");
    parser.addOption(passwordOption);
    QCommandLineOption localAddressOption(QStringList() << "b" << "local-address",
                                          QCoreApplication::translate("main", "local address to listen, default to `localhost`."),
                                          "local_address");
    parser.addOption(localAddressOption);
    QCommandLineOption localPortOption(QStringList() << "l" << "local-port",
                                       QCoreApplication::translate("main", "local port to listen, default to `8085`."),
                                       "local_port");
    parser.addOption(localPortOption);
    QCommandLineOption remoteAddressOption(QStringList() << "r" << "remote-address",
                                           QCoreApplication::translate("main", "remote host which runs the kcptun server."),
                                           "remote_address");
    parser.addOption(remoteAddressOption);
    QCommandLineOption remotePortOption(QStringList() << "p" << "remote-port",
                                        QCoreApplication::translate("main", "remote port which runs the kcptun server. default to `8000`."),
                                        "target_port");
    parser.addOption(remotePortOption);
    

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
        configure->localAddress.setAddress(QHostAddress::LocalHost);
    } else {
        configure->localAddress.setAddress(localAddressStr);
        if (configure->localAddress.isNull()) {
            *errorMessage = QCoreApplication::translate("main", "the local address is not valid.");
            return Failed;
        }
    }

    QString localPortStr = parser.value(localPortOption);
    if (localPortStr.isEmpty()) {
        configure->localPort = 8085;
    } else {
        bool ok;
        configure->localPort = localPortStr.toUShort(&ok);
        if (!ok) {
            *errorMessage = QCoreApplication::translate("main", "the local port %1 is invalid.").arg(localPortStr);
            return Failed;
        }
    }
    
    QString remoteAddressStr = parser.value(remoteAddressOption);
    if (remoteAddressStr.isEmpty()) {
        *errorMessage = QCoreApplication::translate("main", "require remote host address.");
    } else {
        configure->remoteAddress = remoteAddressStr;
    }
    
    QString remotePortStr = parser.value(remotePortOption);
    if (remotePortStr.isEmpty()) {
        configure->remotePort = 8000;
    } else {
        bool ok;
        configure->remotePort = remotePortStr.toUShort(&ok);
        if (!ok) {
            *errorMessage = QCoreApplication::translate("main", "the target port %1 is invalid.").arg(remotePortStr);
            return Failed;
        }
    }

    return Success;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("kcptun-client");
    app.setApplicationVersion("1.0");
    
    Configure configure;
    QString errorMessage;
    if (parseArguments(&configure, &errorMessage) != Success) {
        printf("%s\n", qPrintable(errorMessage));
        return 1;
    }
    QSharedPointer<KcptunClient> client(new KcptunClient(configure));
    if (!client->start()) {
        errorMessage = QCoreApplication::translate("main", "can not start client. there may be some application use the local port: %1").arg(configure.localPort);
        printf("%s\n", qPrintable(errorMessage));
        return 2;
    }
    return startQtLoop();
}
