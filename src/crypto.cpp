#include <QtCore/qdebug.h>
#include <QtCore/qatomic.h>
#include <QtCore/qfile.h>
#include <QtCore/qsharedpointer.h>
#include "../include/crypto.h"
#include "../include/private/openssl_symbols.h"

QTNETWORKNG_NAMESPACE_BEGIN

struct OpenSSLLib {
    OpenSSLLib() :version(0) {}
    QAtomicInt inited;
    int version;
};

Q_GLOBAL_STATIC(struct OpenSSLLib, lib)


void initOpenSSL()
{
    if(lib()->inited.fetchAndAddAcquire(1) > 0) {
        return;
    }
    openssl::q_resolveOpenSslSymbols(false);
    // TODO support openssl 1.1
    // TODO get openssl version.
    openssl::q_OPENSSL_add_all_algorithms_conf();
    openssl::q_SSL_library_init();
    openssl::q_SSL_load_error_strings();
}

void cleanupOpenSSL()
{

}


QTNETWORKNG_NAMESPACE_END


