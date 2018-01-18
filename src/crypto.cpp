#include <QtCore/qdebug.h>
#include <QtCore/qatomic.h>
#include <QtCore/qfile.h>
#include <QtCore/qsharedpointer.h>
#include "../include/crypto.h"
#include "../include/openssl_symbols.h"

QTNETWORKNG_NAMESPACE_BEGIN

static struct OpenSSLLib {
    bool inited;
    int version;
} lib;


void initOpenSSL()
{
    static QAtomicInt inited;
    if(inited.fetchAndAddAcquire(1) > 0) {
        return;
    }
    lib.inited = true;
    openssl::q_resolveOpenSslSymbols(false);
    // TODO support openssl 1.1
    // TODO get openssl version.
    openssl::q_OPENSSL_add_all_algorithms_conf();
    openssl::q_SSL_library_init();
    openssl::q_SSL_load_error_strings();
}

QTNETWORKNG_NAMESPACE_END


