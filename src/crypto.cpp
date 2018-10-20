#include <QtCore/qdebug.h>
#include <QtCore/qatomic.h>
#include <QtCore/qfile.h>
#include <QtCore/qsharedpointer.h>
#include <openssl/ssl.h>
#include "../include/private/crypto_p.h"

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
    OPENSSL_add_all_algorithms_noconf();
    SSL_library_init();
    SSL_load_error_strings();
}

void cleanupOpenSSL()
{

}

QTNETWORKNG_NAMESPACE_END


