#include <QtCore/qdebug.h>
#include <QtCore/qatomic.h>
#include <QtCore/qfile.h>
#include <QtCore/qsharedpointer.h>
extern "C" {
#include <openssl/ssl.h>
}
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
    if (lib()->inited.fetchAndAddAcquire(1) > 0) {
        return;
    }
    OPENSSL_add_all_algorithms_noconf();
    SSL_library_init();
    SSL_load_error_strings();
}


void cleanupOpenSSL()
{
    if (lib()->inited.fetchAndSubAcquire(1) > 0) {
        return;
    }
    ERR_remove_state(0);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}

QTNETWORKNG_NAMESPACE_END


