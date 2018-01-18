/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Copyright (C) 2014 BlackBerry Limited. All rights reserved.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

/****************************************************************************
**
** In addition, as a special exception, the copyright holders listed above give
** permission to link the code of its release of Qt with the OpenSSL project's
** "OpenSSL" library (or modified versions of the "OpenSSL" library that use the
** same license as the original version), and distribute the linked executables.
**
** You must comply with the GNU General Public License version 2 in all
** respects for all of the code used other than the "OpenSSL" code.  If you
** modify this file, you may extend this exception to your version of the file,
** but you are not obligated to do so.  If you do not wish to do so, delete
** this exception statement from your version of this file.
**
****************************************************************************/

#ifndef QTNG_OPENSSL_SYMBOLS_H
#define QTNG_OPENSSL_SYMBOLS_H

#include <QtCore/qglobal.h>
#include <QtCore/qdatetime.h>
#include "config.h"


namespace QTNETWORKNG_NAMESPACE {
namespace openssl {

// section begin: copy from openssl header

struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    long flags;
};
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
struct asn1_object_st {
    const char *sn, *ln;
    int nid;
    int length;
    const unsigned char *data;
    int flags;
};
struct ASN1_TYPE;
typedef struct asn1_object_st ASN1_OBJECT;

typedef struct stack_st {
    int num;
    char **data;
    int sorted;
    int num_alloc;
    int (*comp) (const void *, const void *);
} _STACK;
#define STACK struct stack_st
#define STACK_OF(type) struct stack_st

struct BIO;
struct BIO_METHOD;

struct MD4_CTX;
struct MD5_CTX;
struct SHA_CTX;
struct SHA256_CTX;
struct SHA512_CTX;

struct EVP_MD;
struct EVP_MD_CTX;
struct EVP_CIPHER;
struct EVP_CIPHER_CTX;
struct EVP_PKEY;
struct EVP_PKEY_CTX;
struct ENGINE;

struct DH;
struct RSA;
struct DSA;
struct EC_GROUP;
struct EC_KEY;
struct EC_builtin_curve;

struct X509;
struct X509_REQ;
struct X509_CRL;
struct X509_STORE;
struct X509_EXTENSION;
struct X509_NAME;
struct X509_NAME_ENTRY;
struct X509_PUBKEY;
struct X509_STORE_CTX;
struct X509V3_EXT_METHOD;
struct PKCS12;
struct PKCS7;

struct SSL;
struct SSL_CIPHER;
struct SSL_CTX;
struct SSL_METHOD;
struct SSL_SESSION;

struct BIGNUM;
struct BN_GENCB;
struct BASIC_CONSTRAINTS;
struct CRYPTO_EX_DATA;
struct AUTHORITY_KEYID;

typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);
typedef int CRYPTO_EX_new (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp);
typedef void CRYPTO_EX_free (void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                             int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from,
                           void *from_d, int idx, long argl, void *argp);
typedef void *d2i_of_void (void **,const unsigned char **,long);
typedef int i2d_of_void (void *,unsigned char **);


#if QT_POINTER_SIZE == 64
#define BN_ULONG quint64
#else
#define BN_ULONG quint32
#endif

#define OPENSSL_VERSION_NUMBER 0x10000000L
#define SHLIB_VERSION_NUMBER "1.0.0"
#define SSL_CTRL_SET_TMP_ECDH 4
#define NID_undef 0
#define EVP_PKEY_RSA 6
#define EVP_PKEY_DSA 116
#define EVP_PKEY_DH 28
#define EVP_PKEY_EC 408
#define EVP_PKEY_HMAC 855

#define V_ASN1_UTCTIME 23
#define V_ASN1_GENERALIZEDTIME 24
#define SSLEAY_VERSION 0
#define EVP_MAX_MD_SIZE 64
#define EVP_MAX_KEY_LENGTH 64
#define EVP_MAX_IV_LENGTH 16
#define EVP_MAX_BLOCK_LENGTH 32

#define PEM_STRING_X509_OLD     "X509 CERTIFICATE"
#define PEM_STRING_X509         "CERTIFICATE"
#define PEM_STRING_X509_PAIR    "CERTIFICATE PAIR"
#define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
#define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
#define PEM_STRING_X509_REQ     "CERTIFICATE REQUEST"
#define PEM_STRING_X509_CRL     "X509 CRL"
#define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
#define PEM_STRING_PUBLIC       "PUBLIC KEY"
#define PEM_STRING_RSA          "RSA PRIVATE KEY"
#define PEM_STRING_RSA_PUBLIC   "RSA PUBLIC KEY"
#define PEM_STRING_DSA          "DSA PRIVATE KEY"
#define PEM_STRING_DSA_PUBLIC   "DSA PUBLIC KEY"
#define PEM_STRING_PKCS7        "PKCS7"
#define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
#define PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
#define PEM_STRING_PKCS8INF     "PRIVATE KEY"
#define PEM_STRING_DHPARAMS     "DH PARAMETERS"
#define PEM_STRING_DHXPARAMS    "X9.42 DH PARAMETERS"
#define PEM_STRING_SSL_SESSION  "SSL SESSION PARAMETERS"
#define PEM_STRING_DSAPARAMS    "DSA PARAMETERS"
#define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
#define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
#define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
#define PEM_STRING_PARAMETERS   "PARAMETERS"
#define PEM_STRING_CMS          "CMS"

#define BIO_CTRL_INFO 3
#define BIO_CTRL_PENDING 10

#define SSL_ERROR_NONE 0
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL 5
#define SSL_ERROR_ZERO_RETURN 6
#define SSL_ERROR_WANT_CONNECT 7
#define SSL_ERROR_WANT_ACCEPT 8

// section end.


#define DUMMYARG
#ifndef QTNETWORKNG_LINKED_OPENSSL
// **************** Shared declarations ******************
// ret func(arg)

#  define DEFINEFUNC(ret, func, arg, a, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg); \
    static _q_PTR_##func _q_##func = 0; \
    ret q_##func(arg) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a); \
    }

// ret func(arg1, arg2)
#  define DEFINEFUNC2(ret, func, arg1, a, arg2, b, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2);         \
    static _q_PTR_##func _q_##func = 0;               \
    ret q_##func(arg1, arg2) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func);\
            err; \
        } \
        funcret _q_##func(a, b); \
    }

// ret func(arg1, arg2, arg3)
#  define DEFINEFUNC3(ret, func, arg1, a, arg2, b, arg3, c, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3);            \
    static _q_PTR_##func _q_##func = 0;                        \
    ret q_##func(arg1, arg2, arg3) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c); \
    }

// ret func(arg1, arg2, arg3, arg4)
#  define DEFINEFUNC4(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4);               \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4) { \
         if (Q_UNLIKELY(!_q_##func)) { \
             qsslSocketUnresolvedSymbolWarning(#func); \
             err; \
         } \
         funcret _q_##func(a, b, c, d); \
    }

// ret func(arg1, arg2, arg3, arg4, arg5)
#  define DEFINEFUNC5(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5);         \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4, arg5) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6)
#  define DEFINEFUNC6(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6);   \
    static _q_PTR_##func _q_##func = 0;                                 \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e, f); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7)
#  define DEFINEFUNC7(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7);   \
    static _q_PTR_##func _q_##func = 0;                                       \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e, f, g); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8)
#  define DEFINEFUNC8(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);   \
    static _q_PTR_##func _q_##func = 0;                                       \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        } \
        funcret _q_##func(a, b, c, d, e, f, g, h); \
    }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8, arg9)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, arg9, i, err, funcret) \
    typedef ret (*_q_PTR_##func)(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);   \
    static _q_PTR_##func _q_##func = 0;                                                   \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { \
        if (Q_UNLIKELY(!_q_##func)) { \
            qsslSocketUnresolvedSymbolWarning(#func); \
            err; \
        }   \
        funcret _q_##func(a, b, c, d, e, f, g, h, i); \
    }
// **************** Shared declarations ******************

#else // !defined QTNETWORKNG_LINKED_OPENSSL

// **************** Static declarations ******************

// ret func(arg)
#  define DEFINEFUNC(ret, func, arg, a, err, funcret) \
    ret q_##func(arg) { funcret func(a); }

// ret func(arg1, arg2)
#  define DEFINEFUNC2(ret, func, arg1, a, arg2, b, err, funcret) \
    ret q_##func(arg1, arg2) { funcret func(a, b); }

// ret func(arg1, arg2, arg3)
#  define DEFINEFUNC3(ret, func, arg1, a, arg2, b, arg3, c, err, funcret) \
    ret q_##func(arg1, arg2, arg3) { funcret func(a, b, c); }

// ret func(arg1, arg2, arg3, arg4)
#  define DEFINEFUNC4(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4) { funcret func(a, b, c, d); }

// ret func(arg1, arg2, arg3, arg4, arg5)
#  define DEFINEFUNC5(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5) { funcret func(a, b, c, d, e); }

// ret func(arg1, arg2, arg3, arg4, arg6)
#  define DEFINEFUNC6(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6) { funcret func(a, b, c, d, e, f); }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7)
#  define DEFINEFUNC7(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7) { funcret func(a, b, c, d, e, f, g); }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { funcret func(a, b, c, d, e, f, g, h); }

// ret func(arg1, arg2, arg3, arg4, arg6, arg7, arg8, arg9)
#  define DEFINEFUNC9(ret, func, arg1, a, arg2, b, arg3, c, arg4, d, arg5, e, arg6, f, arg7, g, arg8, h, arg9, i, err, funcret) \
    ret q_##func(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9) { funcret func(a, b, c, d, e, f, g, h, i); }

// **************** Static declarations ******************

#endif // !defined QTNETWORKNG_LINKED_OPENSSL


// our functions
bool q_resolveOpenSslSymbols(bool force = false);
QDateTime q_getTimeFromASN1(const ASN1_TIME *aTime);


// here we defined!
//unsigned char *q_MD4(const unsigned char *d, unsigned long n, unsigned char *md);
//int q_MD4_Init(MD4_CTX *c);
//int q_MD4_Update(MD4_CTX *c, const void *data, unsigned long len);
//int q_MD4_Final(unsigned char *md, MD4_CTX *c);
//unsigned char *q_MD5(const unsigned char *d, unsigned long n,unsigned char *md);
//int q_MD5_Init(MD5_CTX *c);
//int q_MD5_Update(MD5_CTX *c, const void *data, unsigned long len);
//int q_MD5_Final(unsigned char *md, MD5_CTX *c);
//int q_SHA1_Init(SHA_CTX *c);
//int q_SHA1_Update(SHA_CTX *c, const void *data, unsigned long len);
//int q_SHA1_Final(unsigned char *md, SHA_CTX *c);
//int q_SHA224_Init(SHA256_CTX *c);
//int q_SHA224_Update(SHA256_CTX *c, const void *data, unsigned long len);
//int q_SHA224_Final(unsigned char *md, SHA256_CTX *c);
//int q_SHA256_Init(SHA256_CTX *c);
//int q_SHA256_Update(SHA256_CTX *c, const void *data, unsigned long len);
//int q_SHA256_Final(unsigned char *md, SHA256_CTX *c);
//int q_SHA384_Init(SHA512_CTX *c);
//int q_SHA384_Update(SHA512_CTX *c, const void *data, unsigned long len);
//int q_SHA384_Final(unsigned char *md, SHA512_CTX *c);
//int q_SHA512_Init(SHA512_CTX *c);
//int q_SHA512_Update(SHA512_CTX *c, const void *data, unsigned long len);
//int q_SHA512_Final(unsigned char *md, SHA512_CTX *c);

bool has_EVP_MD_CTX_new();
EVP_MD_CTX *q_EVP_MD_CTX_new(void);
EVP_MD_CTX *q_EVP_MD_CTX_create(void);
void q_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
void q_EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
int q_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int q_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int q_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int q_EVP_MD_block_size(const EVP_MD *md);
const EVP_MD *q_EVP_MD_CTX_md(EVP_MD_CTX *ctx);
const EVP_MD *q_EVP_md4(void);
const EVP_MD *q_EVP_md5(void);
const EVP_MD *q_EVP_sha1(void);
const EVP_MD *q_EVP_sha224(void);
const EVP_MD *q_EVP_sha256(void);
const EVP_MD *q_EVP_sha384(void);
const EVP_MD *q_EVP_sha512(void);
const EVP_MD *q_EVP_ripemd160(void);
const EVP_MD *q_EVP_blake2s256(void);
const EVP_MD *q_EVP_blake2b512(void);
void q_OpenSSL_add_all_digests(void);

EVP_CIPHER_CTX *q_EVP_CIPHER_CTX_new(void);
void q_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int q_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key,
                        unsigned char *iv, int enc);
int q_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
int q_EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int q_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
int q_EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int q_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int q_EVP_CIPHER_nid(const EVP_CIPHER *e);
int q_EVP_CIPHER_block_size(const EVP_CIPHER *e);
int q_EVP_CIPHER_key_length(const EVP_CIPHER *e);
int q_EVP_CIPHER_iv_length(const EVP_CIPHER *e);
unsigned long q_EVP_CIPHER_flags(const EVP_CIPHER *e);
unsigned long q_EVP_CIPHER_mode(const EVP_CIPHER *e);
int q_EVP_CIPHER_type(const EVP_CIPHER *ctx);
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int q_EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, const unsigned char *data,
                   int datal, int count, unsigned char *key, unsigned char *iv);
int q_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest,int keylen, unsigned char *out);

const EVP_CIPHER *q_EVP_enc_null(void); /* does nothing :-) */
const EVP_CIPHER *q_EVP_des_ecb(void);
const EVP_CIPHER *q_EVP_des_cfb64(void);
inline const EVP_CIPHER *q_EVP_des_cfb() { return q_EVP_des_cfb64(); }
const EVP_CIPHER *q_EVP_des_cfb1(void);
const EVP_CIPHER *q_EVP_des_cfb8(void);
const EVP_CIPHER *q_EVP_des_ofb(void);
const EVP_CIPHER *q_EVP_des_cbc(void);

const EVP_CIPHER *q_EVP_des_ede(void);
const EVP_CIPHER *q_EVP_des_ede_ecb(void);
const EVP_CIPHER *q_EVP_des_ede_cfb64(void);
inline const EVP_CIPHER *q_EVP_des_ede_cfb() { return q_EVP_des_ede_cfb64(); }
const EVP_CIPHER *q_EVP_des_ede_ofb(void);
const EVP_CIPHER *q_EVP_des_ede_cbc(void);

const EVP_CIPHER *q_EVP_des_ede3(void);
const EVP_CIPHER *q_EVP_des_ede3_ecb(void);
const EVP_CIPHER *q_EVP_des_ede3_cfb64(void);
inline const EVP_CIPHER *q_EVP_des_ede3_cfb() { return q_EVP_des_ede3_cfb64(); }
const EVP_CIPHER *q_EVP_des_ede3_cfb1(void);
const EVP_CIPHER *q_EVP_des_ede3_cfb8(void);
const EVP_CIPHER *q_EVP_des_ede3_ofb(void);
const EVP_CIPHER *q_EVP_des_ede3_cbc(void);

const EVP_CIPHER *q_EVP_rc4(void);
const EVP_CIPHER *q_EVP_rc4_40(void);

const EVP_CIPHER *q_EVP_idea_ecb(void);
const EVP_CIPHER *q_EVP_idea_cfb64(void);
inline const EVP_CIPHER *q_EVP_idea_cfb() { return q_EVP_idea_cfb64(); }
const EVP_CIPHER *q_EVP_idea_ofb(void);
const EVP_CIPHER *q_EVP_idea_cbc(void);

const EVP_CIPHER *q_EVP_rc2_ecb(void);
const EVP_CIPHER *q_EVP_rc2_cbc(void);
const EVP_CIPHER *q_VP_rc2_40_cbc(void);
const EVP_CIPHER *q_EVP_rc2_64_cbc(void);
const EVP_CIPHER *q_EVP_rc2_cfb64(void);
inline const EVP_CIPHER *q_EVP_rc2_cfb() { return q_EVP_rc2_cfb64(); }
const EVP_CIPHER *q_EVP_rc2_ofb(void);

const EVP_CIPHER *q_EVP_bf_ecb(void);
const EVP_CIPHER *q_EVP_bf_cbc(void);
const EVP_CIPHER *q_EVP_bf_cfb64(void);
inline const EVP_CIPHER *q_EVP_bf_cfb() { return q_EVP_bf_cfb64(); }
const EVP_CIPHER *q_EVP_bf_ofb(void);

const EVP_CIPHER *q_EVP_cast5_ecb(void);
const EVP_CIPHER *q_EVP_cast5_cbc(void);
const EVP_CIPHER *q_EVP_cast5_cfb64(void);
inline const EVP_CIPHER *q_EVP_cast5_cfb() { return q_EVP_cast5_cfb64(); }
const EVP_CIPHER *q_EVP_cast5_ofb(void);

const EVP_CIPHER *q_EVP_rc5_32_12_16_cbc(void);
const EVP_CIPHER *q_EVP_rc5_32_12_16_ecb(void);
const EVP_CIPHER *q_EVP_rc5_32_12_16_cfb64(void);
inline const EVP_CIPHER *q_EVP_rc5_32_12_16_cfb() { return q_EVP_rc5_32_12_16_cfb64(); }
const EVP_CIPHER *q_EVP_rc5_32_12_16_ofb(void);

const EVP_CIPHER *q_EVP_aes_128_ecb(void);
const EVP_CIPHER *q_EVP_aes_128_cbc(void);
const EVP_CIPHER *q_EVP_aes_128_cfb1(void);
const EVP_CIPHER *q_EVP_aes_128_cfb8(void);
const EVP_CIPHER *q_EVP_aes_128_cfb128(void);
inline const EVP_CIPHER *q_EVP_aes_128_cfb() { return q_EVP_aes_128_cfb128(); }
const EVP_CIPHER *q_EVP_aes_128_ofb(void);
const EVP_CIPHER *q_EVP_aes_128_ctr(void);
const EVP_CIPHER *q_EVP_aes_128_ccm(void);
const EVP_CIPHER *q_EVP_aes_128_gcm(void);
const EVP_CIPHER *q_EVP_aes_128_xts(void);
const EVP_CIPHER *q_EVP_aes_128_wrap(void);

const EVP_CIPHER *q_EVP_aes_192_ecb(void);
const EVP_CIPHER *q_EVP_aes_192_cbc(void);
const EVP_CIPHER *q_EVP_aes_192_cfb1(void);
const EVP_CIPHER *q_EVP_aes_192_cfb8(void);
const EVP_CIPHER *q_EVP_aes_192_cfb128(void);
inline const EVP_CIPHER *q_EVP_aes_192_cfb() { return q_EVP_aes_192_cfb128(); }
const EVP_CIPHER *q_EVP_aes_192_ofb(void);
const EVP_CIPHER *q_EVP_aes_192_ctr(void);
const EVP_CIPHER *q_EVP_aes_192_ccm(void);
const EVP_CIPHER *q_EVP_aes_192_gcm(void);
const EVP_CIPHER *q_EVP_aes_192_wrap(void);

const EVP_CIPHER *q_EVP_aes_256_ecb(void);
const EVP_CIPHER *q_EVP_aes_256_cbc(void);
const EVP_CIPHER *q_EVP_aes_256_cfb1(void);
const EVP_CIPHER *q_EVP_aes_256_cfb8(void);
const EVP_CIPHER *q_EVP_aes_256_cfb128(void);
inline const EVP_CIPHER *q_EVP_aes_256_cfb() { return q_EVP_aes_256_cfb128(); }
const EVP_CIPHER *q_EVP_aes_256_ofb(void);
const EVP_CIPHER *q_EVP_aes_256_ctr(void);
const EVP_CIPHER *q_EVP_aes_256_ccm(void);
const EVP_CIPHER *q_EVP_aes_256_gcm(void);
const EVP_CIPHER *q_EVP_aes_256_xts(void);
const EVP_CIPHER *q_EVP_aes_256_wrap(void);

const EVP_CIPHER *q_EVP_chacha20(void);

/*
int q_EVP_PKEY_assign(EVP_PKEY *a, int b, char *c);
#define q_EVP_PKEY_assign_RSA(pkey,rsa) q_EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
                                        (char *)(rsa))
#define q_EVP_PKEY_assign_DSA(pkey,dsa) q_EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
                                        (char *)(dsa))
*/

int q_EVP_PKEY_set1_RSA(EVP_PKEY *a, RSA *b);
int q_EVP_PKEY_set1_DSA(EVP_PKEY *a, DSA *b);
int q_EVP_PKEY_set1_EC_KEY(EVP_PKEY *a, EC_KEY *b);
RSA *q_EVP_PKEY_get1_RSA(EVP_PKEY *a);
DSA *q_EVP_PKEY_get1_DSA(EVP_PKEY *a);
EC_KEY *q_EVP_PKEY_get1_EC_KEY(EVP_PKEY *a);
int q_EVP_PKEY_type(int a);

EVP_PKEY *q_EVP_PKEY_new();
int q_EVP_PKEY_up_ref(EVP_PKEY *key);
void q_EVP_PKEY_free(EVP_PKEY *);
int q_EVP_PKEY_size(EVP_PKEY *);
int q_EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

inline int q_EVP_SignInit_ex(EVP_MD_CTX *a, const EVP_MD *b, ENGINE *c) { return q_EVP_DigestInit_ex(a, b, c); }
inline int q_EVP_SignUpdate(EVP_MD_CTX *a, const void *b, size_t c) { return q_EVP_DigestUpdate(a, b, c); }
int q_EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);
inline int q_EVP_VerifyInit_ex(EVP_MD_CTX *a, const EVP_MD *b, ENGINE *c) { return q_EVP_DigestInit_ex(a, b, c); }
inline int q_EVP_VerifyUpdate(EVP_MD_CTX *a, const void *b, size_t c) { return q_EVP_DigestUpdate(a, b, c); }
int q_EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int, EVP_PKEY *);
int q_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
inline int q_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) { return q_EVP_DigestUpdate(ctx, d, cnt); }
int q_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int q_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
inline int q_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) { return q_EVP_DigestUpdate(ctx, d, cnt); }
int q_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);

EVP_PKEY_CTX *q_EVP_PKEY_CTX_new(EVP_PKEY *, ENGINE *);
EVP_PKEY_CTX *q_EVP_PKEY_CTX_new_id(int, ENGINE *);
EVP_PKEY_CTX *q_EVP_PKEY_CTX_dup(EVP_PKEY_CTX *);
void q_EVP_PKEY_CTX_free(EVP_PKEY_CTX *);
int q_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *, const EVP_MD *);
int q_EVP_PKEY_sign_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_sign(EVP_PKEY_CTX *, unsigned char *, size_t *,const unsigned char *, size_t);
int q_EVP_PKEY_verify_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_verify(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
int q_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_encrypt(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
int q_EVP_PKEY_decrypt(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);

int q_EVP_PKEY_keygen_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_keygen(EVP_PKEY_CTX *, EVP_PKEY **);
int q_EVP_PKEY_derive_init(EVP_PKEY_CTX *);
int q_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *, EVP_PKEY *);
int q_EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);
int q_EVP_PKEY_set_type(EVP_PKEY *, int);
int q_EVP_PKEY_base_id(const EVP_PKEY *pkey);
int q_EVP_PKEY_bits(EVP_PKEY *pkey);
int q_EVP_PKEY_size(EVP_PKEY *pkey);

RSA *q_RSA_new();
void q_RSA_free(RSA *a);
int q_RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int q_RSA_private_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int q_RSA_public_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int q_RSA_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int q_RSA_private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int q_RSA_size(const RSA *rsa);

DSA *q_DSA_new();
void q_DSA_free(DSA *a);
int q_DSA_generate_parameters_ex(DSA *dsa, int bits,const unsigned char *seed, int seed_len,
                               int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int q_DSA_generate_key(DSA *a);


EVP_PKEY *q_PEM_read_bio_PrivateKey(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
EVP_PKEY *q_PEM_read_bio_PUBKEY(BIO *a, EVP_PKEY **b, pem_password_cb *c, void *d);
int q_PEM_write_bio_PrivateKey(BIO *a, EVP_PKEY *b, const EVP_CIPHER *c, unsigned char *d, int e, pem_password_cb *f, void *g);
int q_PEM_write_bio_PKCS8PrivateKey(BIO *a, EVP_PKEY *b, const EVP_CIPHER *c, unsigned char *d, int e, pem_password_cb *f, void *g);
int q_PEM_write_bio_RSAPrivateKey(BIO *a, RSA *b, const EVP_CIPHER *c, unsigned char *d, int e, pem_password_cb *f, void *g);
int q_PEM_write_bio_DSAPrivateKey(BIO *a, DSA *b, const EVP_CIPHER *c, unsigned char *d, int e, pem_password_cb *f, void *g);
int q_PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);
int q_PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x);
int q_PEM_write_bio_DSA_PUBKEY(BIO *bp, DSA *x);
int q_PEM_write_bio_DSAparams(BIO *bp, DSA *x);
int q_PEM_write_bio_DHparams(BIO *bp, DH *x);
int q_PEM_write_bio_X509(BIO *bp, X509 *x);
int q_PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x);
int q_PEM_write_bio_X509_REQ_NEW(BIO *bp, X509_REQ *x);
int q_PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x);
int q_PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x);



BIGNUM *q_BN_new(void);
void q_BN_free(BIGNUM *);
int q_BN_set_word(BIGNUM *a, BN_ULONG w);
int q_BN_num_bits(const BIGNUM *a);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int q_BN_is_word(BIGNUM *a, BN_ULONG w);
#else
// BN_is_word is implemented purely as a
// macro in OpenSSL < 1.1. It doesn't
// call any functions.
//
// The implementation of BN_is_word is
// 100% the same between 1.0.0, 1.0.1
// and 1.0.2.
//
// Users are required to include <openssl/bn.h>.
#define q_BN_is_word BN_is_word
#endif // OPENSSL_VERSION_NUMBER >= 0x10100000L
BN_ULONG q_BN_mod_word(const BIGNUM *a, BN_ULONG w);


// here follow openssl functions
long q_ASN1_INTEGER_get(ASN1_INTEGER *a);
unsigned char * q_ASN1_STRING_data(ASN1_STRING *a);
int q_ASN1_STRING_length(ASN1_STRING *a);
int q_ASN1_STRING_to_UTF8(unsigned char **a, ASN1_STRING *b);

long q_BIO_ctrl(BIO *a, int b, long c, void *d);
inline long q_BIO_get_mem_data(BIO *b, char **pp) { return  q_BIO_ctrl(b, BIO_CTRL_INFO, 0, (void *) pp); }
inline int q_BIO_pending(BIO *b) { return (int) q_BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL); }
int q_BIO_free(BIO *a);
BIO *q_BIO_new(BIO_METHOD *a);
BIO *q_BIO_new_mem_buf(const void *a, int b);
BIO_METHOD *q_BIO_s_mem();
int q_BIO_read(BIO *a, void *b, int c);
int q_BIO_write(BIO *a, const void *b, int c);
int q_BIO_up_ref(BIO *a);

const EC_GROUP* q_EC_KEY_get0_group(const EC_KEY* k);
int q_EC_GROUP_get_degree(const EC_GROUP* g);
int q_CRYPTO_num_locks();
void q_CRYPTO_set_locking_callback(void (*a)(int, int, const char *, int));
void q_CRYPTO_set_id_callback(unsigned long (*a)());
void q_CRYPTO_free(void *a);
X509 *q_d2i_X509(X509 **a, const unsigned char **b, long c);
char *q_ERR_error_string(unsigned long a, char *b);
unsigned long q_ERR_get_error();
void q_ERR_free_strings();
int q_i2d_X509(X509 *a, unsigned char **b);
const char *q_OBJ_nid2sn(int a);
const char *q_OBJ_nid2ln(int a);
int q_OBJ_sn2nid(const char *s);
int q_OBJ_ln2nid(const char *s);
int q_i2t_ASN1_OBJECT(char *buf, int buf_len, ASN1_OBJECT *obj);
int q_OBJ_obj2txt(char *buf, int buf_len, ASN1_OBJECT *obj, int no_name);
int q_OBJ_obj2nid(const ASN1_OBJECT *a);
int q_RAND_bytes(unsigned char *buf, int num);
void q_RAND_seed(const void *a, int b);
int q_RAND_status();
int q_sk_num(STACK *a);
void q_sk_pop_free(STACK *a, void (*b)(void *));
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
_STACK *q_sk_new_null();
void q_sk_push(_STACK *st, void *data);
void q_sk_free(_STACK *a);
void * q_sk_value(STACK *a, int b);
#else
STACK *q_sk_new_null();
void q_sk_push(STACK *st, char *data);
void q_sk_free(STACK *a);
char * q_sk_value(STACK *a, int b);
#endif
int q_SSL_accept(SSL *a);
int q_SSL_clear(SSL *a);
char *q_SSL_CIPHER_description(SSL_CIPHER *a, char *b, int c);
int q_SSL_CIPHER_get_bits(SSL_CIPHER *a, int *b);
int q_SSL_connect(SSL *a);
int q_SSL_CTX_check_private_key(const SSL_CTX *a);
long q_SSL_CTX_ctrl(SSL_CTX *a, int b, long c, void *d);
void q_SSL_CTX_free(SSL_CTX *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
SSL_CTX *q_SSL_CTX_new(const SSL_METHOD *a);
#else
SSL_CTX *q_SSL_CTX_new(SSL_METHOD *a);
#endif
int q_SSL_CTX_set_cipher_list(SSL_CTX *a, const char *b);
int q_SSL_CTX_set_default_verify_paths(SSL_CTX *a);
void q_SSL_CTX_set_verify(SSL_CTX *a, int b, int (*c)(int, X509_STORE_CTX *));
void q_SSL_CTX_set_verify_depth(SSL_CTX *a, int b);
int q_SSL_CTX_use_certificate(SSL_CTX *a, X509 *b);
int q_SSL_CTX_use_certificate_file(SSL_CTX *a, const char *b, int c);
int q_SSL_CTX_use_PrivateKey(SSL_CTX *a, EVP_PKEY *b);
int q_SSL_CTX_use_RSAPrivateKey(SSL_CTX *a, RSA *b);
int q_SSL_CTX_use_PrivateKey_file(SSL_CTX *a, const char *b, int c);
X509_STORE *q_SSL_CTX_get_cert_store(const SSL_CTX *a);
void q_SSL_free(SSL *a);
STACK_OF(SSL_CIPHER) *q_SSL_get_ciphers(const SSL *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
const SSL_CIPHER *q_SSL_get_current_cipher(SSL *a);
#else
SSL_CIPHER *q_SSL_get_current_cipher(SSL *a);
#endif
int q_SSL_version(const SSL *a);
int q_SSL_get_error(SSL *a, int b);
STACK_OF(X509) *q_SSL_get_peer_cert_chain(SSL *a);
X509 *q_SSL_get_peer_certificate(SSL *a);
long q_SSL_get_verify_result(const SSL *a);
int q_SSL_library_init();
void q_SSL_load_error_strings();
SSL *q_SSL_new(SSL_CTX *a);
long q_SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
int q_SSL_read(SSL *a, void *b, int c);
void q_SSL_set_bio(SSL *a, BIO *b, BIO *c);
void q_SSL_set0_rbio(SSL *a, BIO *b);
BIO *q_SSL_get_rbio(SSL *a);
void q_SSL_set0_wbio(SSL *a, BIO *b);
BIO *q_SSL_get_wbio(SSL *a);
void q_SSL_set_accept_state(SSL *a);
void q_SSL_set_connect_state(SSL *a);
int q_SSL_shutdown(SSL *a);
int q_SSL_set_session(SSL *to, SSL_SESSION *session);
void q_SSL_SESSION_free(SSL_SESSION *ses);
SSL_SESSION *q_SSL_get1_session(SSL *ssl);
SSL_SESSION *q_SSL_get_session(const SSL *ssl);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
int q_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int q_SSL_set_ex_data(SSL *ssl, int idx, void *arg);
void *q_SSL_get_ex_data(const SSL *ssl, int idx);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
typedef unsigned int (*q_psk_client_callback_t)(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len);
void q_SSL_set_psk_client_callback(SSL *ssl, q_psk_client_callback_t callback);
typedef unsigned int (*q_psk_server_callback_t)(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);
void q_SSL_set_psk_server_callback(SSL *ssl, q_psk_server_callback_t callback);
int q_SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *hint);
#endif // OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
const SSL_METHOD *q_SSLv2_client_method();
const SSL_METHOD *q_SSLv3_client_method();
const SSL_METHOD *q_SSLv23_client_method();
const SSL_METHOD *q_TLSv1_client_method();
const SSL_METHOD *q_TLSv1_1_client_method();
const SSL_METHOD *q_TLSv1_2_client_method();
const SSL_METHOD *q_SSLv2_server_method();
const SSL_METHOD *q_SSLv3_server_method();
const SSL_METHOD *q_SSLv23_server_method();
const SSL_METHOD *q_TLSv1_server_method();
const SSL_METHOD *q_TLSv1_1_server_method();
const SSL_METHOD *q_TLSv1_2_server_method();
int q_SSL_write(SSL *a, const void *b, int c);
int q_X509_cmp(X509 *a, X509 *b);
#ifdef SSLEAY_MACROS
void *q_ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x);
#define q_X509_dup(x509) (X509 *)q_ASN1_dup((i2d_of_void *)q_i2d_X509, \
                (d2i_of_void *)q_d2i_X509,(char *)x509)
#else
X509 *q_X509_dup(X509 *a);
#endif
void q_X509_print(BIO *a, X509*b);
ASN1_OBJECT *q_X509_EXTENSION_get_object(X509_EXTENSION *a);
void q_X509_free(X509 *a);
X509_EXTENSION *q_X509_get_ext(X509 *a, int b);
int q_X509_get_ext_count(X509 *a);
void *q_X509_get_ext_d2i(X509 *a, int b, int *c, int *d);
const X509V3_EXT_METHOD *q_X509V3_EXT_get(X509_EXTENSION *a);
void *q_X509V3_EXT_d2i(X509_EXTENSION *a);
int q_X509_EXTENSION_get_critical(X509_EXTENSION *a);
ASN1_OCTET_STRING *q_X509_EXTENSION_get_data(X509_EXTENSION *a);
void q_BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);
void q_AUTHORITY_KEYID_free(AUTHORITY_KEYID *a);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
int q_ASN1_STRING_print(BIO *a, const ASN1_STRING *b);
#else
int q_ASN1_STRING_print(BIO *a, ASN1_STRING *b);
#endif
int q_X509_check_issued(X509 *a, X509 *b);
X509_NAME *q_X509_get_issuer_name(X509 *a);
X509_NAME *q_X509_get_subject_name(X509 *a);
int q_X509_verify_cert(X509_STORE_CTX *ctx);
int q_X509_NAME_entry_count(X509_NAME *a);
X509_NAME_ENTRY *q_X509_NAME_get_entry(X509_NAME *a,int b);
ASN1_STRING *q_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *a);
ASN1_OBJECT *q_X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *a);
EVP_PKEY *q_X509_PUBKEY_get(X509_PUBKEY *a);
void q_X509_STORE_free(X509_STORE *store);
X509_STORE *q_X509_STORE_new();
int q_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
void q_X509_STORE_CTX_free(X509_STORE_CTX *storeCtx);
int q_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                          X509 *x509, STACK_OF(X509) *chain);
X509_STORE_CTX *q_X509_STORE_CTX_new();
int q_X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int q_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
int q_X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 *q_X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK_OF(X509) *q_X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);

// Diffie-Hellman support
DH *q_DH_new();
void q_DH_free(DH *dh);
DH *q_d2i_DHparams(DH **a, const unsigned char **pp, long length);
int q_i2d_DHparams(DH *a, unsigned char **p);
int q_DH_check(DH *dh, int *codes);

BIGNUM *q_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
#define q_SSL_CTX_set_tmp_dh(ctx, dh) q_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_DH, 0, (char *)dh)

#ifndef OPENSSL_NO_EC
// EC Diffie-Hellman support
EC_KEY *q_EC_KEY_dup(const EC_KEY *src);
EC_KEY *q_EC_KEY_new_by_curve_name(int nid);
void q_EC_KEY_free(EC_KEY *ecdh);
#define q_SSL_CTX_set_tmp_ecdh(ctx, ecdh) q_SSL_CTX_ctrl((ctx), SSL_CTRL_SET_TMP_ECDH, 0, (char *)ecdh)

// EC curves management
size_t q_EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int q_EC_curve_nist2nid(const char *name);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
#endif // OPENSSL_NO_EC
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#define q_SSL_get_server_tmp_key(ssl, key) q_SSL_ctrl((ssl), SSL_CTRL_GET_SERVER_TMP_KEY, 0, (char *)key)
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

// PKCS#12 support
int q_PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
PKCS12 *q_d2i_PKCS12_bio(BIO *bio, PKCS12 **pkcs12);
void q_PKCS12_free(PKCS12 *pkcs12);


#define q_SSL_CTX_set_options(ctx,op) q_SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL)
#define q_SSL_CTX_set_mode(ctx,op) q_SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
#define q_SKM_sk_num(type, st) ((int (*)(const STACK_OF(type) *))q_sk_num)(st)
#define q_SKM_sk_value(type, st,i) ((type * (*)(const STACK_OF(type) *, int))q_sk_value)(st, i)
#define q_sk_GENERAL_NAME_num(st) q_SKM_sk_num(GENERAL_NAME, (st))
#define q_sk_GENERAL_NAME_value(st, i) q_SKM_sk_value(GENERAL_NAME, (st), (i))
#define q_sk_X509_num(st) q_SKM_sk_num(X509, (st))
#define q_sk_X509_value(st, i) q_SKM_sk_value(X509, (st), (i))
#define q_sk_SSL_CIPHER_num(st) q_SKM_sk_num(SSL_CIPHER, (st))
#define q_sk_SSL_CIPHER_value(st, i) q_SKM_sk_value(SSL_CIPHER, (st), (i))
#define q_SSL_CTX_add_extra_chain_cert(ctx,x509) \
        q_SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
#define q_X509_get_notAfter(x) X509_get_notAfter(x)
#define q_X509_get_notBefore(x) X509_get_notBefore(x)
#define q_OpenSSL_add_all_algorithms() q_OPENSSL_add_all_algorithms_conf()
void q_OPENSSL_add_all_algorithms_noconf();
void q_OPENSSL_add_all_algorithms_conf();
int q_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
long q_SSLeay();
const char *q_SSLeay_version(int type);
int q_i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp);
SSL_SESSION *q_d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length);

#if OPENSSL_VERSION_NUMBER >= 0x1000100fL && !defined(OPENSSL_NO_NEXTPROTONEG)
int q_SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                            const unsigned char *in, unsigned int inlen,
                            const unsigned char *client, unsigned int client_len);
void q_SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
                                        int (*cb) (SSL *ssl, unsigned char **out,
                                                   unsigned char *outlen,
                                                   const unsigned char *in,
                                                   unsigned int inlen, void *arg),
                                        void *arg);
void q_SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                      unsigned *len);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
int q_SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                          unsigned protos_len);
void q_SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                  int (*cb) (SSL *ssl,
                                             const unsigned char **out,
                                             unsigned char *outlen,
                                             const unsigned char *in,
                                             unsigned int inlen,
                                             void *arg), void *arg);
void q_SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                              unsigned *len);
#endif
#endif // OPENSSL_VERSION_NUMBER >= 0x1000100fL ...

}
}

#endif  //QTNG_OPENSSL_SYMBOLS_H
