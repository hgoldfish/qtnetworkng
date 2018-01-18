QT += core network

CONFIG += c++11

HEADERS += $$PWD/include/config.h \
    $$PWD/include/crypto.h \
    $$PWD/include/ssl.h \
    $$PWD/include/openssl_symbols.h \
    $$PWD/include/qtng_temp.h \
    $$PWD/qtsslng.h \
    $$PWD/include/md.h \
    $$PWD/include/random.h \
    $$PWD/include/cipher.h \
    $$PWD/include/pkey.h \
    $$PWD/include/crypto_p.h \
    $$PWD/include/certificate.h

SOURCES += $$PWD/src/ssl.cpp \
    $$PWD/src/crypto.cpp \
    $$PWD/src/openssl_symbols.cpp \
    $$PWD/src/random.cpp \
    $$PWD/src/md.cpp \
    $$PWD/src/pkey.cpp \
    $$PWD/src/cipher.cpp

