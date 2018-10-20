QT += core

CONFIG += c++11

HEADERS += $$PWD/include/config.h \
    $$PWD/include/crypto.h \
    $$PWD/include/md.h \
    $$PWD/include/random.h \
    $$PWD/include/cipher.h \
    $$PWD/include/pkey.h \
    $$PWD/include/private/crypto_p.h \
    $$PWD/include/certificate.h \
    $$PWD/include/private/qasn1element.h \
    $$PWD/include/qtcryoto.h

SOURCES += $$PWD/src/crypto.cpp \
    $$PWD/src/random.cpp \
    $$PWD/src/md.cpp \
    $$PWD/src/pkey.cpp \
    $$PWD/src/cipher.cpp \
    $$PWD/src/certificate.cpp \
    $$PWD/src/qasn1element.cpp

LIBS += -lssl -lcrypto
