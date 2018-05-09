QT = core network testlib

TARGET = qtnetworkng
CONFIG += console
CONFIG -= app_bundle
TEMPLATE = app
# CONFIG += networkng_ev
# QT_ARCH = undefined
SOURCES += tests/simple_test.cpp \
    tests/many_httpget.cpp \
    tests/sleep_coroutines.cpp \
    tests/test_crypto.cpp \
    tests/test_ssl.cpp \
    tests/test_coroutines.cpp
#DEFINES += QSOCKETNG_DEBUG

include(qtnetworkng.pri)




