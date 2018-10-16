QT += core network
QT -= gui

TARGET = qtnetworkng
CONFIG += console staticlib
CONFIG -= app_bundle
TEMPLATE = lib
# CONFIG += networkng_ev

TESTS_SOURCES = tests/simple_test.cpp \
    tests/many_httpget.cpp \
    tests/sleep_coroutines.cpp \
    tests/test_crypto.cpp \
    tests/test_ssl.cpp \
    tests/test_coroutines.cpp
#DEFINES += QSOCKETNG_DEBUG

include(qtnetworkng.pri)

qtnetworkng_public_headers.path=$$[QT_INSTALL_HEADERS]/qtnetworkng/
qtnetworkng_public_headers.files=$$HEADERS
qtnetworkng_private_headers.path=$$[QT_INSTALL_HEADERS]/qtnetworkng/private/
qtnetworkng_public_headers.files=$$PRIVATE_HEADERS

target.path=$$[QT_INSTALL_LIBS]/

INSTALLS += qtnetworkng_public_headers target




