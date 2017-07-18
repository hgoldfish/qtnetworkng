QT = core network

TARGET = qtnetworkng
CONFIG += console
#CONFIG += networkng_ev
CONFIG -= app_bundle
TEMPLATE = app
SOURCES += simple_test.cpp
#DEFINES += QSOCKETNG_DEBUG

include(qtnetworkng.pri)



