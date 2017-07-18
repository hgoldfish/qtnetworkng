QT += core network

CONFIG += c++11

QMAKE_CXXFLAGS += -Wno-invalid-offsetof

INCLUDEPATH += $$PWD

SOURCES += $$PWD/socket_ng.cpp \
    $$PWD/eventloop.cpp \
    $$PWD/coroutine.cpp \
    $$PWD/locks.cpp \
    $$PWD/coroutine_utils.cpp \
    $$PWD/data_channel.cpp \
    $$PWD/http_ng.cpp \

unix {
    SOURCES += $$PWD/socket_ng_unix.cpp \
        $$PWD/coroutine_unix.cpp
}

windows{
    SOURCES += $$PWD/socket_ng_win.cpp \
        $$PWD/coroutine_win.cpp
    LIBS += -lws2_32
}

HEADERS += \
    $$PWD/coroutine.h \
    $$PWD/socket_ng.h \
    $$PWD/socket_ng_p.h \
    $$PWD/eventloop.h \
    $$PWD/locks.h \
    $$PWD/coroutine_utils.h \
    $$PWD/qtnetworkng.h \
    $$PWD/data_channel.h \
    $$PWD/datapack.h \
    $$PWD/coroutine_p.h \
    $$PWD/http_ng.h \
    $$PWD/http_ng_p.h

networkng_ev {
    LIBS += -lev
    SOURCES += $$PWD/eventloop_ev.cpp
} else {
    SOURCES += $$PWD/eventloop_qt.cpp
}
