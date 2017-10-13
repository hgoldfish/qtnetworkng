QT += core network

CONFIG += c++11

QMAKE_CXXFLAGS += -Wno-invalid-offsetof

INCLUDEPATH += $$PWD/include/

SOURCES += $$PWD/src/socket_ng.cpp \
    $$PWD/src/eventloop.cpp \
    $$PWD/src/coroutine.cpp \
    $$PWD/src/locks.cpp \
    $$PWD/src/coroutine_utils.cpp \
    $$PWD/src/http_ng.cpp

unix {
    SOURCES += $$PWD/src/socket_ng_unix.cpp \
        $$PWD/src/coroutine_unix.cpp
}

windows{
    SOURCES += $$PWD/src/socket_ng_win.cpp \
        $$PWD/src/coroutine_win.cpp
    LIBS += -lws2_32
}

HEADERS += \
    $$PWD/include/coroutine.h \
    $$PWD/include/socket_ng.h \
    $$PWD/include/socket_ng_p.h \
    $$PWD/include/eventloop.h \
    $$PWD/include/locks.h \
    $$PWD/include/coroutine_utils.h \
    $$PWD/include/qtnetworkng.h \
    $$PWD/include/coroutine_p.h \
    $$PWD/include/http_ng.h \
    $$PWD/include/http_ng_p.h

networkng_ev {
    LIBS += -lev
    SOURCES += $$PWD/src/eventloop_ev.cpp
} else {
    SOURCES += $$PWD/src/eventloop_qt.cpp
}
