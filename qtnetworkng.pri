QT += core network

CONFIG += c++11

QMAKE_CXXFLAGS += -Wno-invalid-offsetof

#INCLUDEPATH += $$PWD/include/

SOURCES += \
    $$PWD/src/socket.cpp \
    $$PWD/src/eventloop.cpp \
    $$PWD/src/coroutine.cpp \
    $$PWD/src/locks.cpp \
    $$PWD/src/coroutine_utils.cpp \
    $$PWD/src/http.cpp \
    $$PWD/contrib/data_channel.cpp \
    $$PWD/src/socket_utils.cpp

unix {
    SOURCES += $$PWD/src/socket_unix.cpp \
        $$PWD/src/coroutine_unix.cpp
}

windows {
    SOURCES += $$PWD/src/socket_win.cpp \
        $$PWD/src/coroutine_win.cpp \
        $$PWD/src/qsystemlibrary.cpp
    LIBS += -lws2_32
}

HEADERS += \
    $$PWD/qtnetworkng.h \
    $$PWD/include/config.h \
    $$PWD/include/coroutine.h \
    $$PWD/include/socket.h \
    $$PWD/include/socket_p.h \
    $$PWD/include/eventloop.h \
    $$PWD/include/locks.h \
    $$PWD/include/coroutine_utils.h \
    $$PWD/include/coroutine_p.h \
    $$PWD/include/http.h \
    $$PWD/include/http_p.h \
    $$PWD/contrib/data_pack.h \
    $$PWD/contrib/data_channel.h \
    $$PWD/include/socket_utils.h \
    $$PWD/include/qsystemlibrary_p.h


networkng_ev {
    LIBS += -lev
    SOURCES += $$PWD/src/eventloop_ev.cpp
} else {
    SOURCES += $$PWD/src/eventloop_qt.cpp
}
