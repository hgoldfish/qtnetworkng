QT += core network
QT -= gui

CONFIG += c++11

!win32-msvc* {
    QMAKE_CXXFLAGS += -Wno-invalid-offsetof
}

INCLUDEPATH += $$PWD

SOURCES += \
    $$PWD/src/socket.cpp \
    $$PWD/src/eventloop.cpp \
    $$PWD/src/coroutine.cpp \
    $$PWD/src/locks.cpp \
    $$PWD/src/coroutine_utils.cpp \
    $$PWD/src/http.cpp \
    $$PWD/src/io_utils.cpp \
    $$PWD/src/socket_utils.cpp \
    $$PWD/src/http_utils.cpp \
    $$PWD/src/http_proxy.cpp \
    $$PWD/src/http_cookie.cpp \
    $$PWD/src/socks5_proxy.cpp \
    $$PWD/src/eventloop_qt.cpp \
    $$PWD/src/msgpack.cpp \
    $$PWD/src/kcp.cpp \
    $$PWD/src/kcp/ikcp.c \
    $$PWD/src/socket_server.cpp \
    $$PWD/src/httpd.cpp \
    $$PWD/src/httpd2.cpp \
    $$PWD/src/socks5_server.cpp \
    $$PWD/src/websocket.cpp \
    $$PWD/src/random.cpp \
    $$PWD/src/hostaddress.cpp \
    $$PWD/src/network_interface/network_interface.cpp

    
PRIVATE_HEADERS += \
    $$PWD/include/private/coroutine_p.h \
    $$PWD/include/private/http_p.h \
    $$PWD/include/private/socket_p.h \
    $$PWD/include/private/hostaddress_p.h \
    $$PWD/include/private/network_interface_p.h \
    $$PWD/src/kcp/ikcp.h

    
HEADERS += \
    $$PWD/include/config.h \
    $$PWD/include/coroutine.h \
    $$PWD/include/socket.h \
    $$PWD/include/eventloop.h \
    $$PWD/include/locks.h \
    $$PWD/include/coroutine_utils.h \
    $$PWD/include/http.h \
    $$PWD/include/io_utils.h \
    $$PWD/include/socket_utils.h \
    $$PWD/include/http_utils.h \
    $$PWD/include/http_proxy.h \
    $$PWD/include/http_cookie.h \
    $$PWD/include/socks5_proxy.h \
    $$PWD/include/deferred.h \
    $$PWD/include/msgpack.h \
    $$PWD/include/kcp.h \
    $$PWD/include/socket_server.h \
    $$PWD/include/httpd.h \
    $$PWD/include/random.h \
    $$PWD/include/hostaddress.h \
    $$PWD/include/network_interface.h

    
win32 {
    SOURCES += $$PWD/src/socket_win.cpp \
        $$PWD/src/eventloop_win.cpp \
        $$PWD/src/network_interface/network_interface_win.cpp
    LIBS += -lws2_32 -luser32
    DEFINES += "QTNETWORKNG_USE_WIN=1"
} else: unix  {
    SOURCES += $$PWD/src/socket_unix.cpp \
        $$PWD/src/network_interface/network_interface_unix_p.h
    linux {
        SOURCES += $$PWD/src/network_interface/network_interface_linux.cpp
    } else {
        SOURCES += $$PWD/src/network_interface/network_interface_unix.cpp
    }
    linux {
        DEFINES += "EV_USE_EPOLL=1"
        DEFINES += "EV_USE_EVENTFD=1"
        DEFINES += "EV_USE_KQUEUE=0"
        DEFINES += "EV_USE_POLL=0"
    } else: netbsd { # use poll
        DEFINES += "EV_USE_EPOLL=0"
        DEFINES += "EV_USE_EVENTFD=0"
        DEFINES += "EV_USE_KQUEUE=0"
        DEFINES += "EV_USE_POLL=1"
    } else: bsd {
        DEFINES += "EV_USE_EPOLL=0"
        DEFINES += "EV_USE_EVENTFD=0"
        DEFINES += "EV_USE_KQUEUE=1"
        DEFINES += "EV_USE_POLL=0"
    } else {
        DEFINES += "EV_USE_EPOLL=0"
        DEFINES += "EV_USE_EVENTFD=0"
        DEFINES += "EV_USE_KQUEUE=0"
        DEFINES += "EV_USE_POLL=1"
    }
    DEFINES += "QTNETWOKRNG_USE_EV=1"
    SOURCES += $$PWD/src/ev/ev.c \
               $$PWD/src/eventloop_ev.cpp
    PRIVATE_HEADERS += $$PWD/src/ev/ev.h
}

qtng_crypto {
    PRIVATE_HEADERS += \
        $$PWD/include/private/crypto_p.h \
        $$PWD/include/private/qasn1element.h

    HEADERS += $$PWD/include/config.h \
        $$PWD/include/crypto.h \
        $$PWD/include/ssl.h \
        $$PWD/include/md.h \
        $$PWD/include/cipher.h \
        $$PWD/include/pkey.h \
        $$PWD/include/certificate.h \
        $$PWD/include/qtcrypto.h

    SOURCES += $$PWD/src/ssl.cpp \
        $$PWD/src/crypto.cpp \
        $$PWD/src/md.cpp \
        $$PWD/src/pkey.cpp \
        $$PWD/src/cipher.cpp \
        $$PWD/src/certificate.cpp \
        $$PWD/src/qasn1element.cpp

    LIBS += -lssl -lcrypto
} else {
    DEFINES += "QTNG_NO_CRYPTO=1"
}

# decide which fcontext asm file to use.
android {
    equals(ANDROID_ARCHITECTURE, x86) {
        SOURCES += $$PWD/src/context/asm/jump_i386_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_i386_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(ANDROID_ARCHITECTURE, x86_64) {
        SOURCES += $$PWD/src/context/asm/jump_x86_64_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_x86_64_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(ANDROID_ARCHITECTURE, mips) {
        SOURCES += $$PWD/src/context/asm/jump_mips32_o32_elf_gas.S \
            $$PWD/src/context/asm/make_mips32_o32_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(ANDROID_ARCHITECTURE, mips64) {
        error(Unsupported platform)
    } else: equals(ANDROID_ARCHITECTURE, arm64) {
        SOURCES += $$PWD/src/context/asm/jump_arm64_aapcs_elf_gas.S \
            $$PWD/src/context/asm/make_arm64_aapcs_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(ANDROID_ARCHITECTURE, arm) {
        SOURCES += $$PWD/src/context/asm/jump_arm_aapcs_elf_gas.S \
            $$PWD/src/context/asm/make_arm_aapcs_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else {
        error(Unsupported platform)
    }
} else: mac {
    equals(QT_ARCH, x86_64) {
        SOURCES += $$PWD/src/context/asm/jump_x86_64_sysv_macho_gas.S \
            $$PWD/src/context/asm/make_x86_64_sysv_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, i386) {
        SOURCES += $$PWD/src/context/asm/jump_i386_sysv_macho_gas.S \
            $$PWD/src/context/asm/make_i386_sysv_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, power64) {
        SOURCES += $$PWD/src/context/asm/jump_ppc64_sysv_macho_gas.S \
            $$PWD/src/context/asm/make_ppc64_sysv_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, power) {
        SOURCES += $$PWD/src/context/asm/jump_ppc32_sysv_macho_gas.S \
            $$PWD/src/context/asm/make_ppc32_ppc64_sysv_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, arm){
        SOURCES += $$PWD/src/context/asm/jump_arm_aapcs_macho_gas.S \
            $$PWD/src/context/asm/make_arm_aapcs_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, arm64) {
        SOURCES += $$PWD/src/context/asm/jump_arm64_aapcs_macho_gas.S \
            $$PWD/src/context/asm/make_arm64_aapcs_macho_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else {
        error(Unsupported platform)
    }
} else: unix {
    equals(QT_ARCH, x86_64) {
        SOURCES += $$PWD/src/context/asm/jump_x86_64_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_x86_64_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, i386) {
        SOURCES += $$PWD/src/context/asm/jump_i386_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_i386_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, sparc64) {
        SOURCES += $$PWD/src/context/asm/jump_sparc64_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_sparc64_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, power64) {
        SOURCES += $$PWD/src/context/asm/jump_ppc64_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_ppc64_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, power) {
        SOURCES += $$PWD/src/context/asm/jump_ppc32_sysv_elf_gas.S \
            $$PWD/src/context/asm/make_ppc32_sysv_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, arm){
        SOURCES += $$PWD/src/context/asm/jump_arm_aapcs_elf_gas.S \
            $$PWD/src/context/asm/make_arm_aapcs_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, arm64) {
        SOURCES += $$PWD/src/context/asm/jump_arm64_aapcs_elf_gas.S \
            $$PWD/src/context/asm/make_arm64_aapcs_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else: equals(QT_ARCH, mips) {
        SOURCES += $$PWD/src/context/asm/jump_mips32_o32_elf_gas.S \
            $$PWD/src/context/asm/make_mips32_o32_elf_gas.S \
            $$PWD/src/coroutine_fcontext.cpp
    } else {
        SOURCES += $$PWD/src/coroutine_unix.cpp
    }
} else: win32 {
    win32-msvc* : {
        SOURCES += $$PWD/src/coroutine_win.cpp
    } else {
        equals(QT_ARCH, i386) {
            SOURCES += $$PWD/src/context/asm/jump_i386_ms_pe_gas.S \
                $$PWD/src/context/asm/make_i386_ms_pe_gas.S \
                $$PWD/src/coroutine_fcontext.cpp
        } else {
            SOURCES += $$PWD/src/coroutine_win.cpp
        }
    }
} else {
    error(Unsupported platform)
}
