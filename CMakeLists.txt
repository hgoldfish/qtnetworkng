cmake_minimum_required(VERSION 2.8.8...3.17 FATAL_ERROR)

if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()
if (POLICY CMP0020)
    cmake_policy(SET CMP0020 NEW)
endif ()
if (POLICY CMP0071)
    cmake_policy(SET CMP0071 NEW)
endif ()

project(qtnetworkng LANGUAGES C CXX ASM)

option(QTNG_USE_OPENSSL OFF)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC OFF)
set(CMAKE_AUTORCC OFF)

find_package(Qt5Core CONFIG REQUIRED CMAKE_FIND_ROOT_PATH_BOTH)
if (QTNG_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)  # CMAKE_FIND_ROOT_PATH_BOTH
    include(CheckFunctionExists)
else()
    # intergrate libressl
    add_subdirectory(libressl)
endif()

if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    else()
        message(SEND_ERROR "Please update your cmake to enable c++11.")
    endif ()
else ()
    set (CMAKE_CXX_STANDARD 11)
endif ()


set(QTNETWORKNG_SRC
    src/debugger.h
    src/socket.cpp
    src/eventloop.cpp
    src/eventloop_qt.cpp
    src/coroutine.cpp
    src/locks.cpp
    src/coroutine_utils.cpp
    src/socket_utils.cpp
    src/io_utils.cpp
    src/http.cpp
    src/http_utils.cpp
    src/http_proxy.cpp
    src/http_cookie.cpp
    src/socks5_proxy.cpp
    src/msgpack.cpp
    src/data_channel.cpp
    src/hostaddress.cpp
    src/gzip.cpp

    src/socket_server.cpp
    src/httpd.cpp
    src/httpd2.cpp
    src/socks5_server.cpp
    src/websocket.cpp

    src/kcp.cpp
    src/kcp/ikcp.c
    src/kcp/ikcp.h

    src/network_interface/network_interface.cpp
)

set(QTNETWORKNG_INCLUDE
    include/config.h
    include/coroutine.h
    include/socket.h
    include/eventloop.h
    include/locks.h
    include/coroutine_utils.h
    include/http.h
    include/httpd.h
    include/socket_utils.h
    include/io_utils.h
    include/socket_server.h
    include/http_utils.h
    include/http_proxy.h
    include/http_cookie.h
    include/socks5_proxy.h
    include/deferred.h
    include/qtnetworkng.h
    include/msgpack.h
    include/data_channel.h
    include/kcp.h
    include/hostaddress.h
    include/network_interface.h
    include/gzip.h
    include/websocket.h
)

set(QTNETWORKNG_PRIVATE_INCLUDE
    include/private/data_pack.h
    include/private/eventloop_p.h
    include/private/coroutine_p.h
    include/private/socket_p.h
    include/private/http_p.h
    include/private/hostaddress_p.h
    include/private/network_interface_p.h
)

set(QTCRYPTONG_SRC
    src/ssl.cpp
    src/crypto.cpp
    src/random.cpp
    src/md.cpp
    src/pkey.cpp
    src/cipher.cpp
    src/certificate.cpp
    src/qasn1element.cpp
)

set(QTCRYPTONG_INCLUDE
    include/config.h
    include/crypto.h
    include/ssl.h
    include/md.h
    include/random.h
    include/cipher.h
    include/pkey.h
    include/certificate.h
)

set(QTCRYPTONG_PRIVATE_INCLUDE
    include/private/crypto_p.h
    include/private/qasn1element.h
)

find_path(QT_BUNDLED_ZLIB zlib.h HINTS "${_qt5Core_install_prefix}/include/QtZlib")
if (${QT_BUNDLED_ZLIB} STREQUAL "${_qt5Core_install_prefix}/include/QtZlib")
    message("use qt bundled zlib.")
    set(ZLIB_LINK "")
    set(ZLIB_INCLUDE ${QT_BUNDLED_ZLIB})
else()
    message("assume that zlib is exists.")
    set(ZLIB_LINK z)
    set(ZLIB_INCLUDE "")
endif()
unset(QT_BUNDLED_ZLIB)


if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(OS_DEPENDENDED_SRC
        src/socket_win.cpp
        src/coroutine_win.cpp
        src/network_interface/network_interface_win.cpp
    )
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    # Android support cross build.
    if(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm64_aapcs_elf_gas.S
            src/context/asm/make_arm64_aapcs_elf_gas.S
        )
    elseif(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm_aapcs_elf_gas.S
            src/context/asm/make_arm_aapcs_elf_gas.S
        )
    elseif(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "mips")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_mips32_o32_elf_gas.S
            src/context/asm/make_mips32_o32_elf_gas.S
        )
    elseif(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "mips64")
        message(FATAL_ERROR Android for mips64 is not supported.)
    elseif(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_i386_sysv_elf_gas.S
            src/context/asm/make_i386_sysv_elf_gas.S
        )
    elseif(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86_64")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_x86_64_sysv_elf_gas.S
            src/context/asm/make_x86_64_sysv_elf_gas.S
        )
    else()
        message(FATAL_ERROR Android for ${CMAKE_ANDROID_ARCH_ABI} is not supported.)
    endif()
    set(OS_DEPENDENDED_SRC
        ${OS_DEPENDENDED_SRC}
        src/socket_unix.cpp
        src/coroutine_fcontext.cpp
        src/network_interface/network_interface_unix.cpp
    )
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_x86_64_sysv_macho_gas.S
            src/context/asm/make_x86_64_sysv_macho_gas.S
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_i386_sysv_macho_gas.S
            src/context/asm/make_i386_sysv_macho_gas.S
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm64_aapcs_macho_gas.S
            src/context/asm/make_arm64_aapcs_macho_gas.S
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm_aapcs_macho_gas.S
            src/context/asm/make_arm_aapcs_macho_gas.S
        )
    else()
        message(FATAL_ERROR ${CMAKE_SYSTEM_NAME} is not supported.)
    endif()
    set(OS_DEPENDENDED_SRC
        ${OS_DEPENDENDED_SRC}
        src/socket_unix.cpp
        src/coroutine_fcontext.cpp
        src/network_interface/network_interface_unix.cpp
    )
elseif(UNIX)
    # TODO should support cross build.
    if((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_x86_64_sysv_elf_gas.S
            src/context/asm/make_x86_64_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_i386_sysv_elf_gas.S
            src/context/asm/make_i386_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm64_aapcs_elf_gas.S
            src/context/asm/make_arm64_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    elseif((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm"))
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_arm_aapcs_elf_gas.S
            src/context/asm/make_arm_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    #ELSEIF(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "mips64")
    elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "mips")
        set(OS_DEPENDENDED_SRC
            src/context/asm/jump_mips32_o32_elf_gas.S
            src/context/asm/make_mips32_o32_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    else()
        # fall back to ucontext
        set(OS_DEPENDENDED_SRC
            src/coroutine_unix.cpp
        )
    endif()
#    if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
#        set(OS_DEPENDENDED_SRC
#            ${OS_DEPENDENDED_SRC}
#            src/socket_unix.cpp
#            src/network_interface/network_interface_linux.cpp
#        )
#    else()
#        set(OS_DEPENDENDED_SRC
#            ${OS_DEPENDENDED_SRC}
#            src/socket_unix.cpp
#            src/network_interface/network_interface_unix.cpp
#        )
#    endif()
    set(OS_DEPENDENDED_SRC
        ${OS_DEPENDENDED_SRC}
        src/socket_unix.cpp
        src/network_interface/network_interface_unix.cpp
    )
else()
    message(FATAL_ERROR ${CMAKE_SYSTEM_NAME} is not supported.)
endif()

# intergrate libev-light
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    add_definitions(-DQTNETWORKNG_USE_WIN=1)
    set(QTNETWORKNG_SRC ${QTNETWORKNG_SRC} src/eventloop_win.cpp)
elseif(UNIX)
    add_definitions(-DQTNETWOKRNG_USE_EV)
    add_definitions(-DEV_USE_4HEAP=1 -DEV_VERIFY=0 -DQTNG_EV_ASSERT=0)
    check_function_exists(kqueue HAVE_KQUEUE)
    check_function_exists(epoll_ctl HAVE_EPOLL)
    if(HAVE_EPOLL)
        message("Use linux epoll() for libev.")
        add_definitions(-DEV_USE_EPOLL=1 -DEV_USE_EVENTFD=1)
        add_definitions(-DEV_USE_KQUEUE=0)
        add_definitions(-DEV_USE_POLL=0)
    elseif(HAVE_KQUEUE AND NOT ${CMAKE_SYSTEM_NAME} STREQUAL "NetBSD")
        message("Use bsd kqueue() for libev.")
        add_definitions(-DEV_USE_EPOLL=0 -DEV_USE_EVENTFD=0)
        add_definitions(-DEV_USE_KQUEUE=1)
        add_definitions(-DEV_USE_POLL=0)
    else()
        message("Use unix poll() for libev.")
        add_definitions(-DEV_USE_EPOLL=0 -DEV_USE_EVENTFD=0)
        add_definitions(-DEV_USE_KQUEUE=0)
        add_definitions(-DEV_USE_POLL=1)
    endif()
    set(QTNETWORKNG_SRC ${QTNETWORKNG_SRC} src/ev/ev.c src/ev/ev.h src/eventloop_ev.cpp)
endif()

add_library(qtnetworkng STATIC ${QTNETWORKNG_SRC} ${QTNETWORKNG_INCLUDE} ${QTNETWORKNG_PRIVATE_INCLUDE}
                               ${QTCRYPTONG_SRC} ${QTCRYPTONG_INCLUDE} ${QTCRYPTONG_PRIVATE_INCLUDE}
                               ${OS_DEPENDENDED_SRC} ${ZLIB_SRC})
target_include_directories(qtnetworkng PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}"
                                       PRIVATE "${ZLIB_INCLUDE}")
target_compile_definitions(qtnetworkng PRIVATE -DQTNG_HAVE_ZLIB)

# Fix Qt-static cmake BUG
# https://bugreports.qt.io/browse/QTBUG-38913
# FIXME qt 5.13 fix this bug
if(EXISTS ${_qt5Core_install_prefix}/lib/libQt5Core.a AND NOT EXISTS ${_qt5Core_install_prefix}/bin/Qt5Core.dll)
    message("Static Qt is detected.")
    if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
        set(OS_EXTRA_LINK log qtpcre2)
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        set(OS_EXTRA_LINK pthread dl qtpcre2)
    elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        set(OS_EXTRA_LINK ws2_32 qtpcre2)
    endif()
    if(${CMAKE_VERSION} VERSION_GREATER "3.13.0")
        target_link_directories(qtnetworkng PUBLIC ${_qt5Core_install_prefix}/lib/)
    else()
        link_directories(${_qt5Core_install_prefix}/lib/)
    endif()
endif()

if (QTNG_USE_OPENSSL)
    target_include_directories(qtnetworkng PRIVATE ${OPENSSL_INCLUDE_DIR})
    if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        set(OS_EXTRA_LINK ${OS_EXTRA_LINK} "ws2_32")
    endif()
else()
    target_include_directories(qtnetworkng PRIVATE "libressl/include")
    set(OPENSSL_LIBRARIES crypto ssl)
endif()

target_link_libraries(qtnetworkng PUBLIC Qt5::Core PRIVATE ${ZLIB_LINK} ${OPENSSL_LIBRARIES} ${OS_EXTRA_LINK})

set(CMAKE_INSTALL_PREFIX ${_qt5Core_install_prefix})
install(TARGETS qtnetworkng ARCHIVE DESTINATION lib)
install(FILES ${QTNETWORKNG_INCLUDE} ${QTCRYPTONG_INCLUDE} DESTINATION include/qtnetworkng/)
install(FILES ${QTNETWORKNG_PRIVATE_INCLUDE} ${QTCRYPTONG_PRIVATE_INCLUDE} DESTINATION include/qtnetworkng/private/)

