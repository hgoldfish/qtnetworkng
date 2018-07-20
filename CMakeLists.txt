# How to build QtNetworkNg for Linux with cmake
# 1. Build static Qt:
#     ./configure --prefix="/usr/local/Qt5.11.1-linux-static-amd64" -release -opensource -static -no-gui -no-icu -no-glib -no-iconv -nomake tests -nomake examples
#     make -j4 && sudo make install
# 2. Build QtNetworkNg
#     mkdir build
#     cd build
#     cmake -DCMAKE_PREFIX_PATH=/usr/local/Qt5.11.1-linux-static-amd64/lib/cmake/ ..
#     make -j4
#     sudo make install
#
# How to cross build QtNetworkNg for Android with cmake
# 1. Build static Qt:
#     ./configure --prefix="/usr/local/Qt5.11.1-android-static-armv7" -release -opensource -static -no-gui -no-icu -xplatform android-clang -disable-rpath -nomake tests -nomake examples -android-ndk /home/goldfish/bin/android-sdk-linux/ndk-bundle -android-sdk /home/goldfish/bin/android-sdk-linux -android-ndk-platform android-14 -android-arch armeabi-v7a 
#     make -j4 && sudo make install
# 2. Build QtNetworkNg
#     mkdir build
#     cd build
#     cmake -DANDROID_ABI=armeabi-v7a -DANDROID_NDK=/home/goldfish/bin/android-sdk-linux/ndk-bundle -DCMAKE_TOOLCHAIN_FILE=/home/goldfish/bin/android-sdk-linux/ndk-bundle/build/cmake/android.toolchain.cmake -DANDROID_TOOLCHAIN=clang -DANDROID_PLATFORM=android-14 -DANDROID_STL=c++_static -DCMAKE_PREFIX_PATH=/usr/local/Qt5.11.1-android-static-armv7/lib/cmake -DANDROID_CPP_FEATURES="exceptions rtti" ..
#     make -j4
#     sudo make install


CMAKE_MINIMUM_REQUIRED(VERSION 3.1.0 FATAL_ERROR)

PROJECT(qtnetworkng)

ENABLE_LANGUAGE(C CXX ASM)
SET(CMAKE_AUTOMOC ON)
SET(CMAKE_INCLUDE_CURRENT_DIR ON)

IF(ANDROID)
    FIND_PACKAGE(Qt5Core CONFIG REQUIRED CMAKE_FIND_ROOT_PATH_BOTH)
    FIND_PACKAGE(Qt5Network CONFIG REQUIRED CMAKE_FIND_ROOT_PATH_BOTH)
    FIND_PACKAGE(Qt5Test CONFIG CMAKE_FIND_ROOT_PATH_BOTH)
ELSE()
    FIND_PACKAGE(Qt5Core REQUIRED)
    FIND_PACKAGE(Qt5Network REQUIRED)
    FIND_PACKAGE(Qt5Test)
ENDIF()

SET(QTNETWORKNG_SRC
    src/socket.cpp
    src/eventloop.cpp
    src/coroutine.cpp
    src/locks.cpp
    src/coroutine_utils.cpp
    src/http.cpp
    src/socket_utils.cpp
    src/http_utils.cpp
    src/http_proxy.cpp
    src/socks5_proxy.cpp
)

SET(QTNETWORKNG_INCLUDE
    include/config.h
    include/coroutine.h
    include/socket.h
    include/socket_p.h
    include/eventloop.h
    include/locks.h
    include/coroutine_utils.h
    include/coroutine_p.h
    include/http.h
    include/http_p.h
    include/socket_utils.h
    include/qsystemlibrary_p.h
    include/http_utils.h
    include/http_proxy.h
    include/socks5_proxy.h
    include/deferred.h
    include/qtnetworkng.h
)

SET(QTSSLNG_SRC
    src/ssl.cpp
    src/crypto.cpp
    src/openssl_symbols.cpp
    src/random.cpp
    src/md.cpp
    src/pkey.cpp
    src/cipher.cpp
    src/certificate.cpp
    src/qasn1element.cpp
)

SET(QTSSLNG_INCLUDE
    include/config.h
    include/crypto.h
    include/ssl.h
    include/openssl_symbols.h
    include/qtng_temp.h
    include/md.h
    include/random.h
    include/cipher.h
    include/pkey.h
    include/crypto_p.h
    include/certificate.h
    include/qasn1element.h
)

ADD_DEFINITIONS(-DQTNETWOKRNG_USE_SSL)

IF(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    SET(OS_DEPENDENDED_SRC 
        src/socket_win.cpp
        src/qsystemlibrary.cpp
        src/coroutine_win.cpp
    )
ELSEIF(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    IF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_arm64_aapcs_elf_gas.S
            src/context/asm/make_arm64_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_arm_aapcs_elf_gas.S
            src/context/asm/make_arm_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "mips")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_mips32_o32_elf_gas.S
            src/context/asm/make_mips32_o32_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "mips64")
        MESSAGE(FATAL_ERROR Android for mips64 is not supported.)
    ELSEIF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_i386_sysv_elf_gas.S
            src/context/asm/make_i386_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86_64")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_x86_64_sysv_elf_gas.S
            src/context/asm/make_x86_64_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSE()
        MESSAGE(FATAL_ERROR Android for ${CMAKE_ANDROID_ARCH_ABI} is not supported.)
    ENDIF()
ELSEIF(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    MESSAGE(FATAL_ERROR MacOS is not supported.)
ELSEIF(UNIX)
    IF((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64"))
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_x86_64_sysv_elf_gas.S
            src/context/asm/make_x86_64_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386") 
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686"))
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_i386_sysv_elf_gas.S
            src/context/asm/make_i386_sysv_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm64"))
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_arm64_aapcs_elf_gas.S
            src/context/asm/make_arm64_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSEIF((${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7")
            OR (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm"))
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_arm_aapcs_elf_gas.S
            src/context/asm/make_arm_aapcs_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    #ELSEIF(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "mips64")   
    ELSEIF(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "mips")
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/context/asm/jump_mips32_o32_elf_gas.S
            src/context/asm/make_mips32_o32_elf_gas.S
            src/coroutine_fcontext.cpp
        )
    ELSE()
        # fall back to ucontext
        SET(OS_DEPENDENDED_SRC
            src/socket_unix.cpp
            src/coroutine_unix.cpp
        )
    ENDIF()
ELSE()
    MESSAGE(FATAL_ERROR ${CMAKE_SYSTEM_NAME} is not supported.)
ENDIF()

# SET(EVENTLOOP_SRC
#     src/eventloop_qt.cpp
# )

# start intergrating libev
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckLibraryExists)

CHECK_INCLUDE_FILES(inttypeas.h HAVE_INTTYPES_H)
CHECK_INCLUDE_FILES(dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILES(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(port.h HAVE_PORT_H)
CHECK_INCLUDE_FILES(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILES(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(strings.h HAVE_STRINGS_H)
CHECK_INCLUDE_FILES(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES(sys/epoll.h HAVE_SYS_EPOLL_H)
CHECK_INCLUDE_FILES(sys/eventfd.h HAVE_SYS_EVENTFD_H)
CHECK_INCLUDE_FILES(sys/event.h HAVE_SYS_EVENT_H)
#CHECK_INCLUDE_FILES(sys/inotify.h HAVE_SYS_INOTIFY_H)  # disabled for android.
CHECK_INCLUDE_FILES(sys/select.h HAVE_SYS_SELECT_H)
CHECK_INCLUDE_FILES(sys/signalfd.h HAVE_SYS_SIGNALFD_H)
CHECK_INCLUDE_FILES(sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES("assert.h;ctype.h;errno.h;float.h;limits.h;locale.h;math.h;setjmp.h;signal.h;stdarg.h;stddef.h;stdio.h;stdlib.h;string.h;time.h;" STDC_HEADERS)
CHECK_INCLUDE_FILES("winsock.h" HAVE_WINSOCK_H)

# check functions
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
CHECK_FUNCTION_EXISTS(epoll_ctl HAVE_EPOLL_CTL)
CHECK_FUNCTION_EXISTS(eventfd HAVE_EVENTFD)
CHECK_FUNCTION_EXISTS(floor HAVE_FLOOR)
#CHECK_FUNCTION_EXISTS(inotify_init HAVE_INOTIFY_INIT)   # disable for androd.
CHECK_FUNCTION_EXISTS(kqueue HAVE_KQUEUE)
CHECK_FUNCTION_EXISTS(nanosleep HAVE_NANOSLEEP)
CHECK_FUNCTION_EXISTS(poll HAVE_POLL)
CHECK_FUNCTION_EXISTS(port_create HAVE_PORT_CREATE)
CHECK_FUNCTION_EXISTS(select HAVE_SELECT)
CHECK_FUNCTION_EXISTS(signalfd HAVE_SIGNALFD)

# check system library
CHECK_LIBRARY_EXISTS(rt pthread_create "" HAVE_LIBRT)

CONFIGURE_FILE(ev/config.h.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR} ev/)
# Ignore deprecation warnings and cast warnings
IF(MSVC)
    ADD_DEFINITIONS("/wd4244") 
    ADD_DEFINITIONS("/wd4996")
ENDIF()

ADD_DEFINITIONS(-DQTNETWOKRNG_USE_EV)

SET(EVENTLOOP_SRC
    src/eventloop_ev.cpp
    src/eventloop_qt.cpp
    ev/ev.c
)

# Fix Qt-static cmake BUG
# https://bugreports.qt.io/browse/QTBUG-38913
IF((EXISTS ${_qt5Core_install_prefix}/lib/libQt5Core.so) OR
   (EXISTS ${_qt5Core_install_prefix}/lib/Qt5Core.dll) OR
   (EXISTS ${_qt5Core_install_prefix}/lib64/libQt5Core.so) OR
   (EXISTS ${_qt5Core_install_prefix}/lib64/Qt5Core.dll))
    MESSAGE("Shared Qt is detected.")
ELSE()
    MESSAGE("Static Qt is detected.")
    IF(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
        SET(OS_EXTRA_LINK z log qtpcre2)
    ELSEIF(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        SET(OS_EXTRA_LINK z pthread dl qtpcre2)
    ELSEIF(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        SET(OS_EXTRA_LINK ws2_32)
    ENDIF()
ENDIF()

LINK_DIRECTORIES(${_qt5Core_install_prefix}/lib/)
ADD_LIBRARY(qtnetworkng STATIC ${QTNETWORKNG_SRC} ${QTSSLNG_SRC} ${OS_DEPENDENDED_SRC} ${EVENTLOOP_SRC})
TARGET_LINK_LIBRARIES(qtnetworkng Qt5::Core Qt5::Network ${OS_EXTRA_LINK})

SET(CMAKE_INSTALL_PREFIX ${_qt5Core_install_prefix})
INSTALL(TARGETS qtnetworkng ARCHIVE DESTINATION lib)
INSTALL(FILES ${QTNETWORKNG_INCLUDE} ${QTSSLNG_INCLUDE} DESTINATION include/qtnetworkng/)

IF(Qt5Test_FOUND)
    ADD_EXECUTABLE(test_ssl tests/test_ssl.cpp)
    TARGET_LINK_LIBRARIES(test_ssl Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(test_crypto tests/test_crypto.cpp)
    TARGET_LINK_LIBRARIES(test_crypto Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(test_coroutines tests/test_coroutines.cpp)
    TARGET_LINK_LIBRARIES(test_coroutines Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(sleep_coroutines tests/sleep_coroutines.cpp)
    TARGET_LINK_LIBRARIES(sleep_coroutines Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(simple_test tests/simple_test.cpp)
    TARGET_LINK_LIBRARIES(simple_test Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(many_httpget tests/many_httpget.cpp)
    TARGET_LINK_LIBRARIES(many_httpget Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
    
    ADD_EXECUTABLE(test_socket tests/test_socket.cpp)
    TARGET_LINK_LIBRARIES(test_socket Qt5::Core Qt5::Network Qt5::Test qtnetworkng)
ENDIF()
